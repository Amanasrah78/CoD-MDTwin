from __future__ import annotations

import secrets
import sqlite3
import time
from pathlib import Path
from threading import Lock
from typing import Any, Dict, List, Set, Tuple

import requests
from fastapi import FastAPI
from pydantic import BaseModel, Field

from shared.credentials import credential_hash, issue_capability, verify_credential_signature
from shared.crypto import verify_holder_proof
from shared.did import create_local_did
from shared.domain_policy import allowed_operations_from_scopes
from shared.methodology import (
    cod_methodology_view,
    request_methodology_view,
    revocation_methodology_view,
)
from shared.policy import validate_capability, validate_cod
from shared.selective_disclosure import (
    issue_sd_jwt_like,
    present_sd_jwt_like,
    verify_sd_jwt_like,
)
from shared.tracing import Trace, sha256_json

app = FastAPI(title="CoD Verifier", version="0.6.0")
VERIFIER = create_local_did("verifier")
REVOKED: Set[str] = set()
REPLAY_CACHE: Set[str] = set()
LEDGER = "http://ledger-service:9000"
VENDOR_AGENT_METADATA = "http://vendor-agent:8003/did"
STATE_DIR = Path("/app/results/state")
STATE_DB = STATE_DIR / "verifier_state.sqlite"
STATE_LOCK = Lock()
DEFAULT_CHALLENGE_TTL_SECONDS = 30
MAX_REQUEST_CLOCK_SKEW_SECONDS = 60


def _init_state() -> None:
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(STATE_DB) as con:
        con.execute(
            "CREATE TABLE IF NOT EXISTS revoked_ids "
            "(credential_id TEXT PRIMARY KEY, reason TEXT, revoked_at INTEGER)"
        )
        con.execute(
            "CREATE TABLE IF NOT EXISTS replay_cache "
            "(nonce_key TEXT PRIMARY KEY, consumed_at INTEGER)"
        )
        con.execute(
            "CREATE TABLE IF NOT EXISTS challenges ("
            "challenge TEXT PRIMARY KEY, capability_id TEXT NOT NULL, "
            "capability_hash TEXT NOT NULL, issued_at INTEGER NOT NULL, "
            "expires_at INTEGER NOT NULL, consumed_at INTEGER)"
        )
        con.commit()


def _load_state() -> None:
    _init_state()
    with sqlite3.connect(STATE_DB) as con:
        REVOKED.update(r[0] for r in con.execute("SELECT credential_id FROM revoked_ids"))
        REPLAY_CACHE.update(r[0] for r in con.execute("SELECT nonce_key FROM replay_cache"))


def _persist_revocation(credential_id: str, reason: str) -> None:
    with STATE_LOCK, sqlite3.connect(STATE_DB) as con:
        con.execute(
            "INSERT OR REPLACE INTO revoked_ids VALUES (?, ?, ?)",
            (credential_id, reason, int(time.time())),
        )
        con.commit()


def _store_challenge(
    challenge: str,
    capability_id: str,
    capability_hash: str,
    issued_at: int,
    expires_at: int,
) -> None:
    with STATE_LOCK, sqlite3.connect(STATE_DB) as con:
        con.execute(
            "INSERT INTO challenges "
            "(challenge, capability_id, capability_hash, issued_at, expires_at, consumed_at) "
            "VALUES (?, ?, ?, ?, ?, NULL)",
            (challenge, capability_id, capability_hash, issued_at, expires_at),
        )
        con.commit()


def _check_challenge(
    challenge: str,
    capability_id: str,
    capability_hash: str,
    now: int,
) -> Tuple[bool, str]:
    with sqlite3.connect(STATE_DB) as con:
        row = con.execute(
            "SELECT capability_id, capability_hash, expires_at, consumed_at "
            "FROM challenges WHERE challenge = ?",
            (challenge,),
        ).fetchone()
    if row is None:
        return False, "unknown verifier challenge"
    stored_capability_id, stored_hash, expires_at, consumed_at = row
    if stored_capability_id != capability_id or stored_hash != capability_hash:
        return False, "verifier challenge is not bound to this capability"
    if consumed_at is not None:
        return False, "verifier challenge replay detected"
    if now > int(expires_at):
        return False, "verifier challenge expired"
    return True, "fresh verifier challenge"


def _consume_nonce_and_challenge(
    nonce_key: str,
    challenge: str,
    capability_id: str,
    capability_hash: str,
    now: int,
) -> Tuple[bool, str]:
    """Atomically consume the capability nonce and verifier challenge."""
    with STATE_LOCK, sqlite3.connect(STATE_DB, timeout=30) as con:
        try:
            con.execute("BEGIN IMMEDIATE")
            row = con.execute(
                "SELECT capability_id, capability_hash, expires_at, consumed_at "
                "FROM challenges WHERE challenge = ?",
                (challenge,),
            ).fetchone()
            if row is None:
                con.rollback()
                return False, "unknown verifier challenge"
            stored_capability_id, stored_hash, expires_at, consumed_at = row
            if stored_capability_id != capability_id or stored_hash != capability_hash:
                con.rollback()
                return False, "verifier challenge is not bound to this capability"
            if consumed_at is not None:
                con.rollback()
                return False, "verifier challenge replay detected"
            if now > int(expires_at):
                con.rollback()
                return False, "verifier challenge expired"
            if con.execute(
                "SELECT 1 FROM replay_cache WHERE nonce_key = ?", (nonce_key,)
            ).fetchone():
                con.rollback()
                return False, "capability replay detected"

            con.execute(
                "INSERT INTO replay_cache (nonce_key, consumed_at) VALUES (?, ?)",
                (nonce_key, now),
            )
            con.execute(
                "UPDATE challenges SET consumed_at = ? WHERE challenge = ? AND consumed_at IS NULL",
                (now, challenge),
            )
            con.commit()
        except sqlite3.IntegrityError:
            con.rollback()
            return False, "capability replay detected"
    REPLAY_CACHE.add(nonce_key)
    return True, "capability nonce and verifier challenge consumed"



def _consume_challenge_only(
    challenge: str,
    capability_id: str,
    capability_hash: str,
    now: int,
) -> Tuple[bool, str]:
    """Consume only the verifier challenge for a presentation-replay test."""
    with STATE_LOCK, sqlite3.connect(STATE_DB, timeout=30) as con:
        con.execute("BEGIN IMMEDIATE")
        row = con.execute(
            "SELECT capability_id, capability_hash, expires_at, consumed_at "
            "FROM challenges WHERE challenge = ?",
            (challenge,),
        ).fetchone()
        if row is None:
            con.rollback()
            return False, "unknown verifier challenge"
        stored_capability_id, stored_hash, expires_at, consumed_at = row
        if stored_capability_id != capability_id or stored_hash != capability_hash:
            con.rollback()
            return False, "verifier challenge is not bound to this capability"
        if consumed_at is not None:
            con.rollback()
            return False, "verifier challenge replay detected"
        if now > int(expires_at):
            con.rollback()
            return False, "verifier challenge expired"
        con.execute(
            "UPDATE challenges SET consumed_at = ? WHERE challenge = ? AND consumed_at IS NULL",
            (now, challenge),
        )
        con.commit()
    return True, "verifier challenge consumed"

def _resolve_verification_method(kid: str, subject_did: str) -> Tuple[bool, str | None, str]:
    """Resolve the local VendorAgent verification method through trusted service metadata."""
    expected_kid = f"{subject_did}#key1"
    if kid != expected_kid:
        return False, None, "capability verification method is not authorized for the subject DID"
    if subject_did != "did:local:vendor-agent":
        return False, None, "unsupported local DID verification method"
    try:
        doc = requests.get(VENDOR_AGENT_METADATA, timeout=3).json()
    except Exception as exc:
        return False, None, f"subject verification metadata unavailable: {exc}"
    if doc.get("did") != subject_did or doc.get("kid") != kid or not doc.get("public_key"):
        return False, None, "subject verification metadata does not match the capability binding"
    return True, str(doc["public_key"]), "subject verification method resolved"


_load_state()


class VerifyRequest(BaseModel):
    cod: List[Dict[str, Any]]
    issuer_keys: Dict[str, str]
    request: Dict[str, Any]
    depth_max: int = 3
    issue_capability_on_success: bool = True
    capability_valid_seconds: int = 120


class RevokeRequest(BaseModel):
    credential_id: str
    reason: str = "manual revocation"


class ChallengeRequest(BaseModel):
    capability: Dict[str, Any]
    validity_seconds: int = Field(default=DEFAULT_CHALLENGE_TTL_SECONDS, ge=1, le=300)


class CapabilityVerifyRequest(BaseModel):
    capability: Dict[str, Any]
    verifier_public_key: str | None = None
    request: Dict[str, Any]
    holder_proof: Dict[str, Any] | None = None
    challenge: str | None = None
    consume_nonce: bool = True
    consume_challenge: bool | None = None
    require_holder_proof: bool = True


class SDIssueRequest(BaseModel):
    subject_did: str
    claims: Dict[str, Any]


class SDPresentRequest(BaseModel):
    credential: Dict[str, Any]
    reveal: List[str]


class SDVerifyRequest(BaseModel):
    presentation: Dict[str, Any]
    issuer_public_key: str | None = None


@app.get("/health")
def health() -> Dict[str, str]:
    return {"status": "ok", "service": "verifier"}


@app.get("/")
def root() -> Dict[str, Any]:
    return domain_info()


@app.get("/domain-info")
def domain_info() -> Dict[str, Any]:
    return {
        "service": "verifier",
        "domain": "VerificationService",
        "role": "CoD validation, holder-key-bound capability realization and verification, revocation",
        "port": 8010,
        "actor": {
            "did": VERIFIER["did"],
            "kid": VERIFIER["kid"],
            "public_key": VERIFIER["public_key"],
        },
        "endpoints": {
            "GET /health": "service readiness",
            "GET /domain-info": "human-readable verifier metadata",
            "GET /did": "verifier DID and public key",
            "GET /revocations": "current persistent revocation set",
            "GET /state": "persistent nonce and challenge-state counts",
            "GET /methodology-map": "paper-notation mapping for implemented artifacts",
            "POST /challenge": "issue a fresh capability-bound verifier challenge",
            "POST /verify-cod": "validate a Chain-of-Delegation and optionally issue a holder-key-bound capability",
            "POST /verify-capability": "validate capability, holder proof, challenge, nonce, and revocation state",
            "POST /revoke": "revoke a delegation credential or capability by id",
            "POST /reset-state": "clear revocations, nonce state, and challenge state",
        },
        "capability_checks": [
            "issuer signature validity",
            "validity interval",
            "revocation status",
            "subject and verification-method binding",
            "holder proof of possession",
            "request and audience binding",
            "verifier-challenge freshness",
            "capability-nonce freshness",
        ],
    }


@app.get("/did")
def did() -> Dict[str, str]:
    return {
        "did": VERIFIER["did"],
        "kid": VERIFIER["kid"],
        "public_key": VERIFIER["public_key"],
    }


@app.get("/revocations")
def revocations() -> Dict[str, Any]:
    return {"revoked_ids": sorted(REVOKED)}


@app.get("/state")
def state() -> Dict[str, Any]:
    with sqlite3.connect(STATE_DB) as con:
        replay_count = con.execute("SELECT COUNT(*) FROM replay_cache").fetchone()[0]
        challenge_count = con.execute("SELECT COUNT(*) FROM challenges").fetchone()[0]
        consumed_challenge_count = con.execute(
            "SELECT COUNT(*) FROM challenges WHERE consumed_at IS NOT NULL"
        ).fetchone()[0]
    return {
        "revoked_count": len(REVOKED),
        "consumed_nonce_count": replay_count,
        "challenge_count": challenge_count,
        "consumed_challenge_count": consumed_challenge_count,
        "state_db": str(STATE_DB),
    }


@app.post("/verify-cod")
def verify(req: VerifyRequest) -> Dict[str, Any]:
    trace = Trace(operation="verify_cod", actor="Verifier", domain="VerificationService")
    trace.inputs = {
        "request": req.request,
        "request_methodology": request_methodology_view(req.request),
        "chain_length": len(req.cod),
        "depth_max": req.depth_max,
    }
    with trace.timer("cod_validation"):
        accepted, checks, reason = validate_cod(
            req.cod, req.issuer_keys, req.request, REVOKED, req.depth_max
        )
    trace.checks = checks
    trace.artifacts["cod_hash"] = sha256_json(req.cod)
    trace.artifacts["cod_methodology"] = cod_methodology_view(req.cod)

    if accepted and req.issue_capability_on_success:
        subject_did = str(req.request["actor_did"])
        subject_kid = str(req.request.get("kid_s") or f"{subject_did}#key1")
        resolved, _, resolution_reason = _resolve_verification_method(subject_kid, subject_did)
        trace.checks["subject_verification_method_resolved"] = resolved
        if not resolved:
            trace.mark("rejected", resolution_reason)
            return {"accepted": False, "reason": resolution_reason, "trace": trace.to_dict()}

        with trace.timer("capability_realization"):
            cap = issue_capability(
                VERIFIER["did"],
                VERIFIER["private_key"],
                subject_did,
                subject_kid,
                [req.request["scope"]],
                [req.request["action"]],
                req.request["resource"],
                valid_seconds=req.capability_valid_seconds,
                cod_hash=trace.artifacts["cod_hash"],
                cod_ids=[dc.get("payload", {}).get("id") for dc in req.cod],
                audience=req.request.get("audience", "vendor-b"),
                allowed_operations=allowed_operations_from_scopes(
                    [req.request["scope"]], req.request["resource"]
                ),
            )
        trace.artifacts["capability_id"] = cap["payload"]["id"]
        trace.artifacts["capability_hash"] = credential_hash(cap)
        trace.artifacts["holder_kid"] = subject_kid
        with trace.timer("ledger_anchor"):
            try:
                ledger = requests.post(
                    f"{LEDGER}/anchor",
                    json={
                        "artifact_type": "Capability",
                        "artifact": cap,
                        "trace": trace.to_dict(),
                    },
                    timeout=3,
                ).json()
                trace.artifacts["ledger_tx"] = ledger["tx_id"]
            except Exception as exc:
                trace.artifacts["ledger_error"] = str(exc)
        trace.mark("accepted", reason)
        return {
            "accepted": True,
            "reason": reason,
            "capability": cap,
            "verifier_public_key": VERIFIER["public_key"],
            "trace": trace.to_dict(),
        }

    trace.mark("accepted" if accepted else "rejected", reason)
    return {"accepted": accepted, "reason": reason, "trace": trace.to_dict()}


@app.post("/challenge")
def issue_challenge(req: ChallengeRequest) -> Dict[str, Any]:
    trace = Trace(operation="issue_access_challenge", actor="Verifier", domain="VerificationService")
    payload = req.capability.get("payload", {})
    cap_id = str(payload.get("id", ""))
    capability_hash = sha256_json(req.capability)
    trace.inputs = {"capability_id": cap_id, "validity_seconds": req.validity_seconds}

    checks = {
        "type_is_capability": payload.get("type") == "Capability",
        "capability_id_present": bool(cap_id),
        "kid_s_present": bool(payload.get("kid_s")),
        "capability_signature_valid": verify_credential_signature(
            req.capability, VERIFIER["public_key"]
        ) if payload and req.capability.get("signature") else False,
        "time_valid": payload.get("valid_from", 0) <= int(time.time()) <= payload.get("valid_until", 0),
        "capability_not_revoked": cap_id not in REVOKED,
        "parent_cod_not_revoked": not any(cid in REVOKED for cid in payload.get("cod_ids", [])),
    }
    trace.checks = checks
    if not all(checks.values()):
        reason = next(name for name, value in checks.items() if not value)
        trace.mark("rejected", reason.replace("_", " "))
        return {"accepted": False, "reason": trace.reason, "trace": trace.to_dict()}

    now = int(time.time())
    challenge = secrets.token_urlsafe(32)
    expires_at = now + req.validity_seconds
    with trace.timer("challenge_state_write"):
        _store_challenge(challenge, cap_id, capability_hash, now, expires_at)
    trace.artifacts["capability_hash"] = capability_hash
    trace.artifacts["challenge_expires_at"] = expires_at
    trace.mark("accepted", "fresh verifier challenge issued")
    return {
        "accepted": True,
        "reason": trace.reason,
        "challenge": challenge,
        "issued_at": now,
        "expires_at": expires_at,
        "capability_id": cap_id,
        "capability_hash": capability_hash,
        "trace": trace.to_dict(),
    }


@app.post("/verify-capability")
def verify_cap(req: CapabilityVerifyRequest) -> Dict[str, Any]:
    trace = Trace(operation="verify_capability", actor="Verifier", domain="VerificationService")
    payload = req.capability.get("payload", {})
    cap_id = str(payload.get("id", ""))
    capability_hash = sha256_json(req.capability)
    trace.inputs = {
        "request": req.request,
        "capability_id": cap_id,
        "consume_nonce": req.consume_nonce,
        "consume_challenge": req.consume_nonce if req.consume_challenge is None else req.consume_challenge,
        "require_holder_proof": req.require_holder_proof,
    }
    trace.artifacts["capability_hash"] = capability_hash

    public_key = req.verifier_public_key or VERIFIER["public_key"]
    with trace.timer("capability_base_validation"):
        accepted, checks, reason = validate_capability(
            req.capability,
            public_key,
            req.request,
            REVOKED,
            REPLAY_CACHE,
            consume_nonce=False,
        )
    trace.checks = checks
    if not accepted:
        trace.mark("rejected", reason)
        return {"accepted": False, "reason": reason, "capability_id": cap_id, "trace": trace.to_dict()}

    if req.require_holder_proof:
        if not req.challenge:
            trace.checks["challenge_present"] = False
            trace.mark("rejected", "verifier challenge is missing")
            return {"accepted": False, "reason": trace.reason, "capability_id": cap_id, "trace": trace.to_dict()}
        if not req.holder_proof:
            trace.checks["holder_proof_present"] = False
            trace.mark("rejected", "holder proof is missing")
            return {"accepted": False, "reason": trace.reason, "capability_id": cap_id, "trace": trace.to_dict()}

        now = int(time.time())
        request_time = req.request.get("timestamp")
        request_time_fresh = isinstance(request_time, int) and abs(now - request_time) <= MAX_REQUEST_CLOCK_SKEW_SECONDS
        trace.checks["request_time_fresh"] = request_time_fresh
        if not request_time_fresh:
            trace.mark("rejected", "holder-proof request time is stale or missing")
            return {"accepted": False, "reason": trace.reason, "capability_id": cap_id, "trace": trace.to_dict()}

        kid = str(payload.get("kid_s", ""))
        with trace.timer("holder_key_resolution"):
            key_resolved, holder_public_key, key_reason = _resolve_verification_method(
                kid, str(payload.get("subject", ""))
            )
        trace.checks["holder_key_resolved"] = key_resolved
        if not key_resolved or holder_public_key is None:
            trace.mark("rejected", key_reason)
            return {"accepted": False, "reason": trace.reason, "capability_id": cap_id, "trace": trace.to_dict()}

        with trace.timer("challenge_state_check"):
            challenge_ok, challenge_reason = _check_challenge(
                req.challenge, cap_id, capability_hash, now
            )
        trace.checks["challenge_fresh_and_bound"] = challenge_ok
        if not challenge_ok:
            trace.mark("rejected", challenge_reason)
            return {"accepted": False, "reason": trace.reason, "capability_id": cap_id, "trace": trace.to_dict()}

        with trace.timer("holder_proof_verification"):
            proof_valid = verify_holder_proof(
                holder_public_key,
                req.holder_proof,
                capability_hash,
                req.request,
                req.challenge,
            )
        trace.checks["holder_proof_valid"] = proof_valid
        if not proof_valid:
            trace.mark("rejected", "invalid holder proof")
            return {"accepted": False, "reason": trace.reason, "capability_id": cap_id, "trace": trace.to_dict()}

        consume_challenge = req.consume_nonce if req.consume_challenge is None else req.consume_challenge
        if req.consume_nonce and consume_challenge:
            nonce_key = f"{cap_id}:{payload.get('nonce')}"
            with trace.timer("nonce_challenge_state_consumption"):
                state_ok, state_reason = _consume_nonce_and_challenge(
                    nonce_key, req.challenge, cap_id, capability_hash, now
                )
            trace.checks["nonce_and_challenge_consumed"] = state_ok
            if not state_ok:
                trace.mark("rejected", state_reason)
                return {"accepted": False, "reason": trace.reason, "capability_id": cap_id, "trace": trace.to_dict()}
        elif consume_challenge:
            with trace.timer("challenge_state_consumption"):
                state_ok, state_reason = _consume_challenge_only(
                    req.challenge, cap_id, capability_hash, now
                )
            trace.checks["challenge_consumed"] = state_ok
            trace.checks["nonce_consumed"] = False
            if not state_ok:
                trace.mark("rejected", state_reason)
                return {"accepted": False, "reason": trace.reason, "capability_id": cap_id, "trace": trace.to_dict()}
        else:
            trace.checks["nonce_and_challenge_consumed"] = False
    elif req.consume_nonce:
        # Unsafe ablation mode: no holder proof, but retain atomic nonce consumption.
        nonce_key = f"{cap_id}:{payload.get('nonce')}"
        with STATE_LOCK, sqlite3.connect(STATE_DB, timeout=30) as con:
            try:
                con.execute("BEGIN IMMEDIATE")
                con.execute(
                    "INSERT INTO replay_cache (nonce_key, consumed_at) VALUES (?, ?)",
                    (nonce_key, int(time.time())),
                )
                con.commit()
                REPLAY_CACHE.add(nonce_key)
            except sqlite3.IntegrityError:
                con.rollback()
                trace.mark("rejected", "capability replay detected")
                return {"accepted": False, "reason": trace.reason, "capability_id": cap_id, "trace": trace.to_dict()}

    if req.require_holder_proof:
        trace.artifacts["holder_kid"] = payload.get("kid_s")
        trace.artifacts["challenge"] = req.challenge

    with trace.timer("ledger_anchor"):
        try:
            ledger = requests.post(
                f"{LEDGER}/anchor",
                json={
                    "artifact_type": "CapabilityUse",
                    "artifact": {
                        "capability_id": cap_id,
                        "request": req.request,
                        "holder_kid": payload.get("kid_s"),
                        "challenge": req.challenge,
                    },
                    "trace": trace.to_dict(),
                },
                timeout=3,
            ).json()
            trace.artifacts["ledger_tx"] = ledger["tx_id"]
        except Exception as exc:
            trace.artifacts["ledger_error"] = str(exc)

    trace.mark("accepted", "valid holder-bound capability presentation" if req.require_holder_proof else "valid capability in no-holder-proof ablation mode")
    return {"accepted": True, "reason": trace.reason, "capability_id": cap_id, "trace": trace.to_dict()}


@app.post("/revoke")
def revoke(req: RevokeRequest) -> Dict[str, Any]:
    REVOKED.add(req.credential_id)
    _persist_revocation(req.credential_id, req.reason)
    trace = Trace(operation="revoke_delegation", actor="Verifier", domain="VerificationService")
    revoked_at = int(time.time())
    trace.inputs = {
        "credential_id": req.credential_id,
        "reason": req.reason,
        "methodology": revocation_methodology_view(req.credential_id, revoked_at, req.reason),
    }
    trace.mark("accepted", "credential revoked")
    try:
        ledger = requests.post(
            f"{LEDGER}/anchor",
            json={"artifact_type": "Revocation", "artifact": req.model_dump(), "trace": trace.to_dict()},
            timeout=3,
        ).json()
        trace.artifacts["ledger_tx"] = ledger["tx_id"]
    except Exception as exc:
        trace.artifacts["ledger_error"] = str(exc)
    return {"revoked": True, "credential_id": req.credential_id, "reason": req.reason, "trace": trace.to_dict()}


@app.post("/reset-state")
def reset_state() -> Dict[str, Any]:
    REVOKED.clear()
    REPLAY_CACHE.clear()
    with STATE_LOCK, sqlite3.connect(STATE_DB) as con:
        con.execute("DELETE FROM revoked_ids")
        con.execute("DELETE FROM replay_cache")
        con.execute("DELETE FROM challenges")
        con.commit()
    return {
        "accepted": True,
        "revoked_count": 0,
        "replay_cache_count": 0,
        "challenge_count": 0,
        "state_db": str(STATE_DB),
    }


@app.get("/methodology-map")
def methodology_map() -> Dict[str, Any]:
    return {
        "DC_i": "Delegation credential: (D_id, DID_from, DID_to, Sigma_i, tau_i, rho_i)",
        "tau_i": "Constraint tuple: T_i, Depth_i, C_i",
        "CoD": "Ordered chain <d_1, d_2, ..., d_n>",
        "Req": "Access request including DID_req, scope, service, resource, action, audience, and request time",
        "Cap": "Holder-key-bound capability including C_id, DID_s, kid_s, Scope_eff, audience, T_cap, Nonce, and H(CoD)",
        "HolderProof": "Ed25519 signature over the capability hash, concrete request, request time, and verifier challenge",
        "Rev": "Revocation record (D_id, t_r, Reason)",
        "implementation_note": "Local DID verification metadata is resolved from the VendorAgent service; nonce and challenge state are consumed atomically in SQLite.",
    }


@app.post("/sd/issue")
def sd_issue(req: SDIssueRequest) -> Dict[str, Any]:
    cred = issue_sd_jwt_like(VERIFIER["did"], VERIFIER["private_key"], req.subject_did, req.claims)
    return {"accepted": True, "credential": cred, "issuer_public_key": VERIFIER["public_key"], "warning": "SD-JWT-style simulation only, not a standards-complete SD-JWT implementation"}


@app.post("/sd/present")
def sd_present(req: SDPresentRequest) -> Dict[str, Any]:
    pres = present_sd_jwt_like(req.credential, req.reveal)
    return {"accepted": True, "presentation": pres, "revealed": req.reveal}


@app.post("/sd/verify")
def sd_verify(req: SDVerifyRequest) -> Dict[str, Any]:
    return verify_sd_jwt_like(req.presentation, req.issuer_public_key or VERIFIER["public_key"])
