from __future__ import annotations

import requests
from typing import Any, Dict, List
from fastapi import FastAPI
from pydantic import BaseModel

from shared.did import create_local_did
from shared.credentials import issue_delegation, credential_hash
from shared.policy import validate_cod
from shared.domain_policy import VENDOR_B_POLICY, SERVICE_DATA, is_operation_allowed
from shared.tracing import Trace

app = FastAPI(title="Vendor B / DAM_B", version="0.3.0")
DAM_B = create_local_did("dam-b")
LEDGER = "http://ledger-service:9000"

class ProtectedResourceRequest(BaseModel):
    capability: Dict[str, Any]
    request: Dict[str, Any]
    holder_proof: Dict[str, Any]
    challenge: str
    verifier_public_key: str | None = None

class DownstreamDelegationRequest(BaseModel):
    cod_to_dam_b: List[Dict[str, Any]]
    issuer_keys: Dict[str, str]
    delegatee_did: str
    scope: List[str] = ["diagnostics.read"]
    actions: List[str] = ["read-status"]
    resource: str = "asset:compressor-7"
    depth_max: int = 3
    valid_seconds: int = 300

@app.get("/health")
def health() -> Dict[str, str]:
    return {"status": "ok", "service": "vendor-b"}


@app.get("/")
def root() -> Dict[str, Any]:
    return domain_info()

@app.get("/domain-info")
def domain_info() -> Dict[str, Any]:
    return {
        "service": "vendor-b",
        "domain": "VendorB",
        "role": "Vendor-domain DAM and downstream delegation issuer",
        "port": 8000,
        "actor": {"dam_b_did": DAM_B["did"], "dam_b_public_key": DAM_B["public_key"]},
        "endpoints": {
            "GET /health": "service readiness",
            "GET /domain-info": "human-readable domain metadata",
            "GET /did": "DAM_B DID and public key",
            "POST /issue-downstream-delegation": "validate CoD to DAM_B and issue DC3 to VendorAgent",
            "GET /services/catalog": "list protected vendor-side services",
            "GET /policy": "show VendorB local authorization policy",
            "POST /protected-resource/read": "verify capability and return protected service data",
        },
        "enforced_checks_before_issuance": [
            "incoming CoD signature validity",
            "continuity",
            "scope monotonicity",
            "action monotonicity",
            "depth reduction",
            "validity interval",
            "revocation status",
        ],
    }

@app.get("/did")
def did() -> Dict[str, str]:
    return {"dam_b_did": DAM_B["did"], "dam_b_kid": DAM_B["kid"], "dam_b_public_key": DAM_B["public_key"]}

@app.post("/issue-downstream-delegation")
def issue_downstream(req: DownstreamDelegationRequest) -> Dict[str, Any]:
    trace = Trace(operation="issue_downstream_delegation", actor="DAM_B", domain="VendorB")
    trace.inputs = {
        "chain_length_to_dam_b": len(req.cod_to_dam_b),
        "delegatee": req.delegatee_did,
        "scope": req.scope,
        "actions": req.actions,
        "resource": req.resource,
    }
    local_request = {
        "actor_did": DAM_B["did"],
        "scope": req.scope[0] if req.scope else "",
        "action": req.actions[0] if req.actions else "",
        "resource": req.resource,
    }
    with trace.timer("incoming_cod_validation"):
        accepted, checks, reason = validate_cod(req.cod_to_dam_b, req.issuer_keys, local_request, set(), req.depth_max)
    trace.checks = checks
    if not accepted:
        trace.mark("rejected", f"DAM_B cannot issue downstream delegation: {reason}")
        return {"accepted": False, "reason": trace.reason, "trace": trace.to_dict()}

    parent = req.cod_to_dam_b[-1]["payload"]
    new_depth = parent["depth"] - 1
    if new_depth < 0:
        trace.mark("rejected", "no remaining delegation depth")
        return {"accepted": False, "reason": trace.reason, "trace": trace.to_dict()}

    with trace.timer("signature_generation"):
        dc = issue_delegation(
            DAM_B["did"], DAM_B["private_key"], req.delegatee_did,
            req.scope, req.actions, req.resource, new_depth,
            req.valid_seconds, parent_id=parent["id"],
            not_after=parent["valid_until"],
        )
    trace.artifacts["delegation_id"] = dc["payload"]["id"]
    trace.artifacts["credential_hash"] = credential_hash(dc)
    with trace.timer("ledger_anchor"):
        try:
            ledger = requests.post(f"{LEDGER}/anchor", json={"artifact_type": "DelegationCredential", "artifact": dc, "trace": trace.to_dict()}, timeout=3).json()
            trace.artifacts["ledger_tx"] = ledger["tx_id"]
        except Exception as exc:
            trace.artifacts["ledger_error"] = str(exc)
    trace.mark("accepted", "downstream delegation issued by DAM_B")
    return {"accepted": True, "credential": dc, "trace": trace.to_dict(), "issuer_public_key": DAM_B["public_key"]}


@app.get("/policy")
def policy() -> Dict[str, Any]:
    return VENDOR_B_POLICY

@app.get("/services/catalog")
def service_catalog() -> Dict[str, Any]:
    return {
        "domain": "VendorB",
        "services": [
            {"service": "diagnostics-api", "scope": "diagnostics.read", "actions": ["read-status"], "description": "diagnostic status for industrial assets"},
            {"service": "maintenance-api", "scope": "maintenance.history.read", "actions": ["read"], "description": "maintenance history and next service indicators"},
            {"service": "telemetry-api", "scope": "sensor.telemetry.read", "actions": ["read"], "description": "recent telemetry readings"},
            {"service": "firmware-api", "scope": "firmware.version.read", "actions": ["read"], "description": "firmware version inventory"},
            {"service": "firmware-update-api", "scope": "firmware.update", "actions": ["write"], "description": "write endpoint intentionally denied in the case study"},
        ]
    }

@app.post("/protected-resource/read")
def protected_resource(req: ProtectedResourceRequest) -> Dict[str, Any]:
    trace = Trace(operation="protected_resource_access", actor="VendorB", domain="VendorB")
    trace.inputs = {"request": req.request, "capability_id": req.capability.get("payload", {}).get("id")}
    allowed, policy_reason = is_operation_allowed(req.request)
    trace.checks["local_policy_allowed"] = allowed
    trace.checks["local_policy_reason"] = policy_reason
    if not allowed:
        trace.mark("rejected", policy_reason)
        return {"accepted": False, "reason": policy_reason, "trace": trace.to_dict()}
    try:
        verifier_did = requests.get("http://verifier:8010/did", timeout=3).json()
        verifier_public_key = req.verifier_public_key or verifier_did["public_key"]
        verification = requests.post(
            "http://verifier:8010/verify-capability",
            json={"capability": req.capability, "verifier_public_key": verifier_public_key, "request": {**req.request, "audience": "vendor-b"}, "holder_proof": req.holder_proof, "challenge": req.challenge, "consume_nonce": True, "require_holder_proof": True},
            timeout=5,
        ).json()
    except Exception as exc:
        trace.mark("rejected", f"verifier unavailable: {exc}")
        return {"accepted": False, "reason": trace.reason, "trace": trace.to_dict()}
    trace.checks["capability_accepted"] = bool(verification.get("accepted"))
    if not verification.get("accepted"):
        trace.mark("rejected", verification.get("reason", "capability rejected"))
        return {"accepted": False, "reason": trace.reason, "verifier_response": verification, "trace": trace.to_dict()}
    service = req.request.get("service")
    data = SERVICE_DATA.get(service, {})
    trace.mark("accepted", "protected resource returned")
    return {"accepted": True, "reason": trace.reason, "service": service, "resource": req.request.get("resource"), "data": data, "verifier_response": verification, "trace": trace.to_dict()}
