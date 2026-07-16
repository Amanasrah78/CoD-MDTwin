from __future__ import annotations

import base64
import hashlib
import json
import secrets
from typing import Any, Dict, Iterable, List

from .crypto import sign_json, verify_json


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def _hash_claim(salt: str, name: str, value: Any) -> str:
    raw = json.dumps([salt, name, value], sort_keys=True, separators=(",", ":")).encode()
    return _b64(hashlib.sha256(raw).digest())


def issue_sd_jwt_like(issuer_did: str, issuer_private_key: str, subject_did: str, claims: Dict[str, Any]) -> Dict[str, Any]:
    """A lightweight SD-JWT-style simulation. It uses salted claim digests.

    It is intentionally labeled as a simulation because it is not a full IETF SD-JWT implementation.
    """
    disclosures = []
    digests = []
    for name, value in claims.items():
        salt = _b64(secrets.token_bytes(16))
        digest = _hash_claim(salt, name, value)
        digests.append(digest)
        disclosures.append({"salt": salt, "claim": name, "value": value, "digest": digest})
    payload = {
        "type": "SD-JWT-Simulation",
        "issuer": issuer_did,
        "subject": subject_did,
        "_sd": digests,
        "disclosure_count": len(disclosures),
        "note": "salted-claim selective-disclosure simulation, not a standards-complete SD-JWT",
    }
    return {"payload": payload, "signature": sign_json(issuer_private_key, payload), "disclosures": disclosures}


def present_sd_jwt_like(credential: Dict[str, Any], reveal: Iterable[str]) -> Dict[str, Any]:
    reveal_set = set(reveal)
    selected = [d for d in credential.get("disclosures", []) if d.get("claim") in reveal_set]
    return {"credential": {"payload": credential["payload"], "signature": credential["signature"]}, "disclosures": selected}


def verify_sd_jwt_like(presentation: Dict[str, Any], issuer_public_key: str) -> Dict[str, Any]:
    cred = presentation.get("credential", {})
    payload = cred.get("payload", {})
    signature_valid = False
    try:
        signature_valid = verify_json(issuer_public_key, payload, cred.get("signature", ""))
    except Exception:
        signature_valid = False
    disclosed: Dict[str, Any] = {}
    digest_checks = []
    sd = set(payload.get("_sd", []))
    for d in presentation.get("disclosures", []):
        digest = _hash_claim(d.get("salt", ""), d.get("claim", ""), d.get("value"))
        ok = digest == d.get("digest") and digest in sd
        digest_checks.append({"claim": d.get("claim"), "digest_valid": ok})
        if ok:
            disclosed[d["claim"]] = d.get("value")
    accepted = signature_valid and all(x["digest_valid"] for x in digest_checks)
    return {
        "accepted": accepted,
        "signature_valid": signature_valid,
        "digest_checks": digest_checks,
        "disclosed_claims": disclosed,
        "hidden_claim_count": max(0, len(sd) - len(disclosed)),
        "mechanism": "SD-JWT-style salted-hash simulation",
    }
