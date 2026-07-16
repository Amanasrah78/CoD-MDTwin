from __future__ import annotations

import time
from typing import Any, Dict, List, Set, Tuple


def is_subset(child: List[str], parent: List[str]) -> bool:
    return set(child).issubset(set(parent))


def _safe_verify_credential_signature(dc: Dict[str, Any], issuer_public_key: str) -> bool:
    from .credentials import verify_credential_signature
    try:
        return verify_credential_signature(dc, issuer_public_key)
    except Exception:
        return False


def validate_cod(
    cod: List[Dict[str, Any]],
    issuer_keys: Dict[str, str],
    request: Dict[str, Any],
    revoked_ids: Set[str],
    depth_max: int = 3,
) -> Tuple[bool, Dict[str, Any], str]:
    checks: Dict[str, Any] = {}
    now = int(time.time())
    required = {"type", "id", "issuer", "subject", "scope", "actions", "resource", "depth", "valid_from", "valid_until", "status"}

    checks["non_empty_chain"] = len(cod) > 0
    checks["depth_within_max"] = len(cod) <= depth_max
    if not checks["non_empty_chain"]:
        return False, checks, "empty chain"
    if not checks["depth_within_max"]:
        return False, checks, "delegation depth exceeded"

    seen_ids: Set[str] = set()
    for i, dc in enumerate(cod):
        p = dc.get("payload", {})
        missing = sorted(required - set(p.keys()))
        checks[f"dc_{i+1}_required_claims_present"] = not missing
        if missing:
            checks[f"dc_{i+1}_missing_claims"] = missing
            return False, checks, f"malformed delegation credential at position {i+1}"

        checks[f"dc_{i+1}_type_valid"] = p.get("type") == "DelegationCredential"
        checks[f"dc_{i+1}_id_unique"] = p.get("id") not in seen_ids
        seen_ids.add(p.get("id"))
        issuer = p.get("issuer")
        checks[f"dc_{i+1}_issuer_key_available"] = issuer in issuer_keys
        checks[f"dc_{i+1}_signature_valid"] = checks[f"dc_{i+1}_issuer_key_available"] and _safe_verify_credential_signature(dc, issuer_keys.get(issuer, ""))
        checks[f"dc_{i+1}_time_valid"] = p.get("valid_from", 0) <= now <= p.get("valid_until", 0)
        checks[f"dc_{i+1}_not_revoked"] = p.get("id") not in revoked_ids
        checks[f"dc_{i+1}_status_active"] = p.get("status") == "active"
        gate_keys = [
            f"dc_{i+1}_type_valid",
            f"dc_{i+1}_id_unique",
            f"dc_{i+1}_signature_valid",
            f"dc_{i+1}_time_valid",
            f"dc_{i+1}_not_revoked",
            f"dc_{i+1}_status_active",
        ]
        if not all(checks[k] for k in gate_keys):
            return False, checks, f"invalid delegation credential at position {i+1}"

    for i in range(len(cod) - 1):
        p = cod[i]["payload"]
        q = cod[i + 1]["payload"]
        checks[f"continuity_{i+1}_{i+2}"] = p["subject"] == q["issuer"]
        checks[f"parent_link_{i+1}_{i+2}"] = q.get("parent_id") in (None, p["id"])
        checks[f"scope_monotonic_{i+1}_{i+2}"] = is_subset(q["scope"], p["scope"])
        checks[f"actions_monotonic_{i+1}_{i+2}"] = is_subset(q["actions"], p["actions"])
        checks[f"resource_monotonic_{i+1}_{i+2}"] = q["resource"] == p["resource"]
        checks[f"depth_decreases_{i+1}_{i+2}"] = q["depth"] == p["depth"] - 1
        if not (
            checks[f"continuity_{i+1}_{i+2}"]
            and checks[f"parent_link_{i+1}_{i+2}"]
            and checks[f"scope_monotonic_{i+1}_{i+2}"]
            and checks[f"actions_monotonic_{i+1}_{i+2}"]
            and checks[f"resource_monotonic_{i+1}_{i+2}"]
            and checks[f"depth_decreases_{i+1}_{i+2}"]
        ):
            return False, checks, f"chain constraint failed between DC_{i+1} and DC_{i+2}"

    leaf = cod[-1]["payload"]
    checks["request_subject_matches_leaf"] = request.get("actor_did") == leaf["subject"]
    checks["request_scope_authorized"] = request.get("scope") in leaf["scope"]
    checks["request_action_authorized"] = request.get("action") in leaf["actions"]
    checks["request_resource_authorized"] = request.get("resource") == leaf["resource"]

    if not all(checks[k] for k in ["request_subject_matches_leaf", "request_scope_authorized", "request_action_authorized", "request_resource_authorized"]):
        return False, checks, "request is outside delegated authority"

    return True, checks, "valid chain of delegation"



def validate_capability(
    capability: Dict[str, Any],
    verifier_public_key: str,
    request: Dict[str, Any],
    revoked_ids: Set[str],
    replay_cache: Set[str],
    consume_nonce: bool = True,
) -> Tuple[bool, Dict[str, Any], str]:
    from .credentials import verify_credential_signature

    checks: Dict[str, Any] = {}
    now = int(time.time())
    p = capability.get("payload", {})
    required = {"type", "id", "issuer", "subject", "kid_s", "scope", "actions", "resource", "audience", "valid_from", "valid_until", "nonce", "cod_hash", "cod_ids"}
    missing = sorted(required - set(p.keys()))
    checks["required_claims_present"] = not missing
    if missing:
        checks["missing_claims"] = missing
        return False, checks, "malformed capability"

    checks["type_is_capability"] = p.get("type") == "Capability"
    try:
        signature_valid = checks["type_is_capability"] and verify_credential_signature(capability, verifier_public_key)
    except Exception:
        signature_valid = False
    checks["signature_valid"] = signature_valid
    checks["time_valid"] = p.get("valid_from", 0) <= now <= p.get("valid_until", 0)
    checks["capability_not_revoked"] = p.get("id") not in revoked_ids
    checks["parent_cod_not_revoked"] = not any(cid in revoked_ids for cid in p.get("cod_ids", []))
    checks["nonce_present"] = bool(p.get("nonce"))
    nonce_key = f"{p.get('id')}:{p.get('nonce')}"
    checks["nonce_not_replayed"] = checks["nonce_present"] and nonce_key not in replay_cache
    checks["subject_matches"] = request.get("actor_did") == p.get("subject")
    checks["holder_key_binding_present"] = bool(p.get("kid_s")) and str(p.get("kid_s")).startswith(f"{p.get('subject')}#")
    checks["scope_authorized"] = request.get("scope") in p.get("scope", [])
    checks["action_authorized"] = request.get("action") in p.get("actions", [])
    checks["resource_authorized"] = request.get("resource") == p.get("resource")
    op_req = {"service": request.get("service"), "scope": request.get("scope"), "action": request.get("action"), "resource": request.get("resource")}
    allowed_ops = p.get("allowed_operations", [])
    if request.get("service") and allowed_ops:
        checks["operation_authorized"] = any(
            op.get("service") == op_req["service"] and op.get("scope") == op_req["scope"] and op.get("action") == op_req["action"] and op.get("resource") == op_req["resource"]
            for op in allowed_ops
        )
    else:
        checks["operation_authorized"] = True
    checks["audience_valid"] = request.get("audience", p.get("audience", "vendor-b")) == p.get("audience", "vendor-b")

    ordered = [
        "type_is_capability",
        "signature_valid",
        "time_valid",
        "capability_not_revoked",
        "parent_cod_not_revoked",
        "nonce_present",
        "nonce_not_replayed",
        "subject_matches",
        "holder_key_binding_present",
        "scope_authorized",
        "action_authorized",
        "resource_authorized",
        "operation_authorized",
        "audience_valid",
    ]
    for key in ordered:
        if not checks[key]:
            reason = {
                "type_is_capability": "artifact is not a capability",
                "signature_valid": "invalid capability signature",
                "time_valid": "capability expired or not yet valid",
                "capability_not_revoked": "capability is revoked",
                "parent_cod_not_revoked": "parent delegation chain has been revoked",
                "nonce_present": "capability nonce is missing",
                "nonce_not_replayed": "capability replay detected",
                "subject_matches": "capability subject does not match requester",
                "holder_key_binding_present": "capability holder verification method is missing or not bound to the subject",
                "scope_authorized": "requested scope is outside capability",
                "action_authorized": "requested action is outside capability",
                "resource_authorized": "requested resource is outside capability",
                "operation_authorized": "requested service operation is outside capability",
                "audience_valid": "capability audience does not match relying domain",
            }[key]
            return False, checks, reason

    if consume_nonce:
        replay_cache.add(nonce_key)
        checks["nonce_consumed"] = True
    else:
        checks["nonce_consumed"] = False
    return True, checks, "valid capability"
