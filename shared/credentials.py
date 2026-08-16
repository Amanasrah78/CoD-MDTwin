from __future__ import annotations

import time
import uuid
from typing import Any, Dict, List

from .crypto import sign_json, verify_json
from .tracing import sha256_json
from .methodology import delegation_methodology_view, capability_methodology_view
from .domain_policy import allowed_operations_from_scopes


def issue_delegation(
    issuer_did: str,
    issuer_private_key: str,
    subject_did: str,
    scope: List[str],
    actions: List[str],
    resource: str,
    depth: int,
    valid_seconds: int = 600,
    parent_id: str | None = None,
    not_after: int | None = None,
) -> Dict[str, Any]:
    now = int(time.time())
    valid_until = now + valid_seconds
    if not_after is not None:
        valid_until = min(valid_until, int(not_after))
    payload = {
        "type": "DelegationCredential",
        "id": "dc_" + uuid.uuid4().hex[:12],
        "issuer": issuer_did,
        "subject": subject_did,
        "parent_id": parent_id,
        "scope": scope,
        "actions": actions,
        "resource": resource,
        "depth": depth,
        "valid_from": now,
        "valid_until": valid_until,
        "status": "active",
    }
    payload["methodology"] = delegation_methodology_view({"payload": payload})["DC_i"]
    return {"payload": payload, "signature": sign_json(issuer_private_key, payload)}


def issue_capability(
    issuer_did: str,
    issuer_private_key: str,
    subject_did: str,
    subject_kid: str,
    effective_scope: List[str],
    actions: List[str],
    resource: str,
    valid_seconds: int = 120,
    cod_hash: str | None = None,
    cod_ids: List[str] | None = None,
    audience: str = "vendor-b",
    allowed_operations: List[Dict[str, Any]] | None = None,
) -> Dict[str, Any]:
    now = int(time.time())
    payload = {
        "type": "Capability",
        "id": "cap_" + uuid.uuid4().hex[:12],
        "issuer": issuer_did,
        "subject": subject_did,
        "kid_s": subject_kid,
        "scope": effective_scope,
        "actions": actions,
        "resource": resource,
        "valid_from": now,
        "valid_until": now + valid_seconds,
        "nonce": uuid.uuid4().hex,
        "cod_hash": cod_hash,
        "cod_ids": cod_ids or [],
        "audience": audience,
        "allowed_operations": allowed_operations if allowed_operations is not None else allowed_operations_from_scopes(effective_scope, resource),
    }
    payload["methodology"] = capability_methodology_view({"payload": payload})["Cap"]
    return {"payload": payload, "signature": sign_json(issuer_private_key, payload)}


def credential_hash(credential: Dict[str, Any]) -> str:
    return sha256_json(credential)


def verify_credential_signature(credential: Dict[str, Any], issuer_public_key: str) -> bool:
    return verify_json(issuer_public_key, credential["payload"], credential["signature"])
