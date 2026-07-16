from __future__ import annotations

from typing import Any, Dict, List


def delegation_methodology_view(dc: Dict[str, Any]) -> Dict[str, Any]:
    p = dc.get("payload", {})
    return {
        "artifact": "DC_i",
        "DC_i": {
            "D_id": p.get("id"),
            "DID_from": p.get("issuer"),
            "DID_to": p.get("subject"),
            "Sigma_i": p.get("scope", []),
            "tau_i": {
                "T_i": {"valid_from": p.get("valid_from"), "valid_until": p.get("valid_until")},
                "Depth_i": p.get("depth"),
                "C_i": {
                    "actions": p.get("actions", []),
                    "resource": p.get("resource"),
                    "allowed_operations": p.get("allowed_operations", []),
                },
            },
            "rho_i": p.get("status"),
            "parent_id": p.get("parent_id"),
        },
    }


def capability_methodology_view(cap: Dict[str, Any]) -> Dict[str, Any]:
    p = cap.get("payload", {})
    return {
        "artifact": "Cap",
        "Cap": {
            "C_id": p.get("id"),
            "Scope_eff": p.get("scope", []),
            "T_cap": {"valid_from": p.get("valid_from"), "valid_until": p.get("valid_until")},
            "Nonce": p.get("nonce"),
            "subject": p.get("subject"),
            "kid_s": p.get("kid_s"),
            "audience": p.get("audience"),
            "resource": p.get("resource"),
            "actions": p.get("actions", []),
            "allowed_operations": p.get("allowed_operations", []),
            "cod_hash": p.get("cod_hash"),
            "cod_ids": p.get("cod_ids", []),
        },
    }


def request_methodology_view(request: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "artifact": "Req",
        "Req": {
            "A_req": request.get("actor_did"),
            "r": request.get("resource"),
            "a": request.get("action"),
            "t": request.get("timestamp"),
            "Aud_req": request.get("audience"),
            "scope": request.get("scope"),
            "service": request.get("service"),
        },
    }


def cod_methodology_view(cod: List[Dict[str, Any]]) -> Dict[str, Any]:
    return {
        "artifact": "CoD",
        "CoD": [delegation_methodology_view(dc)["DC_i"] for dc in cod],
        "notation": "CoD = <d_1, d_2, ..., d_n>",
    }


def revocation_methodology_view(credential_id: str, revoked_at: int, reason: str) -> Dict[str, Any]:
    return {
        "artifact": "Rev",
        "Rev": {"D_id": credential_id, "t_r": revoked_at, "Reason": reason},
    }
