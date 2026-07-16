from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List

import requests

ROOT = Path(__file__).resolve().parents[1]
BASE = {
    "factory": "http://localhost:8001",
    "twin": "http://localhost:8002",
    "vendor_b": "http://localhost:8000",
    "vendor_agent": "http://localhost:8003",
    "verifier": "http://localhost:8010",
}


def post(url: str, payload: Dict[str, Any]) -> Dict[str, Any]:
    r = requests.post(url, json=payload, timeout=10)
    r.raise_for_status()
    return r.json()


def get(url: str) -> Dict[str, Any]:
    r = requests.get(url, timeout=5)
    r.raise_for_status()
    return r.json()


def build_valid_chain() -> Dict[str, Any]:
    twin = get(f"{BASE['twin']}/did")
    dam_b = get(f"{BASE['vendor_b']}/did")
    vendor_agent = get(f"{BASE['vendor_agent']}/did")
    s1 = post(f"{BASE['factory']}/issue-delegation", {"subject_did": twin["did"], "scope": ["diagnostics.read"], "actions": ["read-status"], "resource": "asset:compressor-7", "depth": 3})
    dc1 = s1["credential"]
    s2 = post(f"{BASE['twin']}/delegate-to-domain", {"delegatee_did": dam_b["dam_b_did"], "parent_credential": dc1, "scope": ["diagnostics.read"], "actions": ["read-status"], "resource": "asset:compressor-7"})
    dc2 = s2["credential"]
    keys = {dc1["payload"]["issuer"]: s1["issuer_public_key"], dc2["payload"]["issuer"]: s2["issuer_public_key"]}
    s3 = post(f"{BASE['vendor_b']}/issue-downstream-delegation", {"cod_to_dam_b": [dc1, dc2], "issuer_keys": keys, "delegatee_did": vendor_agent["did"], "scope": ["diagnostics.read"], "actions": ["read-status"], "resource": "asset:compressor-7"})
    dc3 = s3["credential"]
    keys[dc3["payload"]["issuer"]] = s3["issuer_public_key"]
    return {"cod": [dc1, dc2, dc3], "keys": keys, "vendor_agent": vendor_agent}


def verify(cod: List[Dict[str, Any]], keys: Dict[str, str], request: Dict[str, Any], depth_max: int = 3) -> Dict[str, Any]:
    return post(f"{BASE['verifier']}/verify-cod", {"cod": cod, "issuer_keys": keys, "request": request, "depth_max": depth_max, "issue_capability_on_success": False})


def main() -> None:
    chain = build_valid_chain()
    cod = chain["cod"]
    keys = chain["keys"]
    va = chain["vendor_agent"]
    base_req = {"actor_did": va["did"], "scope": "diagnostics.read", "action": "read-status", "resource": "asset:compressor-7"}

    results = []

    bad_req = dict(base_req)
    bad_req["action"] = "write"
    r = verify(cod, keys, bad_req)
    results.append({"case": "http_write_scope_violation", "accepted": r["accepted"], "reason": r.get("reason")})

    tampered = json.loads(json.dumps(cod))
    tampered[-1]["payload"]["actions"] = ["read", "write"]
    r = verify(tampered, keys, base_req)
    results.append({"case": "http_tampered_leaf_signature", "accepted": r["accepted"], "reason": r.get("reason")})

    post(f"{BASE['verifier']}/revoke", {"credential_id": cod[1]["payload"]["id"], "reason": "negative test"})
    r = verify(cod, keys, base_req)
    results.append({"case": "http_revoked_middle_dc", "accepted": r["accepted"], "reason": r.get("reason")})

    print(json.dumps(results, indent=2))


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(json.dumps({"accepted": False, "error": str(exc)}, indent=2), file=sys.stderr)
        sys.exit(1)
