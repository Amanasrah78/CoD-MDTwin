from __future__ import annotations

import requests
from fastapi import FastAPI
from pydantic import BaseModel
from typing import Any, Dict, List

from shared.did import create_local_did
from shared.credentials import issue_delegation, credential_hash
from shared.tracing import Trace

app = FastAPI(title="Industrial Digital Twin Agent", version="0.3.0")
TWIN = create_local_did("twin-agent")
LEDGER = "http://ledger-service:9000"

class DelegateToDomainRequest(BaseModel):
    delegatee_did: str
    parent_credential: Dict[str, Any]
    scope: List[str] = ["diagnostics.read"]
    actions: List[str] = ["read-status"]
    resource: str = "asset:compressor-7"
    valid_seconds: int = 600

@app.get("/health")
def health() -> Dict[str, str]:
    return {"status": "ok", "service": "twin-agent"}


@app.get("/")
def root() -> Dict[str, Any]:
    return domain_info()

@app.get("/domain-info")
def domain_info() -> Dict[str, Any]:
    return {
        "service": "twin-agent",
        "domain": "FactoryA",
        "role": "Industrial Digital Twin agent and intermediate delegate",
        "port": 8002,
        "actor": {"did": TWIN["did"], "public_key": TWIN["public_key"]},
        "endpoints": {
            "GET /health": "service readiness",
            "GET /domain-info": "human-readable service metadata",
            "GET /did": "agent DID and public key",
            "POST /delegate-to-domain": "issue DC2 from TwinAgent to DAM_B under parent DC1",
        },
    }

@app.get("/did")
def did() -> Dict[str, str]:
    return {"did": TWIN["did"], "public_key": TWIN["public_key"]}

@app.post("/delegate-to-domain")
def delegate_to_domain(req: DelegateToDomainRequest) -> Dict[str, Any]:
    trace = Trace(operation="delegate_to_domain", actor="TwinAgent", domain="FactoryA")
    parent = req.parent_credential["payload"]
    new_depth = parent["depth"] - 1
    trace.inputs = {
        "issuer": TWIN["did"],
        "delegatee": req.delegatee_did,
        "parent_id": parent["id"],
        "scope": req.scope,
        "actions": req.actions,
        "resource": req.resource,
        "depth": new_depth,
    }
    if new_depth < 0:
        trace.mark("rejected", "parent delegation has no remaining depth")
        return {"accepted": False, "reason": trace.reason, "trace": trace.to_dict()}
    with trace.timer("signature_generation"):
        dc = issue_delegation(
            TWIN["did"], TWIN["private_key"], req.delegatee_did,
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
    trace.mark("accepted", "downstream delegation issued by TwinAgent")
    return {"accepted": True, "credential": dc, "trace": trace.to_dict(), "issuer_public_key": TWIN["public_key"]}
