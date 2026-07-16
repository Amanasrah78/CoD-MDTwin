from __future__ import annotations

import requests
from fastapi import FastAPI
from pydantic import BaseModel
from typing import Any, Dict, List

from shared.did import create_local_did
from shared.credentials import issue_delegation, credential_hash
from shared.tracing import Trace

app = FastAPI(title="Factory A / DAM_A", version="0.3.0")
DAM_A = create_local_did("dam-a")
TWIN_DID = "did:local:twin-agent"
LEDGER = "http://ledger-service:9000"

class DelegationRequest(BaseModel):
    subject_did: str | None = None
    scope: List[str] = ["diagnostics.read"]
    actions: List[str] = ["read-status"]
    resource: str = "asset:compressor-7"
    depth: int = 3
    valid_seconds: int = 600

@app.get("/health")
def health() -> Dict[str, str]:
    return {"status": "ok", "service": "factory-a"}


@app.get("/")
def root() -> Dict[str, Any]:
    return domain_info()

@app.get("/domain-info")
def domain_info() -> Dict[str, Any]:
    return {
        "service": "factory-a",
        "domain": "FactoryA",
        "role": "Domain Authority Manager issuer",
        "port": 8001,
        "actors": {
            "dam_a": {"did": DAM_A["did"], "public_key": DAM_A["public_key"]},
            "default_twin": {"did": TWIN_DID},
        },
        "endpoints": {
            "GET /health": "service readiness",
            "GET /domain-info": "human-readable domain metadata",
            "GET /did": "DID and public keys",
            "POST /issue-delegation": "issue DC1 from DAM_A to the Industrial Digital Twin agent",
        },
        "default_policy": {
            "scope": ["diagnostics.read"],
            "actions": ["read-status"],
            "resource": "asset:compressor-7",
            "depth": 3,
        },
    }

@app.get("/did")
def dids() -> Dict[str, Any]:
    return {"dam_a": {"did": DAM_A["did"], "public_key": DAM_A["public_key"]}, "default_twin": {"did": TWIN_DID}}

@app.post("/issue-delegation")
def issue(req: DelegationRequest) -> Dict[str, Any]:
    trace = Trace(operation="issue_delegation", actor="DAM_A", domain="FactoryA")
    subject = req.subject_did or TWIN_DID
    trace.inputs = {"issuer": DAM_A["did"], "subject": subject, "scope": req.scope, "actions": req.actions, "resource": req.resource, "depth": req.depth}
    with trace.timer("signature_generation"):
        dc = issue_delegation(DAM_A["did"], DAM_A["private_key"], subject, req.scope, req.actions, req.resource, req.depth, req.valid_seconds)
    trace.artifacts["delegation_id"] = dc["payload"]["id"]
    trace.artifacts["credential_hash"] = credential_hash(dc)
    with trace.timer("ledger_anchor"):
        try:
            ledger = requests.post(f"{LEDGER}/anchor", json={"artifact_type": "DelegationCredential", "artifact": dc, "trace": trace.to_dict()}, timeout=3).json()
            trace.artifacts["ledger_tx"] = ledger["tx_id"]
        except Exception as exc:
            trace.artifacts["ledger_error"] = str(exc)
    trace.mark("accepted", "delegation credential issued")
    return {"accepted": True, "credential": dc, "trace": trace.to_dict(), "issuer_public_key": DAM_A["public_key"], "subject_did": subject}
