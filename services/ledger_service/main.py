from __future__ import annotations

import json
import time
import uuid
from pathlib import Path
from typing import Any, Dict, List

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from shared.tracing import sha256_json

app = FastAPI(title="Ledger Service", version="0.3.0")
LEDGER_PATH = Path("/app/results/traces/ledger.jsonl")
IOTA_SIM_PATH = Path("/app/results/traces/iota_simulated_anchors.jsonl")
LEDGER_PATH.parent.mkdir(parents=True, exist_ok=True)

class AnchorRequest(BaseModel):
    artifact_type: str
    artifact: Dict[str, Any]
    trace: Dict[str, Any] | None = None

@app.get("/health")
def health() -> Dict[str, str]:
    return {"status": "ok", "service": "ledger-service"}


@app.get("/")
def root() -> Dict[str, Any]:
    return domain_info()

@app.get("/domain-info")
def domain_info() -> Dict[str, Any]:
    return {
        "service": "ledger-service",
        "role": "append-only experimental ledger for artifact hashes and traces",
        "port": 9000,
        "storage": str(LEDGER_PATH),
        "endpoints": {
            "GET /health": "service readiness",
            "GET /domain-info": "human-readable ledger metadata",
            "POST /anchor": "append an artifact and hash to the ledger with simulated IOTA receipt",
            "POST /iota-sim/anchor": "create a simulated IOTA anchoring receipt without external account",
            "GET /iota-sim/receipts": "list simulated IOTA receipts",
            "GET /ledger": "all ledger entries",
            "GET /entries": "alias for /ledger",
            "GET /ledger/latest": "latest ledger entry",
            "GET /ledger/tx/{tx_id}": "retrieve one transaction by id",
            "GET /ledger/artifact/{artifact_id}": "retrieve entries containing a credential/capability id",
        },
    }

@app.post("/anchor")
def anchor(req: AnchorRequest) -> Dict[str, Any]:
    artifact_hash = sha256_json(req.artifact)
    iota_receipt = _iota_sim_receipt(artifact_hash, req.artifact_type)
    tx = {
        "tx_id": "ledger_" + artifact_hash.split(":", 1)[1][:16],
        "artifact_type": req.artifact_type,
        "artifact_hash": artifact_hash,
        "artifact": req.artifact,
        "trace": req.trace,
        "iota_simulation_receipt": iota_receipt,
    }
    with LEDGER_PATH.open("a", encoding="utf-8") as f:
        f.write(json.dumps(tx, sort_keys=True) + "\n")
    _append_iota_receipt(iota_receipt)
    return {"accepted": True, "tx_id": tx["tx_id"], "artifact_hash": artifact_hash, "iota_simulation_receipt": iota_receipt}

def _entries() -> List[Dict[str, Any]]:
    if not LEDGER_PATH.exists():
        return []
    return [json.loads(line) for line in LEDGER_PATH.read_text(encoding="utf-8").splitlines() if line.strip()]

@app.get("/entries")
def entries() -> List[Dict[str, Any]]:
    return _entries()

@app.get("/ledger")
def ledger() -> Dict[str, Any]:
    rows = _entries()
    return {"count": len(rows), "entries": rows}

@app.get("/ledger/latest")
def latest() -> Dict[str, Any]:
    rows = _entries()
    if not rows:
        raise HTTPException(status_code=404, detail="ledger is empty")
    return rows[-1]

@app.get("/ledger/tx/{tx_id}")
def by_tx(tx_id: str) -> Dict[str, Any]:
    for row in _entries():
        if row.get("tx_id") == tx_id:
            return row
    raise HTTPException(status_code=404, detail="transaction not found")

@app.get("/ledger/artifact/{artifact_id}")
def by_artifact(artifact_id: str) -> Dict[str, Any]:
    matches = []
    for row in _entries():
        payload = row.get("artifact", {}).get("payload", {})
        if payload.get("id") == artifact_id or row.get("artifact", {}).get("credential_id") == artifact_id:
            matches.append(row)
    return {"artifact_id": artifact_id, "count": len(matches), "entries": matches}


def _iota_sim_receipt(artifact_hash: str, artifact_type: str) -> Dict[str, Any]:
    network = "iota-simulation-local"
    message_id = "iota_sim_" + uuid.uuid4().hex
    return {
        "mode": "simulation",
        "network": network,
        "message_id": message_id,
        "index": "delegation-auth-prototype",
        "artifact_type": artifact_type,
        "anchored_hash": artifact_hash,
        "milestone_index": int(time.time()) % 1000000,
        "confirmed": True,
        "warning": "Simulated IOTA receipt. No external IOTA account, node, token, or transaction was used.",
    }

def _append_iota_receipt(receipt: Dict[str, Any]) -> None:
    IOTA_SIM_PATH.parent.mkdir(parents=True, exist_ok=True)
    with IOTA_SIM_PATH.open("a", encoding="utf-8") as f:
        f.write(json.dumps(receipt, sort_keys=True) + "\n")

@app.post("/iota-sim/anchor")
def iota_sim_anchor(req: AnchorRequest) -> Dict[str, Any]:
    artifact_hash = sha256_json(req.artifact)
    receipt = _iota_sim_receipt(artifact_hash, req.artifact_type)
    _append_iota_receipt(receipt)
    return {"accepted": True, "artifact_hash": artifact_hash, "iota_simulation_receipt": receipt}

@app.get("/iota-sim/receipts")
def iota_sim_receipts() -> Dict[str, Any]:
    if not IOTA_SIM_PATH.exists():
        return {"count": 0, "receipts": []}
    rows = [json.loads(line) for line in IOTA_SIM_PATH.read_text(encoding="utf-8").splitlines() if line.strip()]
    return {"count": len(rows), "receipts": rows}
