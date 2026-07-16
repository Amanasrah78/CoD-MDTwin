from __future__ import annotations

import csv
import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from shared.did import create_local_did
from shared.credentials import issue_delegation
from shared.policy import validate_cod
from shared.tracing import Trace, sha256_json

RESULTS = Path("results")
(RESULTS / "traces").mkdir(parents=True, exist_ok=True)
(RESULTS / "metrics").mkdir(parents=True, exist_ok=True)


def main() -> None:
    dam_a = create_local_did("dam-a")
    twin = create_local_did("twin-agent")
    dam_b = create_local_did("dam-b")
    vendor = create_local_did("vendor-agent")

    trace = Trace(operation="valid_end_to_end_flow", actor="client", domain="experiment")

    with trace.timer("dc1_issue"):
        dc1 = issue_delegation(dam_a["did"], dam_a["private_key"], twin["did"], ["diagnostics.read"], ["read-status"], "asset:compressor-7", depth=3)
    with trace.timer("dc2_issue"):
        dc2 = issue_delegation(twin["did"], twin["private_key"], dam_b["did"], ["diagnostics.read"], ["read-status"], "asset:compressor-7", depth=2, parent_id=dc1["payload"]["id"])
    with trace.timer("dc3_issue"):
        dc3 = issue_delegation(dam_b["did"], dam_b["private_key"], vendor["did"], ["diagnostics.read"], ["read-status"], "asset:compressor-7", depth=1, parent_id=dc2["payload"]["id"])

    cod = [dc1, dc2, dc3]
    issuer_keys = {
        dam_a["did"]: dam_a["public_key"],
        twin["did"]: twin["public_key"],
        dam_b["did"]: dam_b["public_key"],
    }
    request = {
        "actor_did": vendor["did"],
        "scope": "diagnostics.read",
        "action": "read-status",
        "resource": "asset:compressor-7",
    }

    trace.inputs = {"request": request, "cod_hash": sha256_json(cod)}
    with trace.timer("cod_validation"):
        accepted, checks, reason = validate_cod(cod, issuer_keys, request, revoked_ids=set(), depth_max=3)
    trace.checks = checks
    trace.mark("accepted" if accepted else "rejected", reason)
    trace.artifacts = {"dc_ids": [dc["payload"]["id"] for dc in cod], "cod_hash": sha256_json(cod)}

    trace_path = RESULTS / "traces" / f"{trace.trace_id}.json"
    trace_path.write_text(json.dumps(trace.to_dict(), indent=2, sort_keys=True), encoding="utf-8")

    metrics_path = RESULTS / "metrics" / "valid_flow_metrics.csv"
    with metrics_path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["phase", "latency_ms"])
        writer.writeheader()
        for phase, latency in trace.timing_ms.items():
            writer.writerow({"phase": phase, "latency_ms": latency})

    print(json.dumps({"accepted": accepted, "reason": reason, "trace_file": str(trace_path), "metrics_file": str(metrics_path)}, indent=2))


if __name__ == "__main__":
    main()
