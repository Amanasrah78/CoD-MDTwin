from __future__ import annotations

import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))
from typing import Any, Dict, List, Tuple

from shared.did import create_local_did
from shared.credentials import issue_delegation
from shared.policy import validate_cod
from shared.tracing import Trace

RESULTS = Path("results")
(RESULTS / "traces").mkdir(parents=True, exist_ok=True)


def build_base() -> Tuple[List[Dict[str, Any]], Dict[str, str], Dict[str, Any], Dict[str, str]]:
    dam_a = create_local_did("dam-a")
    twin = create_local_did("twin-agent")
    dam_b = create_local_did("dam-b")
    vendor = create_local_did("vendor-agent")
    dc1 = issue_delegation(dam_a["did"], dam_a["private_key"], twin["did"], ["diagnostics.read"], ["read-status"], "asset:compressor-7", depth=3)
    dc2 = issue_delegation(twin["did"], twin["private_key"], dam_b["did"], ["diagnostics.read"], ["read-status"], "asset:compressor-7", depth=2, parent_id=dc1["payload"]["id"])
    dc3 = issue_delegation(dam_b["did"], dam_b["private_key"], vendor["did"], ["diagnostics.read"], ["read-status"], "asset:compressor-7", depth=1, parent_id=dc2["payload"]["id"])
    keys = {dam_a["did"]: dam_a["public_key"], twin["did"]: twin["public_key"], dam_b["did"]: dam_b["public_key"]}
    request = {"actor_did": vendor["did"], "scope": "diagnostics.read", "action": "read-status", "resource": "asset:compressor-7"}
    return [dc1, dc2, dc3], keys, request, {"dc2_id": dc2["payload"]["id"]}


def run_case(name: str, cod: List[Dict[str, Any]], keys: Dict[str, str], request: Dict[str, Any], revoked: set[str], depth_max: int = 3) -> Dict[str, Any]:
    trace = Trace(operation=f"negative_test_{name}", actor="client", domain="experiment")
    trace.inputs = {"test_case": name, "request": request, "depth_max": depth_max}
    with trace.timer("cod_validation"):
        accepted, checks, reason = validate_cod(cod, keys, request, revoked_ids=revoked, depth_max=depth_max)
    trace.checks = checks
    trace.mark("accepted" if accepted else "rejected", reason)
    path = RESULTS / "traces" / f"{trace.trace_id}_{name}.json"
    path.write_text(json.dumps(trace.to_dict(), indent=2, sort_keys=True), encoding="utf-8")
    return {"case": name, "accepted": accepted, "reason": reason, "trace_file": str(path)}


def main() -> None:
    results = []

    cod, keys, request, ids = build_base()
    bad_request = dict(request, action="write")
    results.append(run_case("write_scope_violation", cod, keys, bad_request, set()))

    cod, keys, request, ids = build_base()
    expanded = json.loads(json.dumps(cod))
    expanded[2]["payload"]["actions"] = ["read", "write"]
    results.append(run_case("scope_expansion_tamper", expanded, keys, request, set()))

    cod, keys, request, ids = build_base()
    results.append(run_case("revoked_middle_dc", cod, keys, request, {ids["dc2_id"]}))

    cod, keys, request, ids = build_base()
    results.append(run_case("depth_exceeded", cod, keys, request, set(), depth_max=2))

    print(json.dumps(results, indent=2))


if __name__ == "__main__":
    main()
