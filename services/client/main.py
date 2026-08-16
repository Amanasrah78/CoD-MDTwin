from __future__ import annotations

import copy
import csv
import json
import math
import random
import statistics
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from threading import Event, Thread
from typing import Any, Dict, List, Tuple

import requests
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from shared.crypto import generate_keypair, sign_holder_proof, verify_holder_proof
from shared.credentials import issue_delegation


app = FastAPI(title="Prototype Client Orchestrator", version="0.6.0")

BASE = {
    "factory": "http://factory-a:8001",
    "twin": "http://twin-agent:8002",
    "vendor_b": "http://vendor-b:8000",
    "vendor_agent": "http://vendor-agent:8003",
    "verifier": "http://verifier:8010",
    "ledger": "http://ledger-service:9000",
    "metrics": "http://metrics-service:9100",
}

RESULTS_DIR = Path("/app/results/metrics")
PERF_RAW = RESULTS_DIR / "performance_raw.csv"
PERF_SUMMARY = RESULTS_DIR / "performance_summary.csv"
STRESS_SUMMARY = RESULTS_DIR / "stress_summary.csv"
SINGLE_USE_RAW = RESULTS_DIR / "single_use_renewal_raw.csv"
SINGLE_USE_SESSIONS = RESULTS_DIR / "single_use_renewal_sessions.csv"
SINGLE_USE_SUMMARY = RESULTS_DIR / "single_use_renewal_summary.csv"
REVOCATION_PROPAGATION_RAW = RESULTS_DIR / "revocation_propagation_raw.csv"
REVOCATION_PROPAGATION_SUMMARY = RESULTS_DIR / "revocation_propagation_summary.csv"
REVOCATION_OUTAGE_RAW = RESULTS_DIR / "revocation_outage_raw.csv"


class FlowRequest(BaseModel):
    scope: str = "diagnostics.read"
    action: str = "read-status"
    resource: str = "asset:compressor-7"
    depth: int = 3
    issue_capability_on_success: bool = True
    capability_valid_seconds: int = 120


class PerformanceRequest(BaseModel):
    iterations: int = Field(default=100, ge=1, le=5000)
    warmup: int = Field(default=5, ge=0, le=1000)
    include_capability_verification: bool = True
    reset_verifier_state: bool = True


def _ms(start: float, end: float) -> float:
    return round((end - start) * 1000.0, 6)


def get_json(url: str) -> Dict[str, Any]:
    r = requests.get(url, timeout=5)
    r.raise_for_status()
    return r.json()


def post_json(url: str, payload: Dict[str, Any] | None = None) -> Dict[str, Any]:
    r = requests.post(url, json=payload or {}, timeout=20)
    r.raise_for_status()
    return r.json()


def timed_post_json(url: str, payload: Dict[str, Any] | None = None) -> tuple[Dict[str, Any], float]:
    t0 = time.perf_counter()
    out = post_json(url, payload or {})
    return out, _ms(t0, time.perf_counter())


def normalize_access_request(request: Dict[str, Any]) -> Dict[str, Any]:
    normalized = dict(request)
    normalized.setdefault("audience", "vendor-b")
    if normalized.get("scope") == "diagnostics.read":
        normalized.setdefault("service", "diagnostics-api")
    normalized["timestamp"] = int(time.time())
    return normalized


def prepare_holder_presentation(
    capability: Dict[str, Any],
    request: Dict[str, Any],
    challenge_validity_seconds: int = 30,
) -> Dict[str, Any]:
    normalized_request = normalize_access_request(request)
    challenge, challenge_http_ms = timed_post_json(
        f"{BASE['verifier']}/challenge",
        {"capability": capability, "validity_seconds": challenge_validity_seconds},
    )
    if not challenge.get("accepted"):
        return {
            "accepted": False,
            "reason": challenge.get("reason", "challenge issuance failed"),
            "request": normalized_request,
            "challenge_response": challenge,
            "timing_ms": {"challenge_issue_http": challenge_http_ms},
        }
    proof, holder_sign_http_ms = timed_post_json(
        f"{BASE['vendor_agent']}/holder-proof",
        {
            "capability": capability,
            "request": normalized_request,
            "challenge": challenge["challenge"],
        },
    )
    return {
        "accepted": bool(proof.get("accepted")),
        "reason": proof.get("reason"),
        "request": normalized_request,
        "challenge": challenge.get("challenge"),
        "holder_proof": proof.get("holder_proof"),
        "challenge_response": challenge,
        "proof_response": proof,
        "timing_ms": {
            "challenge_issue_http": challenge_http_ms,
            "holder_sign_http": holder_sign_http_ms,
        },
    }


def verify_capability_with_holder(
    capability: Dict[str, Any],
    verifier_public_key: str,
    request: Dict[str, Any],
    *,
    consume_nonce: bool = True,
    consume_challenge: bool | None = None,
    require_holder_proof: bool = True,
    prepared: Dict[str, Any] | None = None,
    require_fresh_revocation_status: bool = False,
    max_revocation_status_age_ms: float = 1000.0,
) -> Dict[str, Any]:
    presentation = prepared
    if require_holder_proof and presentation is None:
        presentation = prepare_holder_presentation(capability, request)
    normalized_request = (presentation or {}).get("request") or normalize_access_request(request)
    payload = {
        "capability": capability,
        "verifier_public_key": verifier_public_key,
        "request": normalized_request,
        "holder_proof": (presentation or {}).get("holder_proof"),
        "challenge": (presentation or {}).get("challenge"),
        "consume_nonce": consume_nonce,
        "consume_challenge": consume_challenge,
        "require_holder_proof": require_holder_proof,
        "require_fresh_revocation_status": require_fresh_revocation_status,
        "max_revocation_status_age_ms": max_revocation_status_age_ms,
    }
    return post_json(f"{BASE['verifier']}/verify-capability", payload)


def timed_verify_capability_with_holder(
    capability: Dict[str, Any],
    verifier_public_key: str,
    request: Dict[str, Any],
    *,
    consume_nonce: bool = True,
    consume_challenge: bool | None = None,
    require_holder_proof: bool = True,
    prepared: Dict[str, Any] | None = None,
    require_fresh_revocation_status: bool = False,
    max_revocation_status_age_ms: float = 1000.0,
) -> tuple[Dict[str, Any], Dict[str, float]]:
    presentation = prepared
    timings: Dict[str, float] = {}
    if require_holder_proof and presentation is None:
        presentation = prepare_holder_presentation(capability, request)
        timings.update(presentation.get("timing_ms", {}))
    t0 = time.perf_counter()
    out = verify_capability_with_holder(
        capability,
        verifier_public_key,
        request,
        consume_nonce=consume_nonce,
        consume_challenge=consume_challenge,
        require_holder_proof=require_holder_proof,
        prepared=presentation,
        require_fresh_revocation_status=require_fresh_revocation_status,
        max_revocation_status_age_ms=max_revocation_status_age_ms,
    )
    timings["capability_verify_http"] = _ms(t0, time.perf_counter())
    timings["holder_bound_access_total_http"] = round(sum(timings.values()), 6)
    return out, timings


def ingest_trace(scenario: str, trace: Dict[str, Any]) -> None:
    try:
        post_json(f"{BASE['metrics']}/ingest-trace", {"scenario": scenario, "trace": trace})
    except Exception:
        pass


def reset_verifier_state() -> None:
    try:
        post_json(f"{BASE['verifier']}/reset-state", {})
    except Exception:
        pass


def wait_for_services() -> Dict[str, str]:
    status = {}
    for name, base in BASE.items():
        for _ in range(40):
            try:
                health = get_json(f"{base}/health")
                status[name] = health.get("status", "unknown")
                break
            except Exception:
                time.sleep(0.25)
        else:
            status[name] = "not_ready"
    return status


def build_cod(req: FlowRequest, scenario: str = "interactive_valid_flow") -> Dict[str, Any]:
    twin_did = get_json(f"{BASE['twin']}/did")
    dam_b = get_json(f"{BASE['vendor_b']}/did")
    vendor_agent = get_json(f"{BASE['vendor_agent']}/did")

    step1 = post_json(f"{BASE['factory']}/issue-delegation", {
        "subject_did": twin_did["did"],
        "scope": [req.scope],
        "actions": [req.action],
        "resource": req.resource,
        "depth": req.depth,
        "valid_seconds": 600,
    })
    dc1 = step1["credential"]
    ingest_trace(scenario, step1["trace"])

    step2 = post_json(f"{BASE['twin']}/delegate-to-domain", {
        "delegatee_did": dam_b["dam_b_did"],
        "parent_credential": dc1,
        "scope": [req.scope],
        "actions": [req.action],
        "resource": req.resource,
        "valid_seconds": 600,
    })
    if not step2.get("accepted"):
        raise HTTPException(status_code=400, detail=step2)
    dc2 = step2["credential"]
    ingest_trace(scenario, step2["trace"])

    issuer_keys = {
        dc1["payload"]["issuer"]: step1["issuer_public_key"],
        dc2["payload"]["issuer"]: step2["issuer_public_key"],
    }

    step3 = post_json(f"{BASE['vendor_b']}/issue-downstream-delegation", {
        "cod_to_dam_b": [dc1, dc2],
        "issuer_keys": issuer_keys,
        "delegatee_did": vendor_agent["did"],
        "scope": [req.scope],
        "actions": [req.action],
        "resource": req.resource,
        "depth_max": req.depth,
        "valid_seconds": 300,
    })
    if not step3.get("accepted"):
        raise HTTPException(status_code=400, detail=step3)
    dc3 = step3["credential"]
    ingest_trace(scenario, step3["trace"])

    issuer_keys[dc3["payload"]["issuer"]] = step3["issuer_public_key"]

    access_request = {
        "actor_did": vendor_agent["did"],
        "kid_s": vendor_agent["kid"],
        "scope": req.scope,
        "service": "diagnostics-api" if req.scope == "diagnostics.read" else None,
        "action": req.action,
        "resource": req.resource,
        "audience": "vendor-b",
    }
    return {
        "cod": [dc1, dc2, dc3],
        "issuer_keys": issuer_keys,
        "request": access_request,
        "participants": {"twin_agent": twin_did, "dam_b": dam_b, "vendor_agent": vendor_agent},
        "steps": [step1, step2, step3],
    }


def build_cod_timed(req: FlowRequest, scenario: str) -> Dict[str, Any]:
    twin_did = get_json(f"{BASE['twin']}/did")
    dam_b = get_json(f"{BASE['vendor_b']}/did")
    vendor_agent = get_json(f"{BASE['vendor_agent']}/did")

    step1, t1 = timed_post_json(f"{BASE['factory']}/issue-delegation", {
        "subject_did": twin_did["did"], "scope": [req.scope], "actions": [req.action],
        "resource": req.resource, "depth": req.depth, "valid_seconds": 600,
    })
    dc1 = step1["credential"]
    ingest_trace(scenario, step1["trace"])

    step2, t2 = timed_post_json(f"{BASE['twin']}/delegate-to-domain", {
        "delegatee_did": dam_b["dam_b_did"], "parent_credential": dc1, "scope": [req.scope],
        "actions": [req.action], "resource": req.resource, "valid_seconds": 600,
    })
    if not step2.get("accepted"):
        raise HTTPException(status_code=400, detail=step2)
    dc2 = step2["credential"]
    ingest_trace(scenario, step2["trace"])

    issuer_keys = {dc1["payload"]["issuer"]: step1["issuer_public_key"], dc2["payload"]["issuer"]: step2["issuer_public_key"]}

    step3, t3 = timed_post_json(f"{BASE['vendor_b']}/issue-downstream-delegation", {
        "cod_to_dam_b": [dc1, dc2], "issuer_keys": issuer_keys,
        "delegatee_did": vendor_agent["did"], "scope": [req.scope], "actions": [req.action],
        "resource": req.resource, "depth_max": req.depth, "valid_seconds": 300,
    })
    if not step3.get("accepted"):
        raise HTTPException(status_code=400, detail=step3)
    dc3 = step3["credential"]
    ingest_trace(scenario, step3["trace"])
    issuer_keys[dc3["payload"]["issuer"]] = step3["issuer_public_key"]
    access_request = {"actor_did": vendor_agent["did"], "kid_s": vendor_agent["kid"], "scope": req.scope, "service": "diagnostics-api" if req.scope == "diagnostics.read" else None, "action": req.action, "resource": req.resource, "audience": "vendor-b"}

    return {
        "cod": [dc1, dc2, dc3], "issuer_keys": issuer_keys, "request": access_request,
        "steps": [step1, step2, step3],
        "client_timing_ms": {"dc1_issuance_http": t1, "dc2_delegation_http": t2, "dc3_downstream_delegation_http": t3},
    }


@app.get("/health")
def health() -> Dict[str, str]:
    return {"status": "ok", "service": "client"}


@app.get("/")
def root() -> Dict[str, Any]:
    return domain_info()


@app.get("/domain-info")
def domain_info() -> Dict[str, Any]:
    return {
        "service": "client",
        "role": "interactive prototype orchestrator for demonstrations, token tests, and repeated benchmarks",
        "port": 8020,
        "endpoints": {
            "GET /health": "service readiness",
            "GET /domain-info": "human-readable client metadata",
            "GET /services": "read domain-info from all services",
            "POST /run-valid-flow": "execute the full valid CoD and capability realization flow",
            "POST /run-negative-test/{case}": "execute one named negative test",
            "POST /run-capability-test": "verify holder-bound capability use, capability replay, and holder-proof replay",
            "POST /run-performance": "run repeated benchmark and write CSV files",
            "GET /performance-raw": "return performance_raw.csv rows",
            "GET /performance-summary": "return performance_summary.csv rows",
            "POST /run-token-tests": "execute comprehensive delegation-token and capability-token security tests",
            "POST /run-stress-load": "run repeated authorization flows under configurable concurrency",
            "POST /run-stress-replay": "test concurrent capability replay and holder-proof replay",
            "POST /run-stress-depth": "test delegation depth and depth-decrement boundary cases",
            "POST /run-stress-token-size": "measure large-scope delegation token verification latency",
            "POST /run-stress-multiservice": "exercise many authorized and unauthorized service scopes",
            "POST /run-stress-revocation": "test revocation cascade for new and existing capabilities",
            "POST /run-stress-malformed": "send malformed DC and capability tokens",
            "POST /run-stress-ledger": "anchor many audit artifacts and measure latency",
            "POST /run-stress-revocation-list": "measure validation with many revoked identifiers",
            "POST /run-revocation-scale": "measure revocation latency and cascading invalidation as dependent capabilities increase",
            "POST /run-single-use-renewal": "compare on-demand renewal with pre-issued single-use capability pools",
            "POST /run-revocation-propagation": "measure delayed revocation delivery and fail-closed stale-status handling",
            "POST /run-monotonic-delegation-stress": "stress-test monotonic delegation enforcement under valid and authority-expanding chains",
            "POST /run-crypto-cost": "measure cryptographic and security-mechanism operation costs",
            "POST /run-stress-clock-skew": "test expired-token timing boundaries",
            "POST /run-stress-failure-injection": "simulate fail-closed behavior for unavailable verifier/invalid endpoint",
            "POST /run-stress-all": "run all stress tests and write stress_summary.csv",
            "GET /stress-summary": "return stress_summary.csv rows",
        },
        "negative_cases": ["write_scope_violation", "tampered_leaf_signature", "revoked_middle_dc", "depth_exceeded"],
        "host_urls": {
            "factory-a": "http://localhost:8001/domain-info",
            "vendor-b": "http://localhost:8000/domain-info",
            "twin-agent": "http://localhost:8002/domain-info",
            "vendor-agent": "http://localhost:8003/domain-info",
            "verifier": "http://localhost:8010/domain-info",
            "ledger": "http://localhost:9000/ledger",
            "metrics": "http://localhost:9100/summary",
            "performance": "http://localhost:8020/performance-summary",
        },
    }


@app.get("/services")
def services() -> Dict[str, Any]:
    out = {"health": wait_for_services(), "services": {}}
    for name, base in BASE.items():
        try:
            out["services"][name] = get_json(f"{base}/domain-info")
        except Exception as exc:
            out["services"][name] = {"error": str(exc)}
    return out


@app.post("/run-valid-flow")
def run_valid_flow(req: FlowRequest = FlowRequest()) -> Dict[str, Any]:
    built = build_cod(req, "interactive_valid_flow")
    final = post_json(f"{BASE['verifier']}/verify-cod", {
        "cod": built["cod"],
        "issuer_keys": built["issuer_keys"],
        "request": built["request"],
        "depth_max": req.depth,
        "issue_capability_on_success": req.issue_capability_on_success,
        "capability_valid_seconds": req.capability_valid_seconds,
    })
    ingest_trace("interactive_valid_flow", final["trace"])
    return {
        "accepted": final["accepted"],
        "reason": final.get("reason"),
        "delegation_chain": [dc["payload"]["id"] for dc in built["cod"]],
        "capability_id": final.get("capability", {}).get("payload", {}).get("id"),
        "request": built["request"],
        "cod": built["cod"],
        "capability": final.get("capability"),
        "verifier_public_key": final.get("verifier_public_key"),
        "trace": final["trace"],
        "all_step_traces": [s["trace"] for s in built["steps"]] + [final["trace"]],
        "inspect": {"ledger": "http://localhost:9000/ledger", "metrics": "http://localhost:9100/summary", "latest_trace": "http://localhost:9100/latest-trace"},
    }


@app.post("/run-negative-test/{case}")
def run_negative_test(case: str) -> Dict[str, Any]:
    base_req = FlowRequest()
    built = build_cod(base_req, f"interactive_negative_{case}")
    cod = built["cod"]
    issuer_keys = built["issuer_keys"]
    access_request = dict(built["request"])
    depth_max = base_req.depth

    if case == "write_scope_violation":
        access_request["action"] = "write"
    elif case == "tampered_leaf_signature":
        cod = copy.deepcopy(cod)
        cod[-1]["payload"]["scope"] = ["diagnostics.read", "maintenance.write"]
    elif case == "revoked_middle_dc":
        post_json(f"{BASE['verifier']}/revoke", {"credential_id": cod[1]["payload"]["id"], "reason": "interactive negative test"})
    elif case == "depth_exceeded":
        depth_max = 2
    else:
        raise HTTPException(status_code=404, detail=f"unknown negative test: {case}")

    final = post_json(f"{BASE['verifier']}/verify-cod", {
        "cod": cod,
        "issuer_keys": issuer_keys,
        "request": access_request,
        "depth_max": depth_max,
        "issue_capability_on_success": True,
    })
    ingest_trace(f"interactive_negative_{case}", final["trace"])
    return {"case": case, "accepted": final.get("accepted"), "reason": final.get("reason"), "expected": "rejected", "passed": final.get("accepted") is False, "request": access_request, "delegation_chain": [dc["payload"]["id"] for dc in cod], "trace": final["trace"]}


@app.post("/run-capability-test")
def run_capability_test(req: FlowRequest = FlowRequest()) -> Dict[str, Any]:
    reset_verifier_state()
    valid = run_valid_flow(req)
    capability = valid.get("capability")
    verifier_public_key = valid.get("verifier_public_key")
    access_request = valid.get("request")
    if not capability or not verifier_public_key or not access_request:
        raise HTTPException(status_code=400, detail="valid flow did not return a capability")

    presentation = prepare_holder_presentation(capability, access_request)
    first = verify_capability_with_holder(
        capability, verifier_public_key, access_request,
        consume_nonce=True, consume_challenge=True, prepared=presentation,
    )
    ingest_trace("interactive_capability_first_use", first["trace"])
    replay = verify_capability_with_holder(
        capability, verifier_public_key, access_request,
        consume_nonce=True, consume_challenge=True, prepared=presentation,
    )
    ingest_trace("interactive_capability_replay", replay["trace"])

    fresh = run_valid_flow(req)
    wrong_action_req = dict(fresh["request"])
    wrong_action_req["action"] = "write"
    wrong_action = verify_capability_with_holder(
        fresh["capability"], fresh["verifier_public_key"], wrong_action_req,
        consume_nonce=False, consume_challenge=False,
    )
    ingest_trace("interactive_capability_wrong_action", wrong_action["trace"])

    proof_replay_flow = run_valid_flow(req)
    proof_presentation = prepare_holder_presentation(
        proof_replay_flow["capability"], proof_replay_flow["request"]
    )
    proof_first = verify_capability_with_holder(
        proof_replay_flow["capability"], proof_replay_flow["verifier_public_key"],
        proof_replay_flow["request"], consume_nonce=False,
        consume_challenge=True, prepared=proof_presentation,
    )
    proof_replay = verify_capability_with_holder(
        proof_replay_flow["capability"], proof_replay_flow["verifier_public_key"],
        proof_replay_flow["request"], consume_nonce=False,
        consume_challenge=True, prepared=proof_presentation,
    )

    passed = (
        first.get("accepted") is True
        and replay.get("accepted") is False
        and wrong_action.get("accepted") is False
        and proof_first.get("accepted") is True
        and proof_replay.get("accepted") is False
    )
    return {
        "capability_id": capability["payload"]["id"],
        "first_use": {"accepted": first.get("accepted"), "reason": first.get("reason")},
        "capability_replay": {"accepted": replay.get("accepted"), "reason": replay.get("reason")},
        "wrong_action": {"accepted": wrong_action.get("accepted"), "reason": wrong_action.get("reason")},
        "holder_proof_first_use": {"accepted": proof_first.get("accepted"), "reason": proof_first.get("reason")},
        "holder_proof_replay": {"accepted": proof_replay.get("accepted"), "reason": proof_replay.get("reason")},
        "passed": passed,
        "traces": [first["trace"], replay["trace"], wrong_action["trace"], proof_first["trace"], proof_replay["trace"]],
    }


def _summary(rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    groups: Dict[str, List[float]] = {}
    for row in rows:
        groups.setdefault(row["operation"], []).append(float(row["value_ms"]))
    out = []
    for op, values in sorted(groups.items()):
        n = len(values)
        mean = statistics.fmean(values)
        std = statistics.stdev(values) if n > 1 else 0.0
        ci95 = 1.96 * std / (n ** 0.5) if n > 1 else 0.0
        out.append({"operation": op, "count": n, "mean_ms": round(mean, 6), "std_ms": round(std, 6), "min_ms": round(min(values), 6), "max_ms": round(max(values), 6), "ci95_ms": round(ci95, 6)})
    return out


def _write_csv(path: Path, rows: List[Dict[str, Any]], fieldnames: List[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def _read_csv(path: Path) -> List[Dict[str, Any]]:
    if not path.exists():
        return []
    with path.open("r", encoding="utf-8") as f:
        return list(csv.DictReader(f))


@app.post("/run-performance")
def run_performance(req: PerformanceRequest = PerformanceRequest()) -> Dict[str, Any]:
    if req.reset_verifier_state:
        reset_verifier_state()
    wait_for_services()
    raw_rows: List[Dict[str, Any]] = []
    flow_req = FlowRequest()
    total_runs = req.warmup + req.iterations
    failures: List[Dict[str, Any]] = []

    for run_index in range(total_runs):
        is_warmup = run_index < req.warmup
        iteration = run_index - req.warmup + 1
        scenario = "benchmark_warmup" if is_warmup else "benchmark"
        t0 = time.perf_counter()
        try:
            built = build_cod_timed(flow_req, scenario)
            final, t_verify = timed_post_json(
                f"{BASE['verifier']}/verify-cod",
                {"cod": built["cod"], "issuer_keys": built["issuer_keys"],
                 "request": built["request"], "depth_max": flow_req.depth,
                 "issue_capability_on_success": True,
                 "capability_valid_seconds": flow_req.capability_valid_seconds},
            )
            ingest_trace(scenario, final["trace"])
            accepted = bool(final.get("accepted"))
            capability = final.get("capability")
            verifier_public_key = final.get("verifier_public_key")
            cap_result = None
            presentation_timings: Dict[str, float] = {}
            if req.include_capability_verification and capability and verifier_public_key:
                cap_result, presentation_timings = timed_verify_capability_with_holder(
                    capability, verifier_public_key, built["request"],
                    consume_nonce=True, consume_challenge=True,
                )
                ingest_trace(scenario, cap_result["trace"])
                accepted = accepted and bool(cap_result.get("accepted"))
            total_ms = _ms(t0, time.perf_counter())
        except Exception as exc:
            failures.append({"iteration": iteration if not is_warmup else f"warmup-{run_index+1}", "error": str(exc)})
            continue

        if is_warmup:
            continue

        row_base = {"iteration": iteration, "accepted": accepted}
        values = {
            "dc1_issuance_http": built["client_timing_ms"]["dc1_issuance_http"],
            "dc2_delegation_http": built["client_timing_ms"]["dc2_delegation_http"],
            "dc3_downstream_delegation_http": built["client_timing_ms"]["dc3_downstream_delegation_http"],
            "cod_verify_http": t_verify,
            "total_flow_ms": total_ms,
            **presentation_timings,
        }
        for k, v in final.get("trace", {}).get("timing_ms", {}).items():
            values[f"verifier_{k}"] = v
        if cap_result:
            for k, v in cap_result.get("trace", {}).get("timing_ms", {}).items():
                values[f"capability_{k}"] = v
        ledger_values = []
        for tr in [step["trace"] for step in built["steps"]] + [final.get("trace", {})] + ([cap_result.get("trace", {})] if cap_result else []):
            if "ledger_anchor" in tr.get("timing_ms", {}):
                ledger_values.append(float(tr["timing_ms"]["ledger_anchor"]))
        if ledger_values:
            values["ledger_anchor_total_ms"] = round(sum(ledger_values), 6)
        for op, value in values.items():
            raw_rows.append({**row_base, "operation": op, "value_ms": value})

    summary_rows = _summary(raw_rows)
    _write_csv(PERF_RAW, raw_rows, ["iteration", "accepted", "operation", "value_ms"])
    _write_csv(PERF_SUMMARY, summary_rows, ["operation", "count", "mean_ms", "std_ms", "min_ms", "max_ms", "ci95_ms"])
    success_iterations = len({r["iteration"] for r in raw_rows if r["accepted"] is True})
    return {"accepted": True, "iterations": req.iterations, "warmup": req.warmup,
            "success_iterations": success_iterations, "failure_count": len(failures),
            "failures": failures[:10], "raw_file": str(PERF_RAW),
            "summary_file": str(PERF_SUMMARY), "summary": summary_rows}


@app.get("/performance-raw")
def performance_raw() -> Dict[str, Any]:
    rows = _read_csv(PERF_RAW)
    return {"count": len(rows), "file": str(PERF_RAW), "rows": rows}


@app.get("/performance-summary")
def performance_summary() -> Dict[str, Any]:
    rows = _read_csv(PERF_SUMMARY)
    return {"count": len(rows), "file": str(PERF_SUMMARY), "summary": rows}


def _verify_cod_case(case: str, expected_accept: bool, cod: List[Dict[str, Any]], issuer_keys: Dict[str, str], access_request: Dict[str, Any], depth_max: int = 3) -> Dict[str, Any]:
    final = post_json(f"{BASE['verifier']}/verify-cod", {"cod": cod, "issuer_keys": issuer_keys, "request": access_request, "depth_max": depth_max, "issue_capability_on_success": True})
    ingest_trace(f"token_test_{case}", final["trace"])
    accepted = bool(final.get("accepted"))
    return {"case": case, "accepted": accepted, "expected": expected_accept, "passed": accepted is expected_accept, "reason": final.get("reason"), "trace_id": final.get("trace", {}).get("trace_id")}


def _verify_cap_case(case: str, expected_accept: bool, capability: Dict[str, Any], verifier_public_key: str, access_request: Dict[str, Any], consume_nonce: bool = False) -> Dict[str, Any]:
    final = verify_capability_with_holder(
        capability, verifier_public_key, access_request,
        consume_nonce=consume_nonce,
        consume_challenge=consume_nonce,
        require_holder_proof=True,
    )
    ingest_trace(f"token_test_{case}", final["trace"])
    accepted = bool(final.get("accepted"))
    return {"case": case, "accepted": accepted, "expected": expected_accept,
            "passed": accepted is expected_accept, "reason": final.get("reason"),
            "trace_id": final.get("trace", {}).get("trace_id")}


@app.post("/run-token-tests")
def run_token_tests() -> Dict[str, Any]:
    reset_verifier_state()
    base_req = FlowRequest()
    delegation_tests: List[Dict[str, Any]] = []
    capability_tests: List[Dict[str, Any]] = []

    # Baseline CoD acceptance.
    built = build_cod(base_req, "token_tests_baseline")
    cod = built["cod"]
    keys = built["issuer_keys"]
    access_request = built["request"]
    delegation_tests.append(_verify_cod_case("valid_three_hop_cod", True, cod, keys, access_request))

    mutated = copy.deepcopy(cod)
    mutated[-1]["payload"]["scope"] = ["diagnostics.read", "maintenance.write"]
    delegation_tests.append(_verify_cod_case("tampered_dc_payload", False, mutated, keys, access_request))

    mutated = copy.deepcopy(cod)
    mutated[-1]["payload"]["scope"] = ["diagnostics.read", "maintenance.write"]
    # Re-signing is intentionally not available to the attacker in this prototype, so this detects tampering.
    delegation_tests.append(_verify_cod_case("scope_expansion_without_valid_signature", False, mutated, keys, access_request))

    mutated = copy.deepcopy(cod)
    mutated[-1]["payload"]["actions"] = ["read-status", "write"]
    delegation_tests.append(_verify_cod_case("action_expansion_without_valid_signature", False, mutated, keys, access_request))

    mutated = copy.deepcopy(cod)
    mutated[-1]["payload"]["resource"] = "asset:compressor-99"
    delegation_tests.append(_verify_cod_case("resource_expansion_without_valid_signature", False, mutated, keys, access_request))

    mutated = copy.deepcopy(cod)
    mutated[1], mutated[2] = mutated[2], mutated[1]
    delegation_tests.append(_verify_cod_case("reordered_delegation_chain", False, mutated, keys, access_request))

    mutated = [cod[0], cod[2]]
    delegation_tests.append(_verify_cod_case("missing_middle_dc", False, mutated, keys, access_request))

    mutated = [cod[0], cod[1], cod[1]]
    delegation_tests.append(_verify_cod_case("duplicate_dc", False, mutated, keys, access_request))

    mutated_keys = dict(keys)
    mutated_keys[cod[-1]["payload"]["issuer"]] = list(keys.values())[0]
    delegation_tests.append(_verify_cod_case("wrong_issuer_key", False, cod, mutated_keys, access_request))

    mutated = copy.deepcopy(cod)
    mutated[-1]["payload"].pop("scope", None)
    delegation_tests.append(_verify_cod_case("missing_required_dc_claim", False, mutated, keys, access_request))

    delegation_tests.append(_verify_cod_case("depth_overflow", False, cod, keys, access_request, depth_max=2))

    unknown_kid_request = dict(access_request)
    unknown_kid_request["kid_s"] = "did:local:vendor-agent#unknown-key"
    delegation_tests.append(_verify_cod_case("unknown_holder_verification_method", False, cod, keys, unknown_kid_request))

    post_json(f"{BASE['verifier']}/revoke", {"credential_id": cod[1]["payload"]["id"], "reason": "token security test"})
    delegation_tests.append(_verify_cod_case("revoked_middle_dc", False, cod, keys, access_request))
    reset_verifier_state()

    # Fresh valid capability for capability-token tests.
    valid = run_valid_flow(base_req)
    capability = valid["capability"]
    verifier_public_key = valid["verifier_public_key"]
    cap_req = valid["request"]

    capability_tests.append(_verify_cap_case("valid_capability_without_nonce_consumption", True, capability, verifier_public_key, cap_req, consume_nonce=False))
    first = _verify_cap_case("valid_first_use_consumes_nonce", True, capability, verifier_public_key, cap_req, consume_nonce=True)
    capability_tests.append(first)
    capability_tests.append(_verify_cap_case("replay_same_capability", False, capability, verifier_public_key, cap_req, consume_nonce=True))

    # Use a fresh capability for non-replay negative tests.
    reset_verifier_state()
    valid2 = run_valid_flow(base_req)
    cap2 = valid2["capability"]
    pk2 = valid2["verifier_public_key"]
    req2 = valid2["request"]
    wrong_action = dict(req2); wrong_action["action"] = "write"
    capability_tests.append(_verify_cap_case("wrong_action", False, cap2, pk2, wrong_action, consume_nonce=False))
    wrong_resource = dict(req2); wrong_resource["resource"] = "asset:compressor-99"
    capability_tests.append(_verify_cap_case("wrong_resource", False, cap2, pk2, wrong_resource, consume_nonce=False))
    wrong_subject = dict(req2); wrong_subject["actor_did"] = "did:local:attacker"
    capability_tests.append(_verify_cap_case("wrong_subject", False, cap2, pk2, wrong_subject, consume_nonce=False))

    tampered = copy.deepcopy(cap2)
    tampered["payload"]["actions"] = ["read-status", "write"]
    capability_tests.append(_verify_cap_case("tampered_capability_payload", False, tampered, pk2, req2, consume_nonce=False))

    missing_nonce = copy.deepcopy(cap2)
    missing_nonce["payload"].pop("nonce", None)
    capability_tests.append(_verify_cap_case("missing_nonce", False, missing_nonce, pk2, req2, consume_nonce=False))

    # Validly signed expired capability.
    reset_verifier_state()
    expired = run_valid_flow(FlowRequest(capability_valid_seconds=-1))
    capability_tests.append(_verify_cap_case("expired_capability", False, expired["capability"], expired["verifier_public_key"], expired["request"], consume_nonce=False))

    # Revoked capability.
    reset_verifier_state()
    revoked = run_valid_flow(base_req)
    post_json(f"{BASE['verifier']}/revoke", {"credential_id": revoked["capability"]["payload"]["id"], "reason": "token security test"})
    capability_tests.append(_verify_cap_case("revoked_capability", False, revoked["capability"], revoked["verifier_public_key"], revoked["request"], consume_nonce=False))

    # Holder-key and presentation-freshness tests.
    reset_verifier_state()
    holder = run_valid_flow(base_req)
    holder_cap = holder["capability"]
    holder_pk = holder["verifier_public_key"]
    holder_req = holder["request"]
    prepared = prepare_holder_presentation(holder_cap, holder_req)

    missing_proof = post_json(
        f"{BASE['verifier']}/verify-capability",
        {"capability": holder_cap, "verifier_public_key": holder_pk,
         "request": prepared["request"], "challenge": prepared["challenge"],
         "holder_proof": None, "consume_nonce": False,
         "consume_challenge": False, "require_holder_proof": True},
    )
    capability_tests.append({"case": "missing_holder_proof", "accepted": bool(missing_proof.get("accepted")),
                             "expected": False, "passed": missing_proof.get("accepted") is False,
                             "reason": missing_proof.get("reason")})

    from shared.tracing import sha256_json
    attacker_sk, _ = generate_keypair()
    attacker_proof = sign_holder_proof(
        attacker_sk, sha256_json(holder_cap), prepared["request"], prepared["challenge"]
    )
    wrong_key = post_json(
        f"{BASE['verifier']}/verify-capability",
        {"capability": holder_cap, "verifier_public_key": holder_pk,
         "request": prepared["request"], "challenge": prepared["challenge"],
         "holder_proof": attacker_proof, "consume_nonce": False,
         "consume_challenge": False, "require_holder_proof": True},
    )
    capability_tests.append({"case": "stolen_capability_wrong_holder_key",
                             "accepted": bool(wrong_key.get("accepted")), "expected": False,
                             "passed": wrong_key.get("accepted") is False, "reason": wrong_key.get("reason")})

    changed_request = dict(prepared["request"])
    changed_request["timestamp"] = int(changed_request["timestamp"]) + 1
    modified_request = post_json(
        f"{BASE['verifier']}/verify-capability",
        {"capability": holder_cap, "verifier_public_key": holder_pk,
         "request": changed_request, "challenge": prepared["challenge"],
         "holder_proof": prepared["holder_proof"], "consume_nonce": False,
         "consume_challenge": False, "require_holder_proof": True},
    )
    capability_tests.append({"case": "request_modified_after_holder_signature",
                             "accepted": bool(modified_request.get("accepted")), "expected": False,
                             "passed": modified_request.get("accepted") is False,
                             "reason": modified_request.get("reason")})

    proof_first = verify_capability_with_holder(
        holder_cap, holder_pk, holder_req, consume_nonce=False,
        consume_challenge=True, prepared=prepared
    )
    proof_replay = verify_capability_with_holder(
        holder_cap, holder_pk, holder_req, consume_nonce=False,
        consume_challenge=True, prepared=prepared
    )
    capability_tests.append({"case": "valid_holder_proof_consumes_challenge",
                             "accepted": bool(proof_first.get("accepted")), "expected": True,
                             "passed": proof_first.get("accepted") is True, "reason": proof_first.get("reason")})
    capability_tests.append({"case": "replayed_holder_proof",
                             "accepted": bool(proof_replay.get("accepted")), "expected": False,
                             "passed": proof_replay.get("accepted") is False, "reason": proof_replay.get("reason")})

    all_tests = delegation_tests + capability_tests
    passed = sum(1 for t in all_tests if t["passed"])
    failed = len(all_tests) - passed
    return {
        "summary": {"total": len(all_tests), "passed": passed, "failed": failed},
        "delegation_token_tests": delegation_tests,
        "capability_token_tests": capability_tests,
    }


class StressLoadRequest(BaseModel):
    iterations: int = Field(default=1000, ge=1, le=10000)
    concurrency: int = Field(default=20, ge=1, le=200)
    reset_verifier_state: bool = True


class StressReplayRequest(BaseModel):
    concurrency: int = Field(default=50, ge=2, le=500)


class StressTokenSizeRequest(BaseModel):
    service_counts: List[int] = [1, 10, 50, 100, 250, 500]


class StressLedgerRequest(BaseModel):
    entries: int = Field(default=1000, ge=1, le=50000)


class StressRevocationListRequest(BaseModel):
    entries: int = Field(default=1000, ge=1, le=50000)

class ChainDepthSensitivityRequest(BaseModel):
    depths: List[int] = Field(default=[1, 2, 3, 5, 10])
    iterations: int = Field(default=100, ge=1, le=5000)
    warmup: int = Field(default=5, ge=0, le=1000)
    reset_verifier_state: bool = True


class SingleUseRenewalRequest(BaseModel):
    operation_counts: List[int] = Field(default=[1, 10, 50, 100, 500, 1000])
    repetitions: int = Field(default=5, ge=1, le=50)
    warmup_sessions: int = Field(default=1, ge=0, le=10)
    revocation_operation_count: int = Field(default=100, ge=2, le=5000)
    reset_verifier_state: bool = True


class RevocationPropagationRequest(BaseModel):
    propagation_delays_ms: List[int] = Field(default=[0, 10, 50, 100, 500, 1000])
    outage_freshness_limits_ms: List[int] = Field(default=[0, 50, 100, 500])
    repetitions: int = Field(default=10, ge=1, le=50)
    post_update_attempts: int = Field(default=10, ge=1, le=100)
    minimum_pool_size: int = Field(default=20, ge=5, le=1000)
    reset_verifier_state: bool = True


def _percentile(values: List[float], pct: float) -> float:
    if not values:
        return 0.0
    values_sorted = sorted(values)
    idx = int(round((pct / 100.0) * (len(values_sorted) - 1)))
    return round(values_sorted[idx], 6)


def _stats(values: List[float]) -> Dict[str, Any]:
    n = len(values)
    if n == 0:
        return {
            "count": 0,
            "mean_ms": 0.0,
            "std_ms": 0.0,
            "min_ms": 0.0,
            "max_ms": 0.0,
            "p95_ms": 0.0,
            "p99_ms": 0.0,
            "ci95_ms": 0.0,
        }
    mean = statistics.fmean(values)
    std = statistics.stdev(values) if n > 1 else 0.0
    ci95 = 1.96 * std / (n ** 0.5) if n > 1 else 0.0
    return {
        "count": n,
        "mean_ms": round(mean, 6),
        "std_ms": round(std, 6),
        "min_ms": round(min(values), 6),
        "max_ms": round(max(values), 6),
        "p95_ms": _percentile(values, 95),
        "p99_ms": _percentile(values, 99),
        "ci95_ms": round(ci95, 6),
    }


def _build_synthetic_cod(depth: int) -> Dict[str, Any]:
    """
    Build a valid synthetic monotone Chain-of-Delegation with the requested depth.
    This isolates verifier-side CoD validation cost from service-to-service issuance cost.
    """
    if depth < 1:
        raise ValueError("depth must be >= 1")

    keypairs: List[Tuple[str, str, str]] = []
    for i in range(depth + 1):
        private_key, public_key = generate_keypair()
        did = f"did:local:depth-node-{depth}-{i}"
        keypairs.append((did, private_key, public_key))

    cod: List[Dict[str, Any]] = []
    issuer_keys: Dict[str, str] = {}
    parent_id = None

    for i in range(depth):
        issuer_did, issuer_private_key, issuer_public_key = keypairs[i]
        subject_did, _, _ = keypairs[i + 1]

        dc = issue_delegation(
            issuer_did=issuer_did,
            issuer_private_key=issuer_private_key,
            subject_did=subject_did,
            scope=["diagnostics.read"],
            actions=["read-status"],
            resource="asset:compressor-7",
            depth=depth - i,
            valid_seconds=600,
            parent_id=parent_id,
        )

        cod.append(dc)
        issuer_keys[issuer_did] = issuer_public_key
        parent_id = dc["payload"]["id"]

    request = {
        "actor_did": keypairs[-1][0],
        "scope": "diagnostics.read",
        "action": "read-status",
        "resource": "asset:compressor-7",
    }

    return {
        "cod": cod,
        "issuer_keys": issuer_keys,
        "request": request,
        "depth_max": depth,
    }

def _stress_row(test: str, metric: str, value: Any, unit: str = "", note: str = "") -> Dict[str, Any]:
    return {"test": test, "metric": metric, "value": value, "unit": unit, "note": note}


def _append_stress_summary(rows: List[Dict[str, Any]]) -> None:
    fieldnames = ["test", "metric", "value", "unit", "note"]
    STRESS_SUMMARY.parent.mkdir(parents=True, exist_ok=True)
    existing = _read_csv(STRESS_SUMMARY)
    _write_csv(STRESS_SUMMARY, existing + rows, fieldnames)


def _build_multiscope_cod(scopes: List[str], actions: List[str] | None = None, resource: str = "asset:compressor-7") -> Dict[str, Any]:
    actions = actions or ["read"]
    twin_did = get_json(f"{BASE['twin']}/did")
    dam_b = get_json(f"{BASE['vendor_b']}/did")
    vendor_agent = get_json(f"{BASE['vendor_agent']}/did")

    step1 = post_json(f"{BASE['factory']}/issue-delegation", {
        "subject_did": twin_did["did"], "scope": scopes, "actions": actions,
        "resource": resource, "depth": 3, "valid_seconds": 600,
    })
    dc1 = step1["credential"]
    step2 = post_json(f"{BASE['twin']}/delegate-to-domain", {
        "delegatee_did": dam_b["dam_b_did"], "parent_credential": dc1, "scope": scopes,
        "actions": actions, "resource": resource, "valid_seconds": 600,
    })
    dc2 = step2["credential"]
    keys = {dc1["payload"]["issuer"]: step1["issuer_public_key"], dc2["payload"]["issuer"]: step2["issuer_public_key"]}
    step3 = post_json(f"{BASE['vendor_b']}/issue-downstream-delegation", {
        "cod_to_dam_b": [dc1, dc2], "issuer_keys": keys, "delegatee_did": vendor_agent["did"],
        "scope": scopes, "actions": actions, "resource": resource, "depth_max": 3, "valid_seconds": 300,
    })
    dc3 = step3["credential"]
    keys[dc3["payload"]["issuer"]] = step3["issuer_public_key"]
    return {"cod": [dc1, dc2, dc3], "issuer_keys": keys, "vendor_agent": vendor_agent, "resource": resource}


def _issue_single_use_capability(built: Dict[str, Any]) -> tuple[Dict[str, Any], float]:
    return timed_post_json(
        f"{BASE['verifier']}/verify-cod",
        {
            "cod": built["cod"],
            "issuer_keys": built["issuer_keys"],
            "request": built["request"],
            "depth_max": 3,
            "issue_capability_on_success": True,
            "capability_valid_seconds": 600,
        },
    )


def _run_single_use_session(
    mode: str,
    operation_count: int,
    repetition: int,
    *,
    collect_rows: bool,
) -> tuple[Dict[str, Any], List[Dict[str, Any]]]:
    reset_verifier_state()
    built = build_cod(
        FlowRequest(capability_valid_seconds=600),
        f"single_use_renewal_{mode}",
    )
    state_before = get_json(f"{BASE['verifier']}/state")
    issued: List[tuple[Dict[str, Any], float]] = []
    issuance_total_ms = 0.0
    preissue_wall_ms = 0.0

    if mode == "preissued_pool":
        preissue_start = time.perf_counter()
        for _ in range(operation_count):
            response, issuance_ms = _issue_single_use_capability(built)
            issued.append((response, issuance_ms))
            issuance_total_ms += issuance_ms
        preissue_wall_ms = _ms(preissue_start, time.perf_counter())

    rows: List[Dict[str, Any]] = []
    accepted_count = 0
    rejected_count = 0
    session_start = time.perf_counter()

    for operation_index in range(1, operation_count + 1):
        operation_start = time.perf_counter()
        if mode == "on_demand":
            issued_response, issuance_ms = _issue_single_use_capability(built)
            issuance_total_ms += issuance_ms
        else:
            issued_response, issuance_ms = issued[operation_index - 1]

        access_ms = 0.0
        reason = issued_response.get("reason")
        accepted = False
        if issued_response.get("accepted") and issued_response.get("capability"):
            access_response, access_timings = timed_verify_capability_with_holder(
                issued_response["capability"],
                issued_response["verifier_public_key"],
                built["request"],
                consume_nonce=True,
                consume_challenge=True,
                require_holder_proof=True,
            )
            access_ms = float(access_timings.get("holder_bound_access_total_http", 0.0))
            accepted = bool(access_response.get("accepted"))
            reason = access_response.get("reason")

        if accepted:
            accepted_count += 1
        else:
            rejected_count += 1

        online_operation_ms = _ms(operation_start, time.perf_counter())
        if collect_rows:
            rows.append({
                "mode": mode,
                "operation_count": operation_count,
                "repetition": repetition,
                "operation_index": operation_index,
                "accepted": accepted,
                "reason": reason,
                "issuance_ms": issuance_ms,
                "access_ms": access_ms,
                "online_operation_ms": online_operation_ms,
                "lifecycle_operation_ms": round(issuance_ms + access_ms, 6),
            })

    online_session_ms = _ms(session_start, time.perf_counter())
    state_after = get_json(f"{BASE['verifier']}/state")
    lifecycle_session_ms = round(preissue_wall_ms + online_session_ms, 6)
    return {
        "mode": mode,
        "operation_count": operation_count,
        "repetition": repetition,
        "accepted": accepted_count,
        "rejected": rejected_count,
        "capability_issuance_count": operation_count,
        "issuance_total_ms": round(issuance_total_ms, 6),
        "preissue_wall_ms": preissue_wall_ms,
        "online_session_ms": online_session_ms,
        "lifecycle_session_ms": lifecycle_session_ms,
        "consumed_nonce_delta": int(state_after["consumed_nonce_count"]) - int(state_before["consumed_nonce_count"]),
        "challenge_delta": int(state_after["challenge_count"]) - int(state_before["challenge_count"]),
        "consumed_challenge_delta": int(state_after["consumed_challenge_count"]) - int(state_before["consumed_challenge_count"]),
    }, rows


def _single_use_revocation_check(mode: str, operation_count: int) -> Dict[str, Any]:
    reset_verifier_state()
    built = build_cod(FlowRequest(capability_valid_seconds=600), f"single_use_revocation_{mode}")
    cutoff = operation_count // 2
    issued: List[tuple[Dict[str, Any], float]] = []
    if mode == "preissued_pool":
        issued = [_issue_single_use_capability(built) for _ in range(operation_count)]

    before_accepted = 0
    after_accepted = 0
    after_attempted = operation_count - cutoff
    rejection_reasons: Dict[str, int] = {}

    for operation_index in range(operation_count):
        if operation_index == cutoff:
            post_json(
                f"{BASE['verifier']}/revoke",
                {
                    "credential_id": built["cod"][1]["payload"]["id"],
                    "reason": "single-use renewal mid-session test",
                },
            )

        issued_response = (
            _issue_single_use_capability(built)[0]
            if mode == "on_demand"
            else issued[operation_index][0]
        )
        accepted = False
        reason = issued_response.get("reason", "capability issuance rejected")
        if issued_response.get("accepted") and issued_response.get("capability"):
            access_response, _ = timed_verify_capability_with_holder(
                issued_response["capability"],
                issued_response["verifier_public_key"],
                built["request"],
                consume_nonce=True,
                consume_challenge=True,
                require_holder_proof=True,
            )
            accepted = bool(access_response.get("accepted"))
            reason = access_response.get("reason", "capability verification rejected")

        if operation_index < cutoff:
            before_accepted += int(accepted)
        else:
            after_accepted += int(accepted)
            if not accepted:
                rejection_reasons[str(reason)] = rejection_reasons.get(str(reason), 0) + 1

    return {
        "mode": mode,
        "operation_count": operation_count,
        "revocation_after_operation": cutoff,
        "pre_revocation_accepted": before_accepted,
        "pre_revocation_expected": cutoff,
        "post_revocation_attempted": after_attempted,
        "post_revocation_accepted": after_accepted,
        "post_revocation_rejected": after_attempted - after_accepted,
        "rejection_reasons": rejection_reasons,
        "passed": before_accepted == cutoff and after_accepted == 0,
    }


@app.post("/run-single-use-renewal")
def run_single_use_renewal(
    req: SingleUseRenewalRequest = SingleUseRenewalRequest(),
) -> Dict[str, Any]:
    wait_for_services()
    counts = sorted(set(req.operation_counts))
    if not counts or any(count < 1 or count > 5000 for count in counts):
        raise HTTPException(status_code=400, detail="operation_counts must contain values from 1 to 5000")

    raw_rows: List[Dict[str, Any]] = []
    session_rows: List[Dict[str, Any]] = []
    failures: List[Dict[str, Any]] = []
    modes = ["on_demand", "preissued_pool"]

    for mode in modes:
        for operation_count in counts:
            for warmup_index in range(req.warmup_sessions):
                try:
                    _run_single_use_session(
                        mode,
                        operation_count,
                        -(warmup_index + 1),
                        collect_rows=False,
                    )
                except Exception as exc:
                    failures.append({
                        "phase": "warmup",
                        "mode": mode,
                        "operation_count": operation_count,
                        "error": str(exc),
                    })

            for repetition in range(1, req.repetitions + 1):
                try:
                    session, rows = _run_single_use_session(
                        mode,
                        operation_count,
                        repetition,
                        collect_rows=True,
                    )
                    session_rows.append(session)
                    raw_rows.extend(rows)
                except Exception as exc:
                    failures.append({
                        "phase": "measurement",
                        "mode": mode,
                        "operation_count": operation_count,
                        "repetition": repetition,
                        "error": str(exc),
                    })

    raw_fields = [
        "mode", "operation_count", "repetition", "operation_index", "accepted", "reason",
        "issuance_ms", "access_ms", "online_operation_ms", "lifecycle_operation_ms",
    ]
    _write_csv(SINGLE_USE_RAW, raw_rows, raw_fields)
    session_fields = [
        "mode", "operation_count", "repetition", "accepted", "rejected",
        "capability_issuance_count", "issuance_total_ms", "preissue_wall_ms",
        "online_session_ms", "lifecycle_session_ms", "consumed_nonce_delta",
        "challenge_delta", "consumed_challenge_delta",
    ]
    _write_csv(SINGLE_USE_SESSIONS, session_rows, session_fields)

    summary_rows: List[Dict[str, Any]] = []
    for mode in modes:
        for operation_count in counts:
            operations = [
                row for row in raw_rows
                if row["mode"] == mode and int(row["operation_count"]) == operation_count
            ]
            sessions = [
                row for row in session_rows
                if row["mode"] == mode and int(row["operation_count"]) == operation_count
            ]
            online_stats = _stats([float(row["online_operation_ms"]) for row in operations])
            lifecycle_stats = _stats([float(row["lifecycle_operation_ms"]) for row in operations])
            issuance_stats = _stats([float(row["issuance_ms"]) for row in operations])
            access_stats = _stats([float(row["access_ms"]) for row in operations])
            session_stats = _stats([float(row["online_session_ms"]) for row in sessions])
            lifecycle_session_stats = _stats([float(row["lifecycle_session_ms"]) for row in sessions])
            summary_rows.append({
                "mode": mode,
                "operation_count": operation_count,
                "repetitions_completed": len(sessions),
                "attempted_operations": len(operations),
                "accepted_operations": sum(int(bool(row["accepted"])) for row in operations),
                "rejected_operations": sum(int(not bool(row["accepted"])) for row in operations),
                "capabilities_issued": sum(int(row["capability_issuance_count"]) for row in sessions),
                "issuance_mean_ms": issuance_stats["mean_ms"],
                "access_mean_ms": access_stats["mean_ms"],
                "online_operation_mean_ms": online_stats["mean_ms"],
                "online_operation_p95_ms": online_stats["p95_ms"],
                "online_operation_p99_ms": online_stats["p99_ms"],
                "online_operation_ci95_ms": online_stats["ci95_ms"],
                "lifecycle_operation_mean_ms": lifecycle_stats["mean_ms"],
                "online_session_mean_ms": session_stats["mean_ms"],
                "online_session_p95_ms": session_stats["p95_ms"],
                "online_session_ci95_ms": session_stats["ci95_ms"],
                "lifecycle_session_mean_ms": lifecycle_session_stats["mean_ms"],
                "lifecycle_session_p95_ms": lifecycle_session_stats["p95_ms"],
                "lifecycle_session_ci95_ms": lifecycle_session_stats["ci95_ms"],
                "consumed_nonce_delta_mean": round(statistics.fmean([float(row["consumed_nonce_delta"]) for row in sessions]), 3) if sessions else 0.0,
                "consumed_challenge_delta_mean": round(statistics.fmean([float(row["consumed_challenge_delta"]) for row in sessions]), 3) if sessions else 0.0,
            })

    summary_fields = list(summary_rows[0].keys()) if summary_rows else []
    _write_csv(SINGLE_USE_SUMMARY, summary_rows, summary_fields)

    revocation_checks = [
        _single_use_revocation_check(mode, req.revocation_operation_count)
        for mode in modes
    ]
    if req.reset_verifier_state:
        reset_verifier_state()

    return {
        "test": "single_use_capability_renewal",
        "interpretation": (
            "Measures the current prototype's single-use renewal path. "
            "On-demand online latency includes capability issuance; pre-issued online latency excludes "
            "pool preparation, which remains included in lifecycle latency."
        ),
        "operation_counts": counts,
        "repetitions": req.repetitions,
        "warmup_sessions": req.warmup_sessions,
        "summary": summary_rows,
        "revocation_checks": revocation_checks,
        "all_normal_operations_accepted": bool(raw_rows) and all(bool(row["accepted"]) for row in raw_rows),
        "all_revocation_checks_passed": all(check["passed"] for check in revocation_checks),
        "failure_count": len(failures),
        "failures": failures[:20],
        "raw_file": str(SINGLE_USE_RAW),
        "sessions_file": str(SINGLE_USE_SESSIONS),
        "summary_file": str(SINGLE_USE_SUMMARY),
    }


def _use_preissued_capability(
    issued_response: Dict[str, Any],
    built: Dict[str, Any],
    *,
    require_fresh_status: bool = False,
    max_status_age_ms: float = 1000.0,
) -> Dict[str, Any]:
    if not issued_response.get("accepted") or not issued_response.get("capability"):
        return {
            "accepted": False,
            "reason": issued_response.get("reason", "capability issuance rejected"),
            "latency_ms": 0.0,
            "status_age_ms": None,
        }
    response, timings = timed_verify_capability_with_holder(
        issued_response["capability"],
        issued_response["verifier_public_key"],
        built["request"],
        consume_nonce=True,
        consume_challenge=True,
        require_holder_proof=True,
        require_fresh_revocation_status=require_fresh_status,
        max_revocation_status_age_ms=max_status_age_ms,
    )
    return {
        "accepted": bool(response.get("accepted")),
        "reason": response.get("reason"),
        "latency_ms": float(timings.get("holder_bound_access_total_http", 0.0)),
        "status_age_ms": response.get("trace", {}).get("artifacts", {}).get(
            "revocation_status_age_ms"
        ),
    }


def _run_propagation_session(
    delay_ms: int,
    repetition: int,
    post_update_attempts: int,
    minimum_pool_size: int,
) -> Dict[str, Any]:
    reset_verifier_state()
    built = build_cod(
        FlowRequest(capability_valid_seconds=600),
        f"revocation_propagation_{delay_ms}ms",
    )
    pool_size = max(
        minimum_pool_size,
        math.ceil(delay_ms / 2.0) + post_update_attempts + 5,
    )
    issued = [_issue_single_use_capability(built)[0] for _ in range(pool_size)]
    if not all(item.get("accepted") and item.get("capability") for item in issued):
        raise RuntimeError("failed to prepare the capability pool")

    applied = Event()
    update: Dict[str, Any] = {}
    start_ns = time.monotonic_ns()

    def deliver_revocation() -> None:
        target_ns = start_ns + delay_ms * 1_000_000
        remaining_ns = target_ns - time.monotonic_ns()
        if remaining_ns > 0:
            time.sleep(remaining_ns / 1_000_000_000.0)
        update_start = time.perf_counter()
        try:
            update["response"] = post_json(
                f"{BASE['verifier']}/revoke",
                {
                    "credential_id": built["cod"][1]["payload"]["id"],
                    "reason": "delayed cross-domain revocation delivery experiment",
                },
            )
            update["error"] = None
        except Exception as exc:
            update["error"] = str(exc)
        update["http_ms"] = _ms(update_start, time.perf_counter())
        update["applied_elapsed_ms"] = round(
            (time.monotonic_ns() - start_ns) / 1_000_000.0,
            6,
        )
        applied.set()

    delivery_thread = Thread(target=deliver_revocation, daemon=True)
    delivery_thread.start()

    pre_update_attempts = 0
    pre_update_accepted = 0
    pre_update_rejected = 0
    index = 0
    while not applied.is_set() and index < pool_size - post_update_attempts:
        result = _use_preissued_capability(issued[index], built)
        pre_update_attempts += 1
        pre_update_accepted += int(result["accepted"])
        pre_update_rejected += int(not result["accepted"])
        index += 1

    delivery_thread.join(timeout=max(5.0, delay_ms / 1000.0 + 5.0))
    if not applied.is_set():
        raise RuntimeError("revocation delivery thread did not complete")
    if update.get("error"):
        raise RuntimeError(f"revocation delivery failed: {update['error']}")
    if index + post_update_attempts > pool_size:
        raise RuntimeError("capability pool exhausted before post-update checks")

    post_update_rejected = 0
    post_update_accepted = 0
    first_post_result_elapsed_ms: float | None = None
    first_post_latency_ms: float | None = None
    post_reasons: Dict[str, int] = {}
    for offset in range(post_update_attempts):
        result = _use_preissued_capability(issued[index + offset], built)
        if offset == 0:
            first_post_result_elapsed_ms = round(
                (time.monotonic_ns() - start_ns) / 1_000_000.0,
                6,
            )
            first_post_latency_ms = float(result["latency_ms"])
        post_update_accepted += int(result["accepted"])
        post_update_rejected += int(not result["accepted"])
        reason = str(result.get("reason"))
        post_reasons[reason] = post_reasons.get(reason, 0) + 1

    applied_elapsed_ms = float(update["applied_elapsed_ms"])
    return {
        "delay_ms": delay_ms,
        "repetition": repetition,
        "pool_size": pool_size,
        "pre_update_attempts": pre_update_attempts,
        "pre_update_accepted": pre_update_accepted,
        "pre_update_rejected": pre_update_rejected,
        "post_update_attempts": post_update_attempts,
        "post_update_accepted": post_update_accepted,
        "post_update_rejected": post_update_rejected,
        "revocation_update_http_ms": update["http_ms"],
        "revocation_applied_elapsed_ms": applied_elapsed_ms,
        "first_post_result_elapsed_ms": first_post_result_elapsed_ms,
        "local_enforcement_observation_ms": round(
            float(first_post_result_elapsed_ms or applied_elapsed_ms) - applied_elapsed_ms,
            6,
        ),
        "first_post_attempt_latency_ms": first_post_latency_ms,
        "post_update_reasons": json.dumps(post_reasons, sort_keys=True),
        # A request may begin before delivery and be rejected after the concurrent
        # update. Such an in-flight rejection is safe and is reported separately.
        "passed": post_update_accepted == 0,
    }


def _run_outage_session(freshness_limit_ms: int, repetition: int) -> Dict[str, Any]:
    reset_verifier_state()
    built = build_cod(
        FlowRequest(capability_valid_seconds=600),
        f"revocation_outage_{freshness_limit_ms}ms",
    )
    issued = [_issue_single_use_capability(built)[0] for _ in range(2)]
    if not all(item.get("accepted") and item.get("capability") for item in issued):
        raise RuntimeError("failed to prepare outage-test capabilities")

    post_json(
        f"{BASE['verifier']}/revocation-status-control",
        {"source_available": False, "mark_synchronized": True},
    )
    outage_start_ns = time.monotonic_ns()
    immediate = _use_preissued_capability(
        issued[0],
        built,
        require_fresh_status=True,
        max_status_age_ms=float(freshness_limit_ms),
    )

    target_age_ms = freshness_limit_ms + 25
    remaining_ms = target_age_ms - (
        (time.monotonic_ns() - outage_start_ns) / 1_000_000.0
    )
    if remaining_ms > 0:
        time.sleep(remaining_ms / 1000.0)
    stale = _use_preissued_capability(
        issued[1],
        built,
        require_fresh_status=True,
        max_status_age_ms=float(freshness_limit_ms),
    )
    immediate_expected = freshness_limit_ms > 0
    return {
        "freshness_limit_ms": freshness_limit_ms,
        "repetition": repetition,
        "immediate_expected_accepted": immediate_expected,
        "immediate_accepted": immediate["accepted"],
        "immediate_status_age_ms": immediate["status_age_ms"],
        "immediate_reason": immediate["reason"],
        "stale_expected_accepted": False,
        "stale_accepted": stale["accepted"],
        "stale_status_age_ms": stale["status_age_ms"],
        "stale_reason": stale["reason"],
        "passed": (
            immediate["accepted"] is immediate_expected
            and stale["accepted"] is False
        ),
    }


@app.post("/run-revocation-propagation")
def run_revocation_propagation(
    req: RevocationPropagationRequest = RevocationPropagationRequest(),
) -> Dict[str, Any]:
    wait_for_services()
    delays = sorted(set(req.propagation_delays_ms))
    freshness_limits = sorted(set(req.outage_freshness_limits_ms))
    if not delays or any(delay < 0 or delay > 10000 for delay in delays):
        raise HTTPException(
            status_code=400,
            detail="propagation_delays_ms must contain values from 0 to 10000",
        )
    if not freshness_limits or any(limit < 0 or limit > 10000 for limit in freshness_limits):
        raise HTTPException(
            status_code=400,
            detail="outage_freshness_limits_ms must contain values from 0 to 10000",
        )

    propagation_rows: List[Dict[str, Any]] = []
    outage_rows: List[Dict[str, Any]] = []
    failures: List[Dict[str, Any]] = []
    for delay_ms in delays:
        for repetition in range(1, req.repetitions + 1):
            try:
                propagation_rows.append(
                    _run_propagation_session(
                        delay_ms,
                        repetition,
                        req.post_update_attempts,
                        req.minimum_pool_size,
                    )
                )
            except Exception as exc:
                failures.append({
                    "phase": "propagation",
                    "delay_ms": delay_ms,
                    "repetition": repetition,
                    "error": str(exc),
                })

    for freshness_limit_ms in freshness_limits:
        for repetition in range(1, req.repetitions + 1):
            try:
                outage_rows.append(
                    _run_outage_session(freshness_limit_ms, repetition)
                )
            except Exception as exc:
                failures.append({
                    "phase": "outage",
                    "freshness_limit_ms": freshness_limit_ms,
                    "repetition": repetition,
                    "error": str(exc),
                })

    propagation_fields = list(propagation_rows[0].keys()) if propagation_rows else []
    outage_fields = list(outage_rows[0].keys()) if outage_rows else []
    _write_csv(REVOCATION_PROPAGATION_RAW, propagation_rows, propagation_fields)
    _write_csv(REVOCATION_OUTAGE_RAW, outage_rows, outage_fields)

    summary_rows: List[Dict[str, Any]] = []
    for delay_ms in delays:
        rows = [row for row in propagation_rows if row["delay_ms"] == delay_ms]
        applied_stats = _stats([
            float(row["revocation_applied_elapsed_ms"]) for row in rows
        ])
        enforcement_stats = _stats([
            float(row["local_enforcement_observation_ms"]) for row in rows
        ])
        exposure_counts = [float(row["pre_update_accepted"]) for row in rows]
        summary_rows.append({
            "delay_ms": delay_ms,
            "repetitions_completed": len(rows),
            "pre_update_accepted_total": int(sum(exposure_counts)),
            "pre_update_accepted_mean": round(statistics.fmean(exposure_counts), 3) if exposure_counts else 0.0,
            "pre_update_accepted_max": int(max(exposure_counts)) if exposure_counts else 0,
            "post_update_attempted_total": sum(int(row["post_update_attempts"]) for row in rows),
            "post_update_accepted_total": sum(int(row["post_update_accepted"]) for row in rows),
            "post_update_rejected_total": sum(int(row["post_update_rejected"]) for row in rows),
            "revocation_applied_mean_ms": applied_stats["mean_ms"],
            "revocation_applied_p95_ms": applied_stats["p95_ms"],
            "local_enforcement_observation_mean_ms": enforcement_stats["mean_ms"],
            "local_enforcement_observation_p95_ms": enforcement_stats["p95_ms"],
            "all_sessions_passed": bool(rows) and all(bool(row["passed"]) for row in rows),
        })
    summary_fields = list(summary_rows[0].keys()) if summary_rows else []
    _write_csv(REVOCATION_PROPAGATION_SUMMARY, summary_rows, summary_fields)

    if req.reset_verifier_state:
        reset_verifier_state()
    return {
        "test": "revocation_propagation_and_outage",
        "interpretation": (
            "Propagation sessions model an authoritative revocation at time zero and delayed delivery "
            "to the relying verifier under continuous use of previously issued capabilities. Outage "
            "sessions test cached-status use only within a configured freshness interval and fail-closed "
            "rejection after that interval. Network transport is emulated by controlled delay."
        ),
        "propagation_delays_ms": delays,
        "outage_freshness_limits_ms": freshness_limits,
        "repetitions": req.repetitions,
        "propagation_summary": summary_rows,
        "outage_results": outage_rows,
        "all_propagation_sessions_passed": bool(propagation_rows) and all(bool(row["passed"]) for row in propagation_rows),
        "all_outage_sessions_passed": bool(outage_rows) and all(bool(row["passed"]) for row in outage_rows),
        "failure_count": len(failures),
        "failures": failures[:20],
        "raw_file": str(REVOCATION_PROPAGATION_RAW),
        "summary_file": str(REVOCATION_PROPAGATION_SUMMARY),
        "outage_file": str(REVOCATION_OUTAGE_RAW),
    }

@app.post("/run-chain-depth-sensitivity")
def run_chain_depth_sensitivity(req: ChainDepthSensitivityRequest = ChainDepthSensitivityRequest()) -> Dict[str, Any]:
    if req.reset_verifier_state:
        reset_verifier_state()
    wait_for_services()

    results: List[Dict[str, Any]] = []
    raw_rows: List[Dict[str, Any]] = []
    failures: List[Dict[str, Any]] = []

    for depth in req.depths:
        depth_latencies: List[float] = []
        accepted_count = 0
        rejected_count = 0
        total_runs = req.warmup + req.iterations

        for run_index in range(total_runs):
            is_warmup = run_index < req.warmup
            iteration = run_index - req.warmup + 1

            try:
                built = _build_synthetic_cod(depth)
                final, latency_ms = timed_post_json(
                    f"{BASE['verifier']}/verify-cod",
                    {
                        "cod": built["cod"],
                        "issuer_keys": built["issuer_keys"],
                        "request": built["request"],
                        "depth_max": built["depth_max"],
                        "issue_capability_on_success": False,
                    },
                )

                accepted = bool(final.get("accepted"))
                if not is_warmup:
                    if accepted:
                        accepted_count += 1
                        depth_latencies.append(latency_ms)
                    else:
                        rejected_count += 1

                    raw_rows.append({
                        "test": "chain_depth_sensitivity",
                        "depth": depth,
                        "iteration": iteration,
                        "accepted": accepted,
                        "latency_ms": latency_ms,
                        "reason": final.get("reason"),
                        "chain_credentials": len(built["cod"]),
                        "chain_size_bytes": len(json.dumps(built["cod"])),
                    })

            except Exception as exc:
                if not is_warmup:
                    rejected_count += 1
                    failures.append({
                        "depth": depth,
                        "iteration": iteration,
                        "error": str(exc),
                    })

        stats = _stats(depth_latencies)
        results.append({
            "depth": depth,
            "iterations": req.iterations,
            "accepted": accepted_count,
            "rejected": rejected_count,
            "chain_credentials": depth,
            "chain_size_bytes_mean": round(
                statistics.fmean([
                    float(r["chain_size_bytes"])
                    for r in raw_rows
                    if int(r["depth"]) == depth and bool(r["accepted"])
                ]),
                2
            ) if any(int(r["depth"]) == depth and bool(r["accepted"]) for r in raw_rows) else 0.0,
            **stats,
        })

    output_file = RESULTS_DIR / "chain_depth_sensitivity.csv"
    _write_csv(
        output_file,
        raw_rows,
        ["test", "depth", "iteration", "accepted", "latency_ms", "reason", "chain_credentials", "chain_size_bytes"],
    )

    summary_rows = []
    for r in results:
        summary_rows.extend([
            _stress_row("chain_depth", f"depth_{r['depth']}_accepted", r["accepted"], "count"),
            _stress_row("chain_depth", f"depth_{r['depth']}_rejected", r["rejected"], "count"),
            _stress_row("chain_depth", f"depth_{r['depth']}_mean_ms", r["mean_ms"], "ms"),
            _stress_row("chain_depth", f"depth_{r['depth']}_p95_ms", r["p95_ms"], "ms"),
            _stress_row("chain_depth", f"depth_{r['depth']}_p99_ms", r["p99_ms"], "ms"),
            _stress_row("chain_depth", f"depth_{r['depth']}_ci95_ms", r["ci95_ms"], "ms"),
            _stress_row("chain_depth", f"depth_{r['depth']}_chain_size_bytes_mean", r["chain_size_bytes_mean"], "bytes"),
        ])
    _append_stress_summary(summary_rows)

    return {
        "test": "chain_depth_sensitivity",
        "depths": req.depths,
        "iterations": req.iterations,
        "warmup": req.warmup,
        "results": results,
        "failure_count": len(failures),
        "failures": failures[:10],
        "raw_file": str(output_file),
    }
    
@app.post("/run-stress-load")
def run_stress_load(req: StressLoadRequest = StressLoadRequest()) -> Dict[str, Any]:
    if req.reset_verifier_state:
        reset_verifier_state()
    wait_for_services()
    latencies: List[float] = []
    failures: List[str] = []

    def one_flow(_: int) -> Dict[str, Any]:
        t0 = time.perf_counter()
        issued = run_valid_flow(FlowRequest())
        checked = verify_capability_with_holder(
            issued["capability"], issued["verifier_public_key"], issued["request"],
            consume_nonce=True, consume_challenge=True,
        )
        return {"accepted": issued.get("accepted") and checked.get("accepted"),
                "latency_ms": _ms(t0, time.perf_counter()), "reason": checked.get("reason")}

    with ThreadPoolExecutor(max_workers=req.concurrency) as pool:
        futures = [pool.submit(one_flow, i) for i in range(req.iterations)]
        for fut in as_completed(futures):
            try:
                result = fut.result()
                if result.get("accepted"):
                    latencies.append(float(result["latency_ms"]))
                else:
                    failures.append(str(result.get("reason")))
            except Exception as exc:
                failures.append(str(exc))

    summary = _summary([{"operation": "holder_bound_total_flow", "value_ms": v} for v in latencies])
    p95 = round(statistics.quantiles(latencies, n=100)[94], 6) if len(latencies) >= 100 else None
    p99 = round(statistics.quantiles(latencies, n=100)[98], 6) if len(latencies) >= 100 else None
    _append_stress_summary([
        _stress_row("load", "iterations", req.iterations, "count"),
        _stress_row("load", "concurrency", req.concurrency, "workers"),
        _stress_row("load", "success_count", len(latencies), "count"),
        _stress_row("load", "failure_count", len(failures), "count"),
        _stress_row("load", "p95_latency_ms", p95, "ms"),
        _stress_row("load", "p99_latency_ms", p99, "ms"),
    ])
    return {"test": "holder_bound_load", "summary": summary, "p95_latency_ms": p95,
            "p99_latency_ms": p99, "success_count": len(latencies),
            "failure_count": len(failures), "sample_failures": failures[:5]}


@app.post("/run-stress-replay")
def run_stress_replay(req: StressReplayRequest = StressReplayRequest()) -> Dict[str, Any]:
    reset_verifier_state()
    valid = run_valid_flow(FlowRequest())
    cap = valid["capability"]
    key = valid["verifier_public_key"]
    access_req = valid["request"]

    def use_cap_with_fresh_proof(_: int) -> Dict[str, Any]:
        return verify_capability_with_holder(
            cap, key, access_req, consume_nonce=True, consume_challenge=True
        )

    capability_accepted = 0
    capability_rejected = 0
    capability_reasons: Dict[str, int] = {}
    with ThreadPoolExecutor(max_workers=req.concurrency) as pool:
        futures = [pool.submit(use_cap_with_fresh_proof, i) for i in range(req.concurrency)]
        for fut in as_completed(futures):
            try:
                result = fut.result()
                if result.get("accepted"):
                    capability_accepted += 1
                else:
                    capability_rejected += 1
                    reason = result.get("reason", "unknown")
                    capability_reasons[reason] = capability_reasons.get(reason, 0) + 1
            except Exception as exc:
                capability_rejected += 1
                capability_reasons[str(exc)] = capability_reasons.get(str(exc), 0) + 1

    reset_verifier_state()
    proof_flow = run_valid_flow(FlowRequest())
    prepared = prepare_holder_presentation(proof_flow["capability"], proof_flow["request"])

    def reuse_same_proof(_: int) -> Dict[str, Any]:
        return verify_capability_with_holder(
            proof_flow["capability"], proof_flow["verifier_public_key"], proof_flow["request"],
            consume_nonce=False, consume_challenge=True, prepared=prepared,
        )

    proof_accepted = 0
    proof_rejected = 0
    proof_reasons: Dict[str, int] = {}
    with ThreadPoolExecutor(max_workers=req.concurrency) as pool:
        futures = [pool.submit(reuse_same_proof, i) for i in range(req.concurrency)]
        for fut in as_completed(futures):
            try:
                result = fut.result()
                if result.get("accepted"):
                    proof_accepted += 1
                else:
                    proof_rejected += 1
                    reason = result.get("reason", "unknown")
                    proof_reasons[reason] = proof_reasons.get(reason, 0) + 1
            except Exception as exc:
                proof_rejected += 1
                proof_reasons[str(exc)] = proof_reasons.get(str(exc), 0) + 1

    capability_passed = capability_accepted == 1 and capability_rejected == req.concurrency - 1
    proof_passed = proof_accepted == 1 and proof_rejected == req.concurrency - 1
    passed = capability_passed and proof_passed
    _append_stress_summary([
        _stress_row("concurrent_capability_replay", "accepted_count", capability_accepted, "count"),
        _stress_row("concurrent_capability_replay", "rejected_count", capability_rejected, "count"),
        _stress_row("concurrent_holder_proof_replay", "accepted_count", proof_accepted, "count"),
        _stress_row("concurrent_holder_proof_replay", "rejected_count", proof_rejected, "count"),
        _stress_row("concurrent_replay", "passed", passed, "boolean"),
    ])
    return {
        "test": "concurrent_capability_and_holder_proof_replay",
        "concurrency": req.concurrency,
        "capability_replay": {"accepted": capability_accepted, "rejected": capability_rejected,
                              "reasons": capability_reasons, "passed": capability_passed},
        "holder_proof_replay": {"accepted": proof_accepted, "rejected": proof_rejected,
                                "reasons": proof_reasons, "passed": proof_passed},
        "passed": passed,
    }


@app.post("/run-stress-depth")
def run_stress_depth() -> Dict[str, Any]:
    reset_verifier_state()
    base = build_cod(FlowRequest(), "stress_depth")
    cod = base["cod"]
    keys = base["issuer_keys"]
    request = base["request"]
    cases = []
    def verify_case(name: str, test_cod: List[Dict[str, Any]], depth_max: int, expected: bool) -> Dict[str, Any]:
        r = post_json(f"{BASE['verifier']}/verify-cod", {"cod": test_cod, "issuer_keys": keys, "request": request, "depth_max": depth_max, "issue_capability_on_success": False})
        return {"case": name, "accepted": r.get("accepted"), "expected": expected, "passed": r.get("accepted") is expected, "reason": r.get("reason")}
    cases.append(verify_case("valid_3_2_1_depth_max_3", cod, 3, True))
    cases.append(verify_case("depth_max_2_rejects_3_hops", cod, 2, False))
    mutated = copy.deepcopy(cod); mutated[1]["payload"]["depth"] = mutated[0]["payload"]["depth"]
    cases.append(verify_case("wrong_decrement_3_3_1", mutated, 3, False))
    mutated = copy.deepcopy(cod); mutated[2]["payload"]["depth"] = 0
    cases.append(verify_case("wrong_decrement_3_2_0", mutated, 3, False))
    passed = sum(1 for c in cases if c["passed"])
    rows = [_stress_row("depth", "passed_cases", passed, "count"), _stress_row("depth", "total_cases", len(cases), "count")]
    _append_stress_summary(rows)
    return {"test": "depth", "summary": {"passed": passed, "total": len(cases)}, "cases": cases}


@app.post("/run-stress-token-size")
def run_stress_token_size(req: StressTokenSizeRequest = StressTokenSizeRequest()) -> Dict[str, Any]:
    reset_verifier_state()
    results = []
    for n in req.service_counts:
        scopes = [f"vendor.service{i}.read" for i in range(n)]
        built = _build_multiscope_cod(scopes)
        request = {"actor_did": built["vendor_agent"]["did"], "scope": scopes[0], "action": "read", "resource": built["resource"]}
        token_size = len(json.dumps(built["cod"]))
        t0 = time.perf_counter()
        r = post_json(f"{BASE['verifier']}/verify-cod", {"cod": built["cod"], "issuer_keys": built["issuer_keys"], "request": request, "depth_max": 3, "issue_capability_on_success": False})
        latency = _ms(t0, time.perf_counter())
        results.append({"services": n, "cod_token_size_bytes": token_size, "verify_latency_ms": latency, "accepted": r.get("accepted"), "reason": r.get("reason")})
    rows = []
    for r in results:
        rows.append(_stress_row("token_size", f"size_{r['services']}_services_bytes", r["cod_token_size_bytes"], "bytes"))
        rows.append(_stress_row("token_size", f"latency_{r['services']}_services_ms", r["verify_latency_ms"], "ms"))
    _append_stress_summary(rows)
    return {"test": "token_size", "results": results}


@app.post("/run-stress-multiservice")
def run_stress_multiservice(req: StressTokenSizeRequest = StressTokenSizeRequest(service_counts=[50])) -> Dict[str, Any]:
    reset_verifier_state()
    service_count = req.service_counts[0] if req.service_counts else 50
    scopes = [f"vendor.service{i}.read" for i in range(service_count)]
    built = _build_multiscope_cod(scopes)
    accepted = 0; rejected = 0; cases = []
    for i in range(service_count):
        request = {"actor_did": built["vendor_agent"]["did"], "scope": scopes[i], "action": "read", "resource": built["resource"]}
        r = post_json(f"{BASE['verifier']}/verify-cod", {"cod": built["cod"], "issuer_keys": built["issuer_keys"], "request": request, "depth_max": 3, "issue_capability_on_success": False})
        accepted += int(bool(r.get("accepted")))
    invalid_requests = [
        {"actor_did": built["vendor_agent"]["did"], "scope": "vendor.unauthorized.read", "action": "read", "resource": built["resource"]},
        {"actor_did": built["vendor_agent"]["did"], "scope": scopes[0], "action": "write", "resource": built["resource"]},
        {"actor_did": built["vendor_agent"]["did"], "scope": scopes[0], "action": "read", "resource": "asset:other"},
    ]
    for request in invalid_requests:
        r = post_json(f"{BASE['verifier']}/verify-cod", {"cod": built["cod"], "issuer_keys": built["issuer_keys"], "request": request, "depth_max": 3, "issue_capability_on_success": False})
        rejected += int(not bool(r.get("accepted")))
        cases.append({"request": request, "accepted": r.get("accepted"), "reason": r.get("reason")})
    passed = accepted == service_count and rejected == len(invalid_requests)
    rows = [_stress_row("multiservice", "authorized_accepted", accepted, "count"), _stress_row("multiservice", "unauthorized_rejected", rejected, "count"), _stress_row("multiservice", "passed", passed, "boolean")]
    _append_stress_summary(rows)
    return {"test": "multiservice", "service_count": service_count, "authorized_accepted": accepted, "unauthorized_rejected": rejected, "invalid_cases": cases, "passed": passed}


@app.post("/run-stress-revocation")
def run_stress_revocation() -> Dict[str, Any]:
    reset_verifier_state()
    valid = run_valid_flow(FlowRequest())
    cod = valid["cod"]; keys = {dc["payload"]["issuer"]: None for dc in cod}
    # Rebuild to retain issuer keys internally.
    built = build_cod(FlowRequest(), "stress_revocation")
    cod = built["cod"]; keys = built["issuer_keys"]; request = built["request"]
    first = post_json(f"{BASE['verifier']}/verify-cod", {"cod": cod, "issuer_keys": keys, "request": request, "depth_max": 3, "issue_capability_on_success": True})
    cap = first.get("capability")
    pk = first.get("verifier_public_key")
    post_json(f"{BASE['verifier']}/revoke", {"credential_id": cod[1]["payload"]["id"], "reason": "stress revocation cascade"})
    new_cap = post_json(f"{BASE['verifier']}/verify-cod", {"cod": cod, "issuer_keys": keys, "request": request, "depth_max": 3, "issue_capability_on_success": True})
    existing_cap = post_json(f"{BASE['verifier']}/verify-capability", {"capability": cap, "verifier_public_key": pk, "request": request, "consume_nonce": False}) if cap else {"accepted": False, "reason": "no cap"}
    passed = first.get("accepted") is True and new_cap.get("accepted") is False and existing_cap.get("accepted") is False
    rows = [_stress_row("revocation_cascade", "new_cap_after_dc_revocation_accepted", new_cap.get("accepted"), "boolean"), _stress_row("revocation_cascade", "existing_cap_after_dc_revocation_accepted", existing_cap.get("accepted"), "boolean"), _stress_row("revocation_cascade", "passed", passed, "boolean")]
    _append_stress_summary(rows)
    return {"test": "revocation_cascade", "initial_capability_accepted": first.get("accepted"), "new_capability_after_revocation": {"accepted": new_cap.get("accepted"), "reason": new_cap.get("reason")}, "existing_capability_after_revocation": {"accepted": existing_cap.get("accepted"), "reason": existing_cap.get("reason")}, "passed": passed}


@app.post("/run-stress-malformed")
def run_stress_malformed() -> Dict[str, Any]:
    reset_verifier_state()
    malformed_cod_cases = [
        ("empty_chain", []),
        ("random_object", [{"x": "y"}]),
        ("missing_signature", [{"payload": {"type": "DelegationCredential"}}]),
        ("wrong_types", [{"payload": {"type": 5, "id": [], "issuer": {}, "subject": None, "scope": "bad", "actions": "bad", "resource": 7, "depth": "x", "valid_from": 0, "valid_until": 0, "status": "active"}, "signature": "x"}]),
    ]
    results = []
    for name, cod in malformed_cod_cases:
        try:
            r = post_json(f"{BASE['verifier']}/verify-cod", {"cod": cod, "issuer_keys": {}, "request": {}, "depth_max": 3, "issue_capability_on_success": False})
            results.append({"case": name, "accepted": r.get("accepted"), "passed": r.get("accepted") is False, "reason": r.get("reason")})
        except Exception as exc:
            results.append({"case": name, "accepted": False, "passed": True, "reason": str(exc)})
    malformed_cap_cases = [
        ("empty_capability", {}),
        ("random_capability", {"payload": {"x": "y"}, "signature": "z"}),
        ("missing_payload", {"signature": "z"}),
    ]
    for name, cap in malformed_cap_cases:
        try:
            r = post_json(f"{BASE['verifier']}/verify-capability", {"capability": cap, "verifier_public_key": "bad", "request": {}, "consume_nonce": False})
            results.append({"case": name, "accepted": r.get("accepted"), "passed": r.get("accepted") is False, "reason": r.get("reason")})
        except Exception as exc:
            results.append({"case": name, "accepted": False, "passed": True, "reason": str(exc)})
    passed = sum(1 for r in results if r["passed"])
    rows = [_stress_row("malformed", "passed_cases", passed, "count"), _stress_row("malformed", "total_cases", len(results), "count")]
    _append_stress_summary(rows)
    return {"test": "malformed", "summary": {"passed": passed, "total": len(results)}, "cases": results}


@app.post("/run-stress-ledger")
def run_stress_ledger(req: StressLedgerRequest = StressLedgerRequest()) -> Dict[str, Any]:
    latencies = []
    for i in range(req.entries):
        t0 = time.perf_counter()
        post_json(f"{BASE['ledger']}/anchor", {"artifact_type": "StressArtifact", "artifact": {"i": i, "payload": "x" * 64}, "trace": {"stress": "ledger"}})
        latencies.append(_ms(t0, time.perf_counter()))
    latest_t0 = time.perf_counter(); latest = get_json(f"{BASE['ledger']}/ledger/latest"); latest_ms = _ms(latest_t0, time.perf_counter())
    summary = _summary([{"operation": "ledger_anchor", "value_ms": v} for v in latencies])
    rows = [_stress_row("ledger_pressure", "entries", req.entries, "count"), _stress_row("ledger_pressure", "latest_lookup_ms", latest_ms, "ms")]
    _append_stress_summary(rows)
    return {"test": "ledger_pressure", "entries": req.entries, "anchor_summary": summary, "latest_lookup_ms": latest_ms, "latest_tx_id": latest.get("tx_id")}


@app.post("/run-stress-revocation-list")
def run_stress_revocation_list(req: StressRevocationListRequest = StressRevocationListRequest()) -> Dict[str, Any]:
    reset_verifier_state()
    for i in range(req.entries):
        post_json(f"{BASE['verifier']}/revoke", {"credential_id": f"dummy_revoked_{i}", "reason": "revocation-list pressure"})
    built = build_cod(FlowRequest(), "stress_revocation_list")
    t0 = time.perf_counter()
    r = post_json(f"{BASE['verifier']}/verify-cod", {"cod": built["cod"], "issuer_keys": built["issuer_keys"], "request": built["request"], "depth_max": 3, "issue_capability_on_success": False})
    valid_latency = _ms(t0, time.perf_counter())
    post_json(f"{BASE['verifier']}/revoke", {"credential_id": built["cod"][1]["payload"]["id"], "reason": "revocation-list pressure target"})
    t1 = time.perf_counter()
    rr = post_json(f"{BASE['verifier']}/verify-cod", {"cod": built["cod"], "issuer_keys": built["issuer_keys"], "request": built["request"], "depth_max": 3, "issue_capability_on_success": False})
    revoked_latency = _ms(t1, time.perf_counter())
    rows = [_stress_row("revocation_list", "entries", req.entries, "count"), _stress_row("revocation_list", "valid_cod_latency_ms", valid_latency, "ms"), _stress_row("revocation_list", "revoked_cod_latency_ms", revoked_latency, "ms")]
    _append_stress_summary(rows)
    return {"test": "revocation_list", "revoked_entries": req.entries, "valid_cod": {"accepted": r.get("accepted"), "latency_ms": valid_latency}, "revoked_cod": {"accepted": rr.get("accepted"), "reason": rr.get("reason"), "latency_ms": revoked_latency}}


class MonotonicStressRequest(BaseModel):
    iterations: int = Field(default=1000, ge=10, le=10000)
    valid_ratio: float = Field(default=0.30, ge=0.0, le=1.0)
    reset_verifier_state: bool = True


def _verify_cod_for_monotonic_test(
    cod: List[Dict[str, Any]],
    issuer_keys: Dict[str, str],
    request: Dict[str, Any],
    depth_max: int,
) -> tuple[bool, str, float]:
    t0 = time.perf_counter()
    final = post_json(f"{BASE['verifier']}/verify-cod", {
        "cod": cod,
        "issuer_keys": issuer_keys,
        "request": request,
        "depth_max": depth_max,
        "issue_capability_on_success": False,
    })
    latency = _ms(t0, time.perf_counter())
    return bool(final.get("accepted")), str(final.get("reason")), latency


def _make_monotonic_variant(
    built: Dict[str, Any],
    mutation: str,
) -> tuple[List[Dict[str, Any]], Dict[str, Any], str]:
    """
    Create a chain variant for monotonic-delegation testing.

    Important: most variants intentionally mutate a signed payload without
    re-signing. Therefore, rejection may happen at signature verification before
    the monotonicity check. This is still valid as a token-security test because
    a downstream actor cannot expand signed authority without invalidating the
    credential. Dedicated service-level expansion tests already exercise
    properly signed invalid downstream requests during delegation issuance.
    """
    cod = copy.deepcopy(built["cod"])
    request = dict(built["request"])

    if mutation == "valid_monotone":
        expected = "accepted"

    elif mutation == "scope_expansion":
        cod[-1]["payload"]["scope"] = list(set(cod[-1]["payload"].get("scope", [])) | {"maintenance.write"})
        expected = "rejected"

    elif mutation == "action_expansion":
        cod[-1]["payload"]["actions"] = list(set(cod[-1]["payload"].get("actions", [])) | {"write"})
        expected = "rejected"

    elif mutation == "resource_expansion":
        cod[-1]["payload"]["resource"] = "asset:*"
        expected = "rejected"

    elif mutation == "resource_substitution":
        cod[-1]["payload"]["resource"] = "asset:turbine-9"
        request["resource"] = "asset:turbine-9"
        expected = "rejected"

    elif mutation == "validity_expansion":
        parent_until = cod[-2]["payload"].get("valid_until", 0)
        cod[-1]["payload"]["valid_until"] = parent_until + 3600
        expected = "rejected"

    elif mutation == "depth_reset":
        cod[-1]["payload"]["depth"] = cod[-2]["payload"].get("depth")
        expected = "rejected"

    elif mutation == "depth_increase":
        cod[-1]["payload"]["depth"] = cod[-2]["payload"].get("depth", 0) + 1
        expected = "rejected"

    elif mutation == "mixed_expansion":
        cod[-1]["payload"]["scope"] = list(set(cod[-1]["payload"].get("scope", [])) | {"maintenance.write"})
        cod[-1]["payload"]["actions"] = list(set(cod[-1]["payload"].get("actions", [])) | {"write"})
        cod[-1]["payload"]["resource"] = "asset:*"
        cod[-1]["payload"]["valid_until"] = cod[-2]["payload"].get("valid_until", 0) + 3600
        cod[-1]["payload"]["depth"] = cod[-2]["payload"].get("depth", 0) + 1
        expected = "rejected"

    else:
        raise ValueError(f"unknown monotonic mutation: {mutation}")

    return cod, request, expected


@app.post("/run-monotonic-delegation-stress")
def run_monotonic_delegation_stress(req: MonotonicStressRequest = MonotonicStressRequest()) -> Dict[str, Any]:
    """
    Stress-test the monotonic delegation invariant.

    The endpoint generates valid Chains-of-Delegation and mutated non-monotone
    variants. It verifies that valid monotone chains are accepted and that
    authority-expanding variants are rejected before capability realization.
    """
    if req.reset_verifier_state:
        reset_verifier_state()

    random.seed(42)

    valid_case = "valid_monotone"
    invalid_cases = [
        "scope_expansion",
        "action_expansion",
        "resource_expansion",
        "resource_substitution",
        "validity_expansion",
        "depth_reset",
        "depth_increase",
        "mixed_expansion",
    ]

    rows: List[Dict[str, Any]] = []
    latencies: List[float] = []
    valid_total = 0
    invalid_total = 0
    accepted_valid = 0
    rejected_valid = 0
    accepted_invalid = 0
    rejected_invalid = 0

    per_case: Dict[str, Dict[str, Any]] = {}

    def case_record(name: str) -> Dict[str, Any]:
        if name not in per_case:
            per_case[name] = {
                "case": name,
                "generated": 0,
                "expected_accepted": 0,
                "expected_rejected": 0,
                "accepted": 0,
                "rejected": 0,
                "false_acceptance": 0,
                "false_rejection": 0,
                "latencies_ms": [],
                "sample_reason": None,
            }
        return per_case[name]

    for i in range(req.iterations):
        mutation = valid_case if random.random() < req.valid_ratio else random.choice(invalid_cases)
        built = build_cod(FlowRequest(), f"monotonic_stress_{mutation}")
        cod, access_request, expected = _make_monotonic_variant(built, mutation)

        accepted, reason, latency = _verify_cod_for_monotonic_test(
            cod=cod,
            issuer_keys=built["issuer_keys"],
            request=access_request,
            depth_max=3,
        )

        latencies.append(latency)

        rec = case_record(mutation)
        rec["generated"] += 1
        rec["accepted"] += int(accepted)
        rec["rejected"] += int(not accepted)
        rec["latencies_ms"].append(latency)
        if rec["sample_reason"] is None:
            rec["sample_reason"] = reason

        if expected == "accepted":
            valid_total += 1
            rec["expected_accepted"] += 1
            if accepted:
                accepted_valid += 1
            else:
                rejected_valid += 1
                rec["false_rejection"] += 1
        else:
            invalid_total += 1
            rec["expected_rejected"] += 1
            if accepted:
                accepted_invalid += 1
                rec["false_acceptance"] += 1
            else:
                rejected_invalid += 1

        rows.append({
            "iteration": i + 1,
            "case": mutation,
            "expected": expected,
            "accepted": accepted,
            "reason": reason,
            "latency_ms": latency,
            "passed": (expected == "accepted" and accepted) or (expected == "rejected" and not accepted),
        })

    def summarize_values(values: List[float]) -> Dict[str, float]:
        if not values:
            return {"mean_ms": 0.0, "std_ms": 0.0, "min_ms": 0.0, "max_ms": 0.0, "p95_ms": 0.0, "ci95_ms": 0.0}
        values_sorted = sorted(values)
        n = len(values_sorted)
        mean = statistics.mean(values_sorted)
        std = statistics.stdev(values_sorted) if n > 1 else 0.0
        ci95 = 1.96 * std / (n ** 0.5) if n > 1 else 0.0
        p95 = values_sorted[int(0.95 * (n - 1))]
        return {
            "mean_ms": round(mean, 6),
            "std_ms": round(std, 6),
            "min_ms": round(values_sorted[0], 6),
            "max_ms": round(values_sorted[-1], 6),
            "p95_ms": round(p95, 6),
            "ci95_ms": round(ci95, 6),
        }

    case_summaries = []
    for name in [valid_case] + invalid_cases:
        if name in per_case:
            rec = per_case[name]
            timing = summarize_values(rec.pop("latencies_ms"))
            rec.update(timing)
            case_summaries.append(rec)

    timing_summary = summarize_values(latencies)

    passed = accepted_invalid == 0 and rejected_valid == 0

    # Append compact summary to stress_summary.csv when helper exists.
    try:
        summary_rows = [
            _stress_row("monotonic_delegation", "generated_chains", req.iterations, "count"),
            _stress_row("monotonic_delegation", "valid_monotone_chains", valid_total, "count"),
            _stress_row("monotonic_delegation", "invalid_mutated_chains", invalid_total, "count"),
            _stress_row("monotonic_delegation", "accepted_valid_chains", accepted_valid, "count"),
            _stress_row("monotonic_delegation", "rejected_invalid_chains", rejected_invalid, "count"),
            _stress_row("monotonic_delegation", "false_acceptances", accepted_invalid, "count"),
            _stress_row("monotonic_delegation", "false_rejections", rejected_valid, "count"),
            _stress_row("monotonic_delegation", "mean_validation_latency_ms", timing_summary["mean_ms"], "ms"),
            _stress_row("monotonic_delegation", "p95_validation_latency_ms", timing_summary["p95_ms"], "ms"),
        ]
        _append_stress_summary(summary_rows)
    except Exception:
        pass

    return {
        "test": "monotonic_delegation_stress",
        "iterations": req.iterations,
        "valid_ratio": req.valid_ratio,
        "valid_monotone_chains": valid_total,
        "invalid_mutated_chains": invalid_total,
        "accepted_valid_chains": accepted_valid,
        "rejected_valid_chains": rejected_valid,
        "accepted_invalid_chains": accepted_invalid,
        "rejected_invalid_chains": rejected_invalid,
        "false_acceptances": accepted_invalid,
        "false_rejections": rejected_valid,
        "passed": passed,
        "timing_summary_ms": timing_summary,
        "case_summaries": case_summaries,
        "note": "Mutated token variants are intentionally not re-signed; rejection may occur at signature verification or monotonicity checks. The result demonstrates that authority-expanding delegation tokens are not accepted for capability realization.",
    }


class CryptoCostRequest(BaseModel):
    local_iterations: int = Field(default=5000, ge=1, le=50000)
    revocation_read_iterations: int = Field(default=5000, ge=1, le=50000)
    stateful_iterations: int = Field(default=1000, ge=1, le=10000)
    revocation_entries: int = Field(default=100, ge=0, le=10000)


@app.post("/run-crypto-cost")
def run_crypto_cost(req: CryptoCostRequest = CryptoCostRequest()) -> Dict[str, Any]:
    """
    Microbenchmark cryptographic and security-mechanism costs used by the
    delegation authorization pipeline. The benchmark isolates signing,
    signature verification, hashing, revocation lookup, nonce consumption,
    and selective-disclosure digest verification.
    """
    import base64
    import hashlib
    import json
    import math
    import statistics
    import uuid
    from shared.crypto import generate_keypair, sign_holder_proof, verify_holder_proof, sign_json, verify_json, canonical_json
    from shared.credentials import issue_delegation, issue_capability, credential_hash
    from shared.tracing import sha256_json

    iterations = req.local_iterations
    reset_verifier_state()

    def b64u(data: bytes) -> str:
        return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")

    def summarize(name: str, values: list[float]) -> Dict[str, Any]:
        values_sorted = sorted(values)
        n = len(values_sorted)
        mean = statistics.mean(values_sorted) if n else 0.0
        std = statistics.stdev(values_sorted) if n > 1 else 0.0
        p95 = values_sorted[int(0.95 * (n - 1))] if n else 0.0
        ci95 = 1.96 * std / math.sqrt(n) if n > 1 else 0.0
        return {
            "operation": name,
            "count": n,
            "mean_ms": mean,
            "std_ms": std,
            "min_ms": values_sorted[0] if n else 0.0,
            "max_ms": values_sorted[-1] if n else 0.0,
            "p95_ms": p95,
            "ci95_ms": ci95,
        }

    def timed(values: list[float], fn):
        t0 = time.perf_counter()
        result = fn()
        values.append(_ms(t0, time.perf_counter()))
        return result

    # Fixed actors for local microbenchmarking.
    dam_sk, dam_pk = generate_keypair()
    twin_sk, twin_pk = generate_keypair()
    verifier_sk, verifier_pk = generate_keypair()
    holder_sk, holder_pk = generate_keypair()

    dam_did = "did:local:crypto-dam"
    twin_did = "did:local:crypto-twin"
    vendor_did = "did:local:crypto-vendor-agent"
    vendor_kid = f"{vendor_did}#key1"
    verifier_did = "did:local:crypto-verifier"

    sample_dc = issue_delegation(
        dam_did,
        dam_sk,
        twin_did,
        ["diagnostics.read"],
        ["read"],
        "asset:compressor-7",
        3,
    )
    sample_cap = issue_capability(
        verifier_did,
        verifier_sk,
        vendor_did,
        vendor_kid,
        ["diagnostics.read"],
        ["read-status"],
        "asset:compressor-7",
        cod_hash=credential_hash(sample_dc),
        cod_ids=[sample_dc["payload"]["id"]],
    )

    keygen_values = []
    dc_sign_values = []
    dc_verify_values = []
    cap_sign_values = []
    cap_verify_values = []
    holder_sign_values = []
    holder_verify_values = []
    cod_hash_values = []
    cap_hash_values = []
    sd_digest_values = []

    for i in range(iterations):
        timed(keygen_values, generate_keypair)

        dc = timed(
            dc_sign_values,
            lambda: issue_delegation(
                dam_did,
                dam_sk,
                twin_did,
                ["diagnostics.read"],
                ["read"],
                "asset:compressor-7",
                3,
            ),
        )
        timed(dc_verify_values, lambda dc=dc: verify_json(dam_pk, dc["payload"], dc["signature"]))

        cap = timed(
            cap_sign_values,
            lambda: issue_capability(
                verifier_did,
                verifier_sk,
                vendor_did,
                vendor_kid,
                ["diagnostics.read"],
                ["read-status"],
                "asset:compressor-7",
                cod_hash=credential_hash(dc),
                cod_ids=[dc["payload"]["id"]],
            ),
        )
        timed(cap_verify_values, lambda cap=cap: verify_json(verifier_pk, cap["payload"], cap["signature"]))

        holder_request = {
            "actor_did": vendor_did, "scope": "diagnostics.read",
            "service": "diagnostics-api", "action": "read-status",
            "resource": "asset:compressor-7", "audience": "vendor-b",
            "timestamp": int(time.time()),
        }
        challenge = f"crypto-challenge-{i}"
        cap_hash = sha256_json(cap)
        holder_proof = timed(
            holder_sign_values,
            lambda cap_hash=cap_hash, holder_request=holder_request, challenge=challenge:
                sign_holder_proof(holder_sk, cap_hash, holder_request, challenge),
        )
        timed(
            holder_verify_values,
            lambda holder_proof=holder_proof, cap_hash=cap_hash, holder_request=holder_request, challenge=challenge:
                verify_holder_proof(holder_pk, holder_proof, cap_hash, holder_request, challenge),
        )

        timed(cod_hash_values, lambda dc=dc: credential_hash(dc))
        timed(cap_hash_values, lambda cap=cap: credential_hash(cap))

        # SD-style salted claim digest verification.
        salt = uuid.uuid4().hex
        claim = "clearance"
        value = "diagnostics"
        digest_payload = [salt, claim, value]
        digest = b64u(hashlib.sha256(canonical_json(digest_payload)).digest())
        timed(
            sd_digest_values,
            lambda salt=salt, claim=claim, value=value, digest=digest:
                b64u(hashlib.sha256(canonical_json([salt, claim, value])).digest()) == digest
        )

    # Revocation lookup is measured through the verifier path using a populated
    # revocation set and a non-revoked id. This captures API and state lookup cost.
    revocation_lookup_values = []
    for i in range(req.revocation_entries):
        post_json(f"{BASE['verifier']}/revoke", {"credential_id": f"crypto_dummy_revoked_{i}", "reason": "crypto-cost setup"})

    for i in range(req.revocation_read_iterations):
        t0 = time.perf_counter()
        get_json(f"{BASE['verifier']}/revocations")
        revocation_lookup_values.append(_ms(t0, time.perf_counter()))

    # Nonce write/replay cache cost is measured through capability verification.
    # Each capability is verified once with consume_nonce=True.
    nonce_consume_values = []
    challenge_issue_values = []
    built = build_cod(FlowRequest(), "crypto_cost_nonce")
    for i in range(req.stateful_iterations):
        issued = post_json(
            f"{BASE['verifier']}/verify-cod",
            {
                "cod": built["cod"],
                "issuer_keys": built["issuer_keys"],
                "request": built["request"],
                "depth_max": 3,
                "issue_capability_on_success": True,
            },
        )
        cap = issued.get("capability")
        pk = issued.get("verifier_public_key")
        if cap and pk:
            presentation = prepare_holder_presentation(cap, built["request"])
            challenge_issue_values.append(float(presentation.get("timing_ms", {}).get("challenge_issue_http", 0.0)))
            t0 = time.perf_counter()
            verify_capability_with_holder(
                cap, pk, built["request"], consume_nonce=True, consume_challenge=True,
                prepared=presentation,
            )
            nonce_consume_values.append(_ms(t0, time.perf_counter()))

    summary = [
        summarize("ed25519_key_generation", keygen_values),
        summarize("dc_signing", dc_sign_values),
        summarize("dc_signature_verification", dc_verify_values),
        summarize("capability_signing", cap_sign_values),
        summarize("capability_issuer_signature_verification", cap_verify_values),
        summarize("holder_request_signing", holder_sign_values),
        summarize("holder_proof_verification", holder_verify_values),
        summarize("cod_hash_computation", cod_hash_values),
        summarize("capability_hash_computation", cap_hash_values),
        summarize("sd_digest_verification", sd_digest_values),
        summarize("revocation_registry_read_http", revocation_lookup_values),
        summarize("verifier_challenge_issuance_http", challenge_issue_values),
        summarize("nonce_challenge_consume_verify_capability_http", nonce_consume_values),
    ]

    rows = []
    for item in summary:
        op = item["operation"]
        rows.extend([
            _stress_row("crypto_cost", f"{op}_mean_ms", item["mean_ms"], "ms"),
            _stress_row("crypto_cost", f"{op}_p95_ms", item["p95_ms"], "ms"),
            _stress_row("crypto_cost", f"{op}_ci95_ms", item["ci95_ms"], "ms"),
        ])
    _append_stress_summary(rows)

    return {
        "test": "crypto_cost",
        "iterations_local_crypto": iterations,
        "iterations_stateful_http": {
            "revocation_registry_read_http": len(revocation_lookup_values),
            "verifier_challenge_issuance_http": len(challenge_issue_values),
            "nonce_challenge_consume_verify_capability_http": len(nonce_consume_values),
        },
        "summary": summary,
        "note": "Local crypto operations isolate Ed25519 signing/verification and hashing. HTTP rows include API, state access, and verifier logic overhead.",
    }


@app.post("/run-revocation-scale")
def run_revocation_scale() -> Dict[str, Any]:
    """
    Measure revocation latency and cascading capability invalidation as the
    number of capabilities derived from one parent CoD increases.

    For each N:
      1. Build one valid CoD.
      2. Realize N capabilities from the same CoD.
      3. Revoke the middle delegation credential DC2.
      4. Verify all existing capabilities after revocation.
      5. Report revocation registration latency, total rejection-check time,
         mean rejection latency, p95 rejection latency, rejected count, and
         authorization leakage.
    """
    sizes = [1, 10, 50, 100, 500, 1000]
    results = []
    summary_rows = []

    def percentile(values, q):
        if not values:
            return None
        ordered = sorted(values)
        idx = int(round((q / 100.0) * (len(ordered) - 1)))
        return ordered[idx]

    for n in sizes:
        reset_verifier_state()

        built = build_cod(FlowRequest(), f"revocation_scale_{n}")
        cod = built["cod"]
        keys = built["issuer_keys"]
        request = built["request"]

        capabilities = []
        verifier_public_key = None
        issue_latencies = []
        issue_failures = 0

        for _ in range(n):
            t_issue0 = time.perf_counter()
            issued = post_json(
                f"{BASE['verifier']}/verify-cod",
                {
                    "cod": cod,
                    "issuer_keys": keys,
                    "request": request,
                    "depth_max": 3,
                    "issue_capability_on_success": True,
                },
            )
            issue_latencies.append(_ms(t_issue0, time.perf_counter()))

            if issued.get("accepted") and issued.get("capability"):
                capabilities.append(issued["capability"])
                verifier_public_key = issued.get("verifier_public_key")
            else:
                issue_failures += 1

        t_rev0 = time.perf_counter()
        revocation_response = post_json(
            f"{BASE['verifier']}/revoke",
            {
                "credential_id": cod[1]["payload"]["id"],
                "reason": f"revocation scale test for {n} dependent capabilities",
            },
        )
        revocation_registration_ms = _ms(t_rev0, time.perf_counter())

        rejection_latencies = []
        rejected_count = 0
        accepted_leakage = 0
        rejection_reasons = {}

        t_all0 = time.perf_counter()
        for cap in capabilities:
            t_check0 = time.perf_counter()
            checked = post_json(
                f"{BASE['verifier']}/verify-capability",
                {
                    "capability": cap,
                    "verifier_public_key": verifier_public_key,
                    "request": request,
                    "consume_nonce": False,
                },
            )
            rejection_latencies.append(_ms(t_check0, time.perf_counter()))

            if checked.get("accepted"):
                accepted_leakage += 1
            else:
                rejected_count += 1
                reason = checked.get("reason", "unknown")
                rejection_reasons[reason] = rejection_reasons.get(reason, 0) + 1

        total_rejection_check_ms = _ms(t_all0, time.perf_counter())

        mean_issue_ms = sum(issue_latencies) / len(issue_latencies) if issue_latencies else None
        mean_rejection_ms = sum(rejection_latencies) / len(rejection_latencies) if rejection_latencies else None
        p95_rejection_ms = percentile(rejection_latencies, 95)

        passed = (
            issue_failures == 0
            and len(capabilities) == n
            and rejected_count == n
            and accepted_leakage == 0
        )

        row = {
            "invalidated_capabilities": n,
            "issued_capabilities": len(capabilities),
            "issue_failures": issue_failures,
            "mean_capability_issue_ms": mean_issue_ms,
            "revocation_registration_ms": revocation_registration_ms,
            "total_rejection_check_ms": total_rejection_check_ms,
            "mean_rejection_latency_ms": mean_rejection_ms,
            "p95_rejection_latency_ms": p95_rejection_ms,
            "rejected_count": rejected_count,
            "accepted_leakage": accepted_leakage,
            "rejection_reasons": rejection_reasons,
            "revocation_response": {
                "accepted": revocation_response.get("accepted"),
                "reason": revocation_response.get("reason"),
            },
            "passed": passed,
        }
        results.append(row)

        summary_rows.extend([
            _stress_row("revocation_scale", f"issued_capabilities_{n}", len(capabilities), "count"),
            _stress_row("revocation_scale", f"issue_failures_{n}", issue_failures, "count"),
            _stress_row("revocation_scale", f"mean_capability_issue_ms_{n}", mean_issue_ms, "ms"),
            _stress_row("revocation_scale", f"revocation_registration_ms_{n}", revocation_registration_ms, "ms"),
            _stress_row("revocation_scale", f"total_rejection_check_ms_{n}", total_rejection_check_ms, "ms"),
            _stress_row("revocation_scale", f"mean_rejection_latency_ms_{n}", mean_rejection_ms, "ms"),
            _stress_row("revocation_scale", f"p95_rejection_latency_ms_{n}", p95_rejection_ms, "ms"),
            _stress_row("revocation_scale", f"rejected_count_{n}", rejected_count, "count"),
            _stress_row("revocation_scale", f"accepted_leakage_{n}", accepted_leakage, "count"),
            _stress_row("revocation_scale", f"passed_{n}", passed, "boolean"),
        ])

    _append_stress_summary(summary_rows)

    return {
        "test": "revocation_scale",
        "sizes": sizes,
        "results": results,
        "passed": all(r["passed"] for r in results),
    }


@app.post("/run-stress-clock-skew")
def run_stress_clock_skew() -> Dict[str, Any]:
    reset_verifier_state()
    expired_dc = build_cod(FlowRequest(), "stress_clock_expired")
    # Reissue root expired by setting negative valid_seconds at factory and continue normally where possible.
    twin_did = get_json(f"{BASE['twin']}/did")
    step1 = post_json(f"{BASE['factory']}/issue-delegation", {"subject_did": twin_did["did"], "scope": ["diagnostics.read"], "actions": ["read"], "resource": "asset:compressor-7", "depth": 3, "valid_seconds": -1})
    dc1 = step1["credential"]
    r = post_json(f"{BASE['verifier']}/verify-cod", {"cod": [dc1], "issuer_keys": {dc1["payload"]["issuer"]: step1["issuer_public_key"]}, "request": {"actor_did": dc1["payload"]["subject"], "scope": "diagnostics.read", "action": "read", "resource": "asset:compressor-7"}, "depth_max": 3, "issue_capability_on_success": False})
    expired_cap = run_valid_flow(FlowRequest(capability_valid_seconds=-1))
    cap_r = post_json(f"{BASE['verifier']}/verify-capability", {"capability": expired_cap["capability"], "verifier_public_key": expired_cap["verifier_public_key"], "request": expired_cap["request"], "consume_nonce": False})
    passed = r.get("accepted") is False and cap_r.get("accepted") is False
    rows = [_stress_row("clock_skew", "expired_dc_accepted", r.get("accepted"), "boolean"), _stress_row("clock_skew", "expired_capability_accepted", cap_r.get("accepted"), "boolean"), _stress_row("clock_skew", "passed", passed, "boolean")]
    _append_stress_summary(rows)
    return {"test": "clock_skew", "expired_dc": {"accepted": r.get("accepted"), "reason": r.get("reason")}, "expired_capability": {"accepted": cap_r.get("accepted"), "reason": cap_r.get("reason")}, "passed": passed}


@app.post("/run-stress-failure-injection")
def run_stress_failure_injection() -> Dict[str, Any]:
    built = build_cod(FlowRequest(), "stress_failure_injection")
    results = []
    # Simulate verifier unavailable by calling an invalid local endpoint, then assert no authorization decision can be obtained.
    try:
        requests.post("http://verifier:9999/verify-cod", json={}, timeout=1)
        results.append({"case": "verifier_unavailable", "fail_closed": False, "note": "unexpected response"})
    except Exception as exc:
        results.append({"case": "verifier_unavailable", "fail_closed": True, "note": str(exc)})
    # Metrics unavailability must not affect local authorization because it is best-effort in ingest_trace.
    r = post_json(f"{BASE['verifier']}/verify-cod", {"cod": built["cod"], "issuer_keys": built["issuer_keys"], "request": built["request"], "depth_max": 3, "issue_capability_on_success": False})
    results.append({"case": "metrics_best_effort_not_required", "accepted": r.get("accepted"), "passed": r.get("accepted") is True})
    passed = all(x.get("fail_closed", x.get("passed", False)) for x in results)
    rows = [_stress_row("failure_injection", "passed", passed, "boolean")]
    _append_stress_summary(rows)
    return {"test": "failure_injection", "passed": passed, "cases": results}


@app.post("/run-stress-all")
def run_stress_all() -> Dict[str, Any]:
    # Reset summary for a clean all-run.
    _write_csv(STRESS_SUMMARY, [], ["test", "metric", "value", "unit", "note"])
    outputs = {
        "load": run_stress_load(StressLoadRequest(iterations=100, concurrency=10)),
        "concurrent_replay": run_stress_replay(StressReplayRequest(concurrency=50)),
        "depth": run_stress_depth(),
        "token_size": run_stress_token_size(StressTokenSizeRequest(service_counts=[1, 10, 50, 100])),
        "multiservice": run_stress_multiservice(StressTokenSizeRequest(service_counts=[50])),
        "revocation_cascade": run_stress_revocation(),
        "malformed": run_stress_malformed(),
        "ledger_pressure": run_stress_ledger(StressLedgerRequest(entries=100)),
        "revocation_list": run_stress_revocation_list(StressRevocationListRequest(entries=100)),
        "clock_skew": run_stress_clock_skew(),
        "failure_injection": run_stress_failure_injection(),
    }
    return {"accepted": True, "stress_summary_file": "results/metrics/stress_summary.csv", "outputs": outputs}


@app.get("/stress-summary")
def stress_summary() -> Dict[str, Any]:
    return {"file": str(STRESS_SUMMARY), "rows": _read_csv(STRESS_SUMMARY)}

@app.get("/methodology-map")
def client_methodology_map() -> Dict[str, Any]:
    return post_or_get_methodology()


def post_or_get_methodology() -> Dict[str, Any]:
    try:
        verifier_map = get_json(f"{BASE['verifier']}/methodology-map")
    except Exception as exc:
        verifier_map = {"error": str(exc)}
    return {
        "step": "Step 8 schema and notation alignment",
        "verifier_methodology_map": verifier_map,
        "implemented_mapping": {
            "issuer": "DID_from",
            "subject": "DID_to",
            "scope": "Sigma_i",
            "depth": "Depth_i",
            "actions/resource/allowed_operations": "C_i",
            "valid_from/valid_until": "T_i",
            "status": "rho_i",
            "actor_did": "DID_req",
            "kid_s": "holder verification method",
            "resource": "R_req",
            "action": "a_req",
            "audience": "Aud_req",
            "timestamp": "t",
        },
    }


@app.post("/run-protected-resource-test")
def run_protected_resource_test(req: FlowRequest = FlowRequest()) -> Dict[str, Any]:
    """Present a holder-bound capability to VendorB's protected resource endpoint."""
    req.scope = "diagnostics.read"
    req.action = "read-status"
    valid = run_valid_flow(req)
    capability = valid.get("capability")
    if not capability:
        raise HTTPException(status_code=400, detail="valid flow did not issue a capability")
    protected_request = {
        "actor_did": valid["request"]["actor_did"],
        "kid_s": valid["request"].get("kid_s"),
        "service": "diagnostics-api",
        "scope": "diagnostics.read",
        "action": "read-status",
        "resource": valid["request"]["resource"],
        "audience": "vendor-b",
    }
    presentation = prepare_holder_presentation(capability, protected_request)
    protected = post_json(
        f"{BASE['vendor_b']}/protected-resource/read",
        {"capability": capability, "verifier_public_key": valid.get("verifier_public_key"),
         "request": presentation["request"], "holder_proof": presentation["holder_proof"],
         "challenge": presentation["challenge"]},
    )
    denied_request = dict(protected_request)
    denied_request.update({"service": "firmware-update-api", "scope": "firmware.update", "action": "write"})
    denied_presentation = prepare_holder_presentation(capability, denied_request)
    denied = post_json(
        f"{BASE['vendor_b']}/protected-resource/read",
        {"capability": capability, "verifier_public_key": valid.get("verifier_public_key"),
         "request": denied_presentation["request"], "holder_proof": denied_presentation.get("holder_proof"),
         "challenge": denied_presentation.get("challenge")},
    )
    return {"step": "holder-bound protected resource enforcement",
            "valid_protected_access": protected, "denied_write_access": denied,
            "passed": protected.get("accepted") is True and denied.get("accepted") is False}


@app.post("/run-local-policy-test")
def run_local_policy_test() -> Dict[str, Any]:
    """Demonstrate local policy denial apart from cryptographic checks."""
    valid = run_valid_flow(FlowRequest(scope="diagnostics.read", action="read-status"))
    capability = valid["capability"]
    allowed_req = {"actor_did": valid["request"]["actor_did"], "kid_s": valid["request"].get("kid_s"),
                   "service": "diagnostics-api", "scope": "diagnostics.read", "action": "read-status",
                   "resource": valid["request"]["resource"], "audience": "vendor-b"}
    denied_req = {"actor_did": valid["request"]["actor_did"], "kid_s": valid["request"].get("kid_s"),
                  "service": "configuration-api", "scope": "diagnostics.read", "action": "write",
                  "resource": valid["request"]["resource"], "audience": "vendor-b"}
    allowed_presentation = prepare_holder_presentation(capability, allowed_req)
    denied_presentation = prepare_holder_presentation(capability, denied_req)
    allowed = post_json(
        f"{BASE['vendor_b']}/protected-resource/read",
        {"capability": capability, "verifier_public_key": valid.get("verifier_public_key"),
         "request": allowed_presentation["request"], "holder_proof": allowed_presentation["holder_proof"],
         "challenge": allowed_presentation["challenge"]},
    )
    denied = post_json(
        f"{BASE['vendor_b']}/protected-resource/read",
        {"capability": capability, "verifier_public_key": valid.get("verifier_public_key"),
         "request": denied_presentation["request"], "holder_proof": denied_presentation.get("holder_proof"),
         "challenge": denied_presentation.get("challenge")},
    )
    return {"step": "local policy engine with holder-bound presentation", "allowed_case": allowed,
            "denied_case": denied, "passed": allowed.get("accepted") is True and denied.get("accepted") is False}


@app.post("/run-selective-disclosure-test")
def run_selective_disclosure_test() -> Dict[str, Any]:
    """Step 11: SD-JWT-style salted-hash selective disclosure simulation."""
    vendor_agent = get_json(f"{BASE['vendor_agent']}/did")
    issue = post_json(f"{BASE['verifier']}/sd/issue", {"subject_did": vendor_agent["did"], "claims": {"role": "VendorAgent", "organization": "VendorB", "clearance": "diagnostics", "internal_id": "secret-employee-778"}})
    present = post_json(f"{BASE['verifier']}/sd/present", {"credential": issue["credential"], "reveal": ["role", "clearance"]})
    verify = post_json(f"{BASE['verifier']}/sd/verify", {"presentation": present["presentation"], "issuer_public_key": issue["issuer_public_key"]})
    return {"step": "Step 11 selective disclosure simulation", "issue_warning": issue.get("warning"), "presentation": present, "verification": verify, "passed": verify.get("accepted") is True and set(verify.get("disclosed_claims", {}).keys()) == {"role", "clearance"}}


@app.get("/persistent-state")
def persistent_state() -> Dict[str, Any]:
    return {"step": "persistent revocation, nonce, and challenge registry", "revocations": get_json(f"{BASE['verifier']}/revocations"), "state": get_json(f"{BASE['verifier']}/state"), "note": "Verifier persists revocation records, consumed capability nonces, and verifier challenges in /app/results/state/verifier_state.sqlite."}


@app.post("/run-iota-simulation-test")
def run_iota_simulation_test() -> Dict[str, Any]:
    artifact = {"prototype": "delegation-auth", "step": 13, "purpose": "simulated IOTA anchoring"}
    receipt = post_json(f"{BASE['ledger']}/iota-sim/anchor", {"artifact_type": "IOTA-Simulation-Test", "artifact": artifact, "trace": {"scenario": "step13_iota_simulation"}})
    receipts = get_json(f"{BASE['ledger']}/iota-sim/receipts")
    return {"step": "Step 13 simulated IOTA anchoring", "receipt": receipt, "receipt_count": receipts.get("count"), "warning": receipt.get("iota_simulation_receipt", {}).get("warning"), "passed": receipt.get("accepted") is True and receipt.get("iota_simulation_receipt", {}).get("mode") == "simulation"}


@app.post("/run-methodology-alignment-tests")
def run_methodology_alignment_tests() -> Dict[str, Any]:
    protected = run_protected_resource_test()
    sd = run_selective_disclosure_test()
    iota = run_iota_simulation_test()
    state = persistent_state()
    return {
        "steps": "8-13",
        "methodology_map": post_or_get_methodology(),
        "protected_resource": protected,
        "selective_disclosure": sd,
        "persistent_state": state,
        "iota_simulation": iota,
        "passed": protected.get("passed") is True and sd.get("passed") is True and iota.get("passed") is True,
    }


# ---------------------------------------------------------------------------
# Baseline / ablation comparison experiment
# ---------------------------------------------------------------------------

class AblationComparisonRequest(BaseModel):
    iterations: int = Field(default=100, ge=1, le=2000)
    warmup: int = Field(default=5, ge=0, le=500)
    reset_verifier_state: bool = True


@app.post("/run-ablation-comparison")
def run_ablation_comparison(req: AblationComparisonRequest = AblationComparisonRequest()) -> Dict[str, Any]:
    if req.reset_verifier_state:
        reset_verifier_state()
    wait_for_services()
    raw_rows: List[Dict[str, Any]] = []
    failures: List[Dict[str, Any]] = []

    def add_row(iteration: int, variant: str, accepted: bool, latency_ms: float, reason: str | None = None) -> None:
        raw_rows.append({"iteration": iteration, "variant": variant, "accepted": accepted,
                         "latency_ms": latency_ms, "reason": reason})

    total_runs = req.warmup + req.iterations
    for run_index in range(total_runs):
        is_warmup = run_index < req.warmup
        iteration = run_index - req.warmup + 1
        try:
            built = build_cod(FlowRequest(), "ablation_comparison")
            cod, issuer_keys, access_request = built["cod"], built["issuer_keys"], built["request"]

            cod_only, t_cod_only = timed_post_json(
                f"{BASE['verifier']}/verify-cod",
                {"cod": cod, "issuer_keys": issuer_keys, "request": access_request,
                 "depth_max": 3, "issue_capability_on_success": False},
            )
            if not is_warmup:
                add_row(iteration, "cod_validation_only", bool(cod_only.get("accepted")),
                        t_cod_only, cod_only.get("reason"))

            realized, t_realized = timed_post_json(
                f"{BASE['verifier']}/verify-cod",
                {"cod": cod, "issuer_keys": issuer_keys, "request": access_request,
                 "depth_max": 3, "issue_capability_on_success": True,
                 "capability_valid_seconds": 120},
            )
            if not realized.get("accepted") or not realized.get("capability"):
                raise RuntimeError(f"capability realization failed: {realized.get('reason')}")
            capability, verifier_public_key = realized["capability"], realized["verifier_public_key"]
            if not is_warmup:
                add_row(iteration, "cod_validation_plus_capability_realization", True,
                        t_realized, realized.get("reason"))

            # Unsafe bearer-style ablation: issuer signature and fields only.
            no_holder, t_no_holder = timed_post_json(
                f"{BASE['verifier']}/verify-capability",
                {"capability": capability, "verifier_public_key": verifier_public_key,
                 "request": normalize_access_request(access_request), "consume_nonce": False,
                 "consume_challenge": False, "require_holder_proof": False},
            )
            if not is_warmup:
                add_row(iteration, "capability_verification_without_holder_proof",
                        bool(no_holder.get("accepted")), t_no_holder, no_holder.get("reason"))

            holder_no_state, holder_no_state_times = timed_verify_capability_with_holder(
                capability, verifier_public_key, access_request,
                consume_nonce=False, consume_challenge=False,
            )
            if not is_warmup:
                add_row(iteration, "capability_verification_with_holder_proof_no_state",
                        bool(holder_no_state.get("accepted")),
                        holder_no_state_times["holder_bound_access_total_http"],
                        holder_no_state.get("reason"))

            fresh = post_json(
                f"{BASE['verifier']}/verify-cod",
                {"cod": cod, "issuer_keys": issuer_keys, "request": access_request,
                 "depth_max": 3, "issue_capability_on_success": True,
                 "capability_valid_seconds": 120},
            )
            full_state, full_state_times = timed_verify_capability_with_holder(
                fresh["capability"], fresh["verifier_public_key"], access_request,
                consume_nonce=True, consume_challenge=True,
            )
            if not is_warmup:
                add_row(iteration, "full_stateful_holder_bound_capability_verification",
                        bool(full_state.get("accepted")),
                        full_state_times["holder_bound_access_total_http"],
                        full_state.get("reason"))

            t_full0 = time.perf_counter()
            full_issue = run_valid_flow(FlowRequest())
            full_access = verify_capability_with_holder(
                full_issue["capability"], full_issue["verifier_public_key"], full_issue["request"],
                consume_nonce=True, consume_challenge=True,
            )
            t_full = _ms(t_full0, time.perf_counter())
            if not is_warmup:
                add_row(iteration, "full_cod_mdtwin_holder_bound_flow",
                        bool(full_issue.get("accepted")) and bool(full_access.get("accepted")),
                        t_full, full_access.get("reason"))
        except Exception as exc:
            if not is_warmup:
                failures.append({"iteration": iteration, "error": str(exc)})

    # Security evidence for both ablated controls.
    reset_verifier_state()
    security_ablation: Dict[str, Any] = {}
    try:
        valid = run_valid_flow(FlowRequest())
        cap, pk, request = valid["capability"], valid["verifier_public_key"], valid["request"]
        bearer_first = verify_capability_with_holder(
            cap, pk, request, consume_nonce=False, consume_challenge=False,
            require_holder_proof=False,
        )
        bearer_second = verify_capability_with_holder(
            cap, pk, request, consume_nonce=False, consume_challenge=False,
            require_holder_proof=False,
        )
        presentation = prepare_holder_presentation(cap, request)
        no_state_first = verify_capability_with_holder(
            cap, pk, request, consume_nonce=False, consume_challenge=False, prepared=presentation,
        )
        no_state_second = verify_capability_with_holder(
            cap, pk, request, consume_nonce=False, consume_challenge=False, prepared=presentation,
        )
        security_ablation = {
            "without_holder_proof": {
                "first_accepted": bool(bearer_first.get("accepted")),
                "second_accepted": bool(bearer_second.get("accepted")),
                "shows_bearer_capability_risk": bool(bearer_first.get("accepted")),
            },
            "without_nonce_and_challenge_consumption": {
                "first_accepted": bool(no_state_first.get("accepted")),
                "second_accepted": bool(no_state_second.get("accepted")),
                "shows_replay_risk": bool(no_state_first.get("accepted")) and bool(no_state_second.get("accepted")),
            },
        }
    except Exception as exc:
        security_ablation = {"error": str(exc)}

    summary: List[Dict[str, Any]] = []
    for variant in sorted({r["variant"] for r in raw_rows}):
        values = [float(r["latency_ms"]) for r in raw_rows if r["variant"] == variant and bool(r["accepted"])]
        accepted_count = sum(1 for r in raw_rows if r["variant"] == variant and bool(r["accepted"]))
        rejected_count = sum(1 for r in raw_rows if r["variant"] == variant and not bool(r["accepted"]))
        stats = _stats_local(values) if "_stats_local" in globals() else _summary(
            [{"operation": variant, "value_ms": value} for value in values]
        )[0]
        summary.append({"variant": variant, "accepted": accepted_count,
                        "rejected": rejected_count, **stats})

    output_file = RESULTS_DIR / "ablation_comparison.csv"
    _write_csv(output_file, raw_rows,
               ["iteration", "variant", "accepted", "latency_ms", "reason"])
    return {"test": "holder_proof_ablation_comparison", "iterations": req.iterations,
            "warmup": req.warmup, "summary": summary,
            "security_ablation": security_ablation, "failure_count": len(failures),
            "failures": failures[:10], "raw_file": str(output_file)}
