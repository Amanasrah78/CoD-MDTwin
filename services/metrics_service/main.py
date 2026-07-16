from __future__ import annotations

import csv
import json
import statistics
from pathlib import Path
from typing import Any, Dict, List

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

app = FastAPI(title="Metrics Service", version="0.3.0")
METRICS_PATH = Path("/app/results/metrics/http_metrics.csv")
TRACE_PATH = Path("/app/results/traces/http_traces.jsonl")
METRICS_PATH.parent.mkdir(parents=True, exist_ok=True)
TRACE_PATH.parent.mkdir(parents=True, exist_ok=True)

class TraceIngestRequest(BaseModel):
    scenario: str
    trace: Dict[str, Any]

@app.get("/health")
def health() -> Dict[str, str]:
    return {"status": "ok", "service": "metrics-service"}


@app.get("/")
def root() -> Dict[str, Any]:
    return domain_info()

@app.get("/domain-info")
def domain_info() -> Dict[str, Any]:
    return {
        "service": "metrics-service",
        "role": "trace ingestion and timing CSV generation",
        "port": 9100,
        "storage": {"metrics": str(METRICS_PATH), "traces": str(TRACE_PATH)},
        "endpoints": {
            "POST /ingest-trace": "store a trace and append its timing rows",
            "GET /metrics": "raw timing rows",
            "GET /summary": "aggregate mean/std/min/max/count per scenario-operation-metric",
            "GET /latest-trace": "latest ingested trace",
            "GET /trace/{trace_id}": "retrieve one ingested trace",
        },
    }

@app.post("/ingest-trace")
def ingest_trace(req: TraceIngestRequest) -> Dict[str, Any]:
    with TRACE_PATH.open("a", encoding="utf-8") as f:
        f.write(json.dumps({"scenario": req.scenario, "trace": req.trace}, sort_keys=True) + "\n")
    rows = []
    for metric, value in req.trace.get("timing_ms", {}).items():
        rows.append({
            "scenario": req.scenario,
            "trace_id": req.trace.get("trace_id"),
            "operation": req.trace.get("operation"),
            "decision": req.trace.get("decision"),
            "metric": metric,
            "value_ms": value,
        })
    write_header = not METRICS_PATH.exists()
    with METRICS_PATH.open("a", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["scenario", "trace_id", "operation", "decision", "metric", "value_ms"])
        if write_header:
            writer.writeheader()
        writer.writerows(rows)
    return {"accepted": True, "rows_written": len(rows), "metrics_file": str(METRICS_PATH)}

@app.get("/metrics")
def metrics() -> List[Dict[str, Any]]:
    if not METRICS_PATH.exists():
        return []
    with METRICS_PATH.open("r", encoding="utf-8") as f:
        return list(csv.DictReader(f))

@app.get("/summary")
def summary() -> Dict[str, Any]:
    rows = metrics()
    groups: Dict[tuple, List[float]] = {}
    for row in rows:
        key = (row.get("scenario"), row.get("operation"), row.get("metric"))
        try:
            groups.setdefault(key, []).append(float(row.get("value_ms", 0)))
        except ValueError:
            continue
    out = []
    for (scenario, operation, metric), values in sorted(groups.items()):
        n = len(values)
        mean = statistics.fmean(values)
        std = statistics.stdev(values) if n > 1 else 0.0
        ci95 = 1.96 * std / (n ** 0.5) if n > 1 else 0.0
        out.append({
            "scenario": scenario,
            "operation": operation,
            "metric": metric,
            "count": n,
            "mean_ms": round(mean, 4),
            "std_ms": round(std, 4),
            "min_ms": round(min(values), 4),
            "max_ms": round(max(values), 4),
            "ci95_ms": round(ci95, 4),
        })
    return {"count": len(out), "summary": out}


def _trace_rows() -> List[Dict[str, Any]]:
    if not TRACE_PATH.exists():
        return []
    return [json.loads(line) for line in TRACE_PATH.read_text(encoding="utf-8").splitlines() if line.strip()]

@app.get("/latest-trace")
def latest_trace() -> Dict[str, Any]:
    rows = _trace_rows()
    if not rows:
        raise HTTPException(status_code=404, detail="no traces ingested")
    return rows[-1]

@app.get("/trace/{trace_id}")
def trace_by_id(trace_id: str) -> Dict[str, Any]:
    for row in _trace_rows():
        if row.get("trace", {}).get("trace_id") == trace_id:
            return row
    raise HTTPException(status_code=404, detail="trace not found")
