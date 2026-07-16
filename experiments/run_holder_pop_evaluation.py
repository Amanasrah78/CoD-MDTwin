from __future__ import annotations

import json
import sys
import time
from pathlib import Path
from typing import Any, Dict

import requests

ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "results" / "metrics" / "holder_pop_evaluation.json"
CLIENT = "http://localhost:8020"


def post(path: str, payload: Dict[str, Any] | None = None, timeout: int = 3600) -> Dict[str, Any]:
    response = requests.post(f"{CLIENT}{path}", json=payload or {}, timeout=timeout)
    response.raise_for_status()
    return response.json()


def wait() -> None:
    for _ in range(120):
        try:
            requests.get(f"{CLIENT}/health", timeout=3).raise_for_status()
            return
        except Exception:
            time.sleep(0.5)
    raise RuntimeError("client service is not ready")


def run(mode: str) -> Dict[str, Any]:
    full = mode == "full"
    results: Dict[str, Any] = {
        "mode": mode,
        "generated_at_unix": int(time.time()),
        "functional_and_security": post("/run-token-tests"),
        "protected_resource": post("/run-protected-resource-test"),
    }

    replay_levels = [10, 25, 50, 100] if full else [10]
    results["concurrent_replay"] = {
        str(level): post("/run-stress-replay", {"concurrency": level})
        for level in replay_levels
    }

    perf_iterations = 100 if full else 10
    results["performance"] = post(
        "/run-performance",
        {"iterations": perf_iterations, "warmup": 5 if full else 2,
         "include_capability_verification": True, "reset_verifier_state": True},
    )
    results["ablation"] = post(
        "/run-ablation-comparison",
        {"iterations": 100 if full else 10, "warmup": 5 if full else 2,
         "reset_verifier_state": True},
    )
    results["cryptographic_and_stateful_cost"] = post(
        "/run-crypto-cost",
        {
            "local_iterations": 5000 if full else 100,
            "revocation_read_iterations": 5000 if full else 50,
            "stateful_iterations": 1000 if full else 20,
            "revocation_entries": 100,
        },
    )

    load_sizes = [100, 500, 1000] if full else [100]
    results["load"] = {
        str(size): post(
            "/run-stress-load",
            {"iterations": size, "concurrency": 10, "reset_verifier_state": True},
        )
        for size in load_sizes
    }
    return results


if __name__ == "__main__":
    mode = sys.argv[1].lower() if len(sys.argv) > 1 else "quick"
    if mode not in {"quick", "full"}:
        print("Usage: python3 experiments/run_holder_pop_evaluation.py [quick|full]", file=sys.stderr)
        sys.exit(2)
    try:
        wait()
        output = run(mode)
        OUTPUT.parent.mkdir(parents=True, exist_ok=True)
        OUTPUT.write_text(json.dumps(output, indent=2), encoding="utf-8")
        print(json.dumps({
            "mode": mode,
            "output_file": str(OUTPUT.relative_to(ROOT)),
            "functional_summary": output["functional_and_security"].get("summary"),
            "protected_resource_passed": output["protected_resource"].get("passed"),
            "replay_passed": all(item.get("passed") for item in output["concurrent_replay"].values()),
            "performance_failures": output["performance"].get("failure_count"),
            "ablation_failures": output["ablation"].get("failure_count"),
        }, indent=2))
    except Exception as exc:
        print(json.dumps({"accepted": False, "error": str(exc)}, indent=2), file=sys.stderr)
        sys.exit(1)
