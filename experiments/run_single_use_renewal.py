from __future__ import annotations

import json
import sys
import time
from pathlib import Path
from typing import Any, Dict

import requests


ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "results" / "metrics" / "single_use_renewal_results.json"
CLIENT = "http://localhost:8020"


def wait() -> None:
    for _ in range(120):
        try:
            requests.get(f"{CLIENT}/health", timeout=3).raise_for_status()
            return
        except Exception:
            time.sleep(0.5)
    raise RuntimeError("client service is not ready")


def post(payload: Dict[str, Any]) -> Dict[str, Any]:
    response = requests.post(
        f"{CLIENT}/run-single-use-renewal",
        json=payload,
        timeout=14400,
    )
    response.raise_for_status()
    return response.json()


if __name__ == "__main__":
    mode = sys.argv[1].lower() if len(sys.argv) > 1 else "quick"
    if mode not in {"quick", "full"}:
        print(
            "Usage: python3 experiments/run_single_use_renewal.py [quick|full]",
            file=sys.stderr,
        )
        sys.exit(2)

    full = mode == "full"
    payload = {
        "operation_counts": [1, 10, 50, 100, 500, 1000] if full else [1, 10, 50],
        "repetitions": 10 if full else 3,
        "warmup_sessions": 1,
        "revocation_operation_count": 100 if full else 20,
        "reset_verifier_state": True,
    }

    try:
        wait()
        result = post(payload)
        result["mode"] = mode
        result["generated_at_unix"] = int(time.time())
        OUTPUT.parent.mkdir(parents=True, exist_ok=True)
        OUTPUT.write_text(json.dumps(result, indent=2), encoding="utf-8")

        passed = (
            result.get("failure_count") == 0
            and result.get("all_normal_operations_accepted") is True
            and result.get("all_revocation_checks_passed") is True
        )
        print(json.dumps({
            "mode": mode,
            "passed": passed,
            "output_file": str(OUTPUT.relative_to(ROOT)),
            "raw_file": result.get("raw_file"),
            "sessions_file": result.get("sessions_file"),
            "summary_file": result.get("summary_file"),
            "failure_count": result.get("failure_count"),
            "all_normal_operations_accepted": result.get("all_normal_operations_accepted"),
            "all_revocation_checks_passed": result.get("all_revocation_checks_passed"),
            "revocation_checks": result.get("revocation_checks"),
        }, indent=2))
        if not passed:
            sys.exit(1)
    except Exception as exc:
        print(json.dumps({"passed": False, "error": str(exc)}, indent=2), file=sys.stderr)
        sys.exit(1)
