from __future__ import annotations

import json
import sys
import time
from pathlib import Path
from typing import Any, Dict

import requests


ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "results" / "metrics" / "stratified_chain_security_results.json"
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
        f"{CLIENT}/run-stratified-chain-security",
        json=payload,
        timeout=14400,
    )
    response.raise_for_status()
    return response.json()


if __name__ == "__main__":
    mode = sys.argv[1].lower() if len(sys.argv) > 1 else "quick"
    if mode not in {"quick", "full"}:
        print(
            "Usage: python3 experiments/run_stratified_chain_security.py [quick|full]",
            file=sys.stderr,
        )
        sys.exit(2)

    result = post({
        "trials_per_category": 300 if mode == "full" else 10,
        "reset_verifier_state": True,
    })
    result["mode"] = mode
    result["generated_at_unix"] = int(time.time())
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(json.dumps(result, indent=2), encoding="utf-8")

    passed = (
        result.get("failure_count") == 0
        and result.get("all_rows_passed") is True
        and result.get("all_signed_expansions_had_valid_signatures") is True
    )
    print(json.dumps({
        "mode": mode,
        "passed": passed,
        "output_file": str(OUTPUT.relative_to(ROOT)),
        "raw_file": result.get("raw_file"),
        "summary_file": result.get("summary_file"),
        "failure_count": result.get("failure_count"),
        "summary": result.get("summary"),
    }, indent=2))
    if not passed:
        sys.exit(1)
