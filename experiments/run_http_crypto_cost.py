from __future__ import annotations

import json
import sys
import time
from typing import Any, Dict

import requests

CLIENT = "http://localhost:8020"


def post(path: str, payload: Dict[str, Any] | None = None) -> Dict[str, Any]:
    response = requests.post(f"{CLIENT}{path}", json=payload or {}, timeout=1800)
    response.raise_for_status()
    return response.json()


def wait() -> None:
    for _ in range(80):
        try:
            requests.get(f"{CLIENT}/health", timeout=3).raise_for_status()
            return
        except Exception:
            time.sleep(0.5)
    raise RuntimeError("client service is not ready")


if __name__ == "__main__":
    try:
        wait()
        local_iterations = int(sys.argv[1]) if len(sys.argv) > 1 else 5000
        stateful_iterations = int(sys.argv[2]) if len(sys.argv) > 2 else 1000
        out = post("/run-crypto-cost", {
            "local_iterations": local_iterations,
            "revocation_read_iterations": local_iterations,
            "stateful_iterations": stateful_iterations,
            "revocation_entries": 100,
        })
        print(json.dumps(out, indent=2))
    except Exception as exc:
        print(json.dumps({"accepted": False, "error": str(exc)}, indent=2), file=sys.stderr)
        sys.exit(1)
