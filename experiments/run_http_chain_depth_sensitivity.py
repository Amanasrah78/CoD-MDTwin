from __future__ import annotations

import json
import sys
import time
from typing import Any, Dict

import requests

CLIENT = "http://localhost:8020"


def post(path: str, payload: Dict[str, Any] | None = None) -> Dict[str, Any]:
    r = requests.post(f"{CLIENT}{path}", json=payload or {}, timeout=1800)
    r.raise_for_status()
    return r.json()


def wait() -> None:
    for _ in range(80):
        try:
            requests.get(f"{CLIENT}/health", timeout=3).raise_for_status()
            return
        except Exception:
            time.sleep(0.5)
    raise RuntimeError("client service is not ready")


if __name__ == "__main__":
    iterations = int(sys.argv[1]) if len(sys.argv) > 1 else 100
    wait()
    out = post(
        "/run-chain-depth-sensitivity",
        {
            "depths": [1, 2, 3, 5, 10],
            "iterations": iterations,
            "warmup": 5,
            "reset_verifier_state": True,
        },
    )
    print(json.dumps(out, indent=2))