from __future__ import annotations

import json
import time
from typing import Any, Dict

import requests

CLIENT = "http://localhost:8020"


def post(path: str, payload: Dict[str, Any] | None = None) -> Dict[str, Any]:
    r = requests.post(f"{CLIENT}{path}", json=payload or {}, timeout=600)
    r.raise_for_status()
    return r.json()


def wait() -> None:
    for _ in range(60):
        try:
            requests.get(f"{CLIENT}/health", timeout=3).raise_for_status()
            return
        except Exception:
            time.sleep(0.5)
    raise RuntimeError("client service is not ready")


if __name__ == "__main__":
    wait()
    out = post("/run-token-tests", {})
    print(json.dumps(out, indent=2))
