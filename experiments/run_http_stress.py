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
    wait()
    mode = sys.argv[1] if len(sys.argv) > 1 else "all"
    if mode == "all":
        out = post("/run-stress-all", {})
    elif mode == "load":
        iterations = int(sys.argv[2]) if len(sys.argv) > 2 else 1000
        concurrency = int(sys.argv[3]) if len(sys.argv) > 3 else 20
        out = post("/run-stress-load", {"iterations": iterations, "concurrency": concurrency})
    elif mode == "replay":
        concurrency = int(sys.argv[2]) if len(sys.argv) > 2 else 50
        out = post("/run-stress-replay", {"concurrency": concurrency})
    else:
        out = post(f"/run-stress-{mode}", {})
    print(json.dumps(out, indent=2))
