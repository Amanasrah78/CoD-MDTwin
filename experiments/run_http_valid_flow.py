from __future__ import annotations

import json
import sys
import time
from typing import Any, Dict

import requests

CLIENT = "http://localhost:8020"


def post(path: str, payload: Dict[str, Any] | None = None) -> Dict[str, Any]:
    response = requests.post(f"{CLIENT}{path}", json=payload or {}, timeout=120)
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
        issuance = post("/run-valid-flow", {})
        protected = post("/run-protected-resource-test", {})
        out = {
            "capability_issuance": issuance,
            "holder_bound_protected_access": protected,
            "passed": issuance.get("accepted") is True and protected.get("passed") is True,
        }
        print(json.dumps(out, indent=2))
        if not out["passed"]:
            sys.exit(1)
    except Exception as exc:
        print(json.dumps({"accepted": False, "error": str(exc)}, indent=2), file=sys.stderr)
        sys.exit(1)
