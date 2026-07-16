from __future__ import annotations

import hashlib
import json
import time
import uuid
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Any, Dict, Iterator, Optional


def now_ns() -> int:
    return time.perf_counter_ns()


def sha256_json(obj: Any) -> str:
    data = json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return "sha256:" + hashlib.sha256(data).hexdigest()


@dataclass
class Trace:
    operation: str
    actor: str
    domain: str
    request_id: Optional[str] = None
    trace_id: str = field(default_factory=lambda: "tr_" + uuid.uuid4().hex[:16])
    decision: str = "pending"
    reason: str = ""
    inputs: Dict[str, Any] = field(default_factory=dict)
    checks: Dict[str, Any] = field(default_factory=dict)
    artifacts: Dict[str, Any] = field(default_factory=dict)
    timing_ms: Dict[str, float] = field(default_factory=dict)

    def mark(self, decision: str, reason: str) -> None:
        self.decision = decision
        self.reason = reason

    @contextmanager
    def timer(self, name: str) -> Iterator[None]:
        start = now_ns()
        try:
            yield
        finally:
            self.timing_ms[name] = round((now_ns() - start) / 1_000_000, 4)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "trace_id": self.trace_id,
            "request_id": self.request_id,
            "operation": self.operation,
            "actor": self.actor,
            "domain": self.domain,
            "decision": self.decision,
            "reason": self.reason,
            "inputs": self.inputs,
            "checks": self.checks,
            "artifacts": self.artifacts,
            "timing_ms": self.timing_ms,
        }
