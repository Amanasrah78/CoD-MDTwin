from __future__ import annotations

from typing import Any, Dict, List, Tuple

VENDOR_B_POLICY: Dict[str, Any] = {
    "policy_id": "vendor-b-local-policy-v1",
    "default": "deny",
    "trusted_audiences": ["vendor-b"],
    "allowed_operations": [
        {"service": "diagnostics-api", "scope": "diagnostics.read", "action": "read-status", "resource_prefix": "asset:"},
        {"service": "maintenance-api", "scope": "maintenance.history.read", "action": "read", "resource_prefix": "asset:"},
        {"service": "telemetry-api", "scope": "sensor.telemetry.read", "action": "read", "resource_prefix": "asset:"},
        {"service": "firmware-api", "scope": "firmware.version.read", "action": "read", "resource_prefix": "asset:"},
    ],
    "denied_operations": [
        {"service": "firmware-update-api", "action": "write"},
        {"service": "configuration-api", "action": "write"},
    ],
}

SERVICE_DATA = {
    "diagnostics-api": {"status": "nominal", "vibration": "normal", "temperature_c": 61.2},
    "maintenance-api": {"last_service": "2026-06-12", "open_findings": 0, "next_service_days": 42},
    "telemetry-api": {"rpm": 1480, "pressure_bar": 7.3, "sample_window_s": 30},
    "firmware-api": {"controller_fw": "4.8.1", "sensor_fw": "2.3.0"},
}


def is_operation_allowed(request: Dict[str, Any], policy: Dict[str, Any] | None = None) -> Tuple[bool, str]:
    policy = policy or VENDOR_B_POLICY
    service = request.get("service")
    scope = request.get("scope")
    action = request.get("action")
    resource = request.get("resource", "")
    for rule in policy.get("denied_operations", []):
        if rule.get("service") == service and rule.get("action") == action:
            return False, "operation explicitly denied by local policy"
    for rule in policy.get("allowed_operations", []):
        if (
            rule.get("service") == service
            and rule.get("scope") == scope
            and rule.get("action") == action
            and str(resource).startswith(rule.get("resource_prefix", ""))
        ):
            return True, "operation allowed by local policy"
    return False, "operation not allowed by local policy"


def allowed_operations_from_scopes(scopes: List[str], resource: str) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for rule in VENDOR_B_POLICY["allowed_operations"]:
        if rule["scope"] in scopes:
            out.append({"service": rule["service"], "scope": rule["scope"], "action": rule["action"], "resource": resource})
    return out
