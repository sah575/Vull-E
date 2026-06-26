import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from vulle.security import PiiRedactionMode, redact_data

SENSITIVE_AUDIT_KEYS = {
    "api_key",
    "apikey",
    "authorization",
    "client_secret",
    "cookie",
    "password",
    "refresh_token",
    "secret",
    "set-cookie",
    "token",
    "x-api-key",
}


def emit_audit_event(
    path: Path | None,
    event: dict[str, Any],
    *,
    pii_mode: PiiRedactionMode = "off",
) -> None:
    if path is None:
        return
    payload = {
        "timestamp": datetime.now(UTC).isoformat(),
        **event,
    }
    redacted = redact_data(payload, pii_mode=pii_mode)
    redacted = _redact_sensitive_keys(redacted)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(redacted, ensure_ascii=False, sort_keys=True))
        handle.write("\n")


def _redact_sensitive_keys(value: Any) -> Any:
    if isinstance(value, dict):
        result: dict[str, Any] = {}
        for key, item in value.items():
            normalized = str(key).lower().replace("_", "-")
            if normalized in SENSITIVE_AUDIT_KEYS:
                result[key] = "[REDACTED]"
            else:
                result[key] = _redact_sensitive_keys(item)
        return result
    if isinstance(value, list):
        return [_redact_sensitive_keys(item) for item in value]
    return value
