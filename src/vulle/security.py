import re
from typing import Any


REDACTED = "[REDACTED]"

_SECRET_PATTERNS = [
    re.compile(
        r"(?i)\b(authorization\s*:\s*(?:bearer|basic)\s+)[^\s,;]+"
    ),
    re.compile(
        r"(?i)\b((?:api[_-]?key|token|password|passwd|secret|client[_-]?secret)"
        r"\s*[:=]\s*)[^\s,;]+"
    ),
    re.compile(r"(?i)\b((?:cookie|set-cookie)\s*:\s*)[^\r\n]+"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{20,}\b"),
    re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
]


def redact_text(value: str | None) -> str | None:
    if value is None:
        return None
    redacted = value
    for pattern in _SECRET_PATTERNS:
        if pattern.groups:
            redacted = pattern.sub(lambda match: f"{match.group(1)}{REDACTED}", redacted)
        else:
            redacted = pattern.sub(REDACTED, redacted)
    return redacted


def redact_data(value: Any) -> Any:
    if isinstance(value, str):
        return redact_text(value)
    if isinstance(value, dict):
        return {key: redact_data(item) for key, item in value.items()}
    if isinstance(value, list):
        return [redact_data(item) for item in value]
    if isinstance(value, tuple):
        return tuple(redact_data(item) for item in value)
    return value
