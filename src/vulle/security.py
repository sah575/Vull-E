import re
from typing import Any, Literal
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

REDACTED = "[REDACTED]"
REDACTED_PII = "[REDACTED:PII]"
PiiRedactionMode = Literal["off", "mask"]

_PREFIXED_SECRET_PATTERNS = [
    re.compile(r"(?i)\b(authorization\s*:\s*(?:bearer|basic)\s+)[^\s,;]+"),
    re.compile(
        r"(?i)\b((?:x-api-key|api[_-]?key|access[_-]?token|refresh[_-]?token|"
        r"token|password|passwd|secret|client[_-]?secret)\s*[:=]\s*)"
        r"(?:\"[^\"]*\"|'[^']*'|[^\s,;]+)"
    ),
    re.compile(r"(?i)\b((?:cookie|set-cookie)\s*:\s*)[^\r\n]+"),
    re.compile(
        r"(?i)([\"'](?:password|passwd|secret|client_secret|api_key|token|"
        r"access_token|refresh_token)[\"']\s*:\s*)[\"'][^\"']*[\"']"
    ),
    re.compile(
        r"(?is)(<(?:password|secret|token|apiKey|clientSecret)>).*?"
        r"(</(?:password|secret|token|apiKey|clientSecret)>)"
    ),
]
_SECRET_PATTERNS = [
    re.compile(
        r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----.*?"
        r"-----END (?:RSA |EC |OPENSSH )?PRIVATE KEY-----",
        re.DOTALL,
    ),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{20,}\b"),
    re.compile(r"\bglpat-[A-Za-z0-9_-]{20,}\b"),
    re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"),
    re.compile(r"\bnpm_[A-Za-z0-9]{20,}\b"),
    re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
    re.compile(
        r"(?i)\b(?:postgres(?:ql)?|mysql|mongodb(?:\\+srv)?|redis|amqps?)://"
        r"[^\s/@:]+:[^\s/@]+@[^\s]+"
    ),
    re.compile(
        r"(?i)\b(?:jdbc:[a-z0-9]+://[^\s;]+;[^\s]*"
        r"(?:password|pwd)=[^;\s]+[^\s]*)"
    ),
    re.compile(
        r"(?i)\b(?:DefaultEndpointsProtocol|AccountName|AccountKey|"
        r"EndpointSuffix)=[^;\r\n]+(?:;[^;\r\n=]+=[^;\r\n]+)+"
    ),
]
_SENSITIVE_QUERY_KEYS = {
    "access_token",
    "api_key",
    "apikey",
    "auth",
    "authorization",
    "client_secret",
    "code",
    "password",
    "refresh_token",
    "secret",
    "signature",
    "sig",
    "token",
}
_URL_PATTERN = re.compile(r"https?://[^\s<>'\"]+")
_PII_PATTERNS = [
    re.compile(r"\bTR\d{2}(?:\s?\d{4}){5}\s?\d{2}\b", re.IGNORECASE),
    re.compile(r"\b(?:\+?90|0)?5\d{2}[\s.-]?\d{3}[\s.-]?\d{2}[\s.-]?\d{2}\b"),
    re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.IGNORECASE),
    re.compile(r"\b\d{11}\b"),
    re.compile(r"\b(?:\d[ -]*?){13,19}\b"),
]


def redact_text(
    value: str | None,
    *,
    pii_mode: PiiRedactionMode = "off",
) -> str | None:
    if value is None:
        return None
    redacted = value
    for pattern in _PREFIXED_SECRET_PATTERNS:
        if pattern.groups == 2:
            redacted = pattern.sub(
                lambda match: f"{match.group(1)}{REDACTED}{match.group(2)}",
                redacted,
            )
        else:
            redacted = pattern.sub(
                lambda match: f"{match.group(1)}{REDACTED}",
                redacted,
            )
    for pattern in _SECRET_PATTERNS:
        redacted = pattern.sub(REDACTED, redacted)
    redacted = _redact_url_secrets(redacted)
    if pii_mode == "mask":
        for pattern in _PII_PATTERNS:
            redacted = pattern.sub(REDACTED_PII, redacted)
    return redacted


def redact_data(
    value: Any,
    *,
    pii_mode: PiiRedactionMode = "off",
) -> Any:
    if isinstance(value, str):
        return redact_text(value, pii_mode=pii_mode)
    if isinstance(value, dict):
        return {
            key: redact_data(item, pii_mode=pii_mode)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [redact_data(item, pii_mode=pii_mode) for item in value]
    if isinstance(value, tuple):
        return tuple(redact_data(item, pii_mode=pii_mode) for item in value)
    return value


def _redact_url_secrets(text: str) -> str:
    def replace(match: re.Match[str]) -> str:
        url = match.group(0)
        try:
            parts = urlsplit(url)
            query = parse_qsl(parts.query, keep_blank_values=True)
        except ValueError:
            return url
        if not query:
            return url
        changed = False
        sanitized = []
        for key, value in query:
            if key.lower() in _SENSITIVE_QUERY_KEYS:
                sanitized.append((key, REDACTED))
                changed = True
            else:
                sanitized.append((key, value))
        if not changed:
            return url
        return urlunsplit(
            (parts.scheme, parts.netloc, parts.path, urlencode(sanitized), parts.fragment)
        )

    return _URL_PATTERN.sub(replace, text)
