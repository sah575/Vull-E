import math
import re
from collections.abc import Callable
from typing import Any, TypeVar

from vulle.apk.limits import (
    MAX_SECRET_CANDIDATE_LENGTH,
    MAX_STRINGS_SCANNED,
    MIN_SECRET_CANDIDATE_LENGTH,
)
from vulle.apk.models import ApkEvidence, ApkFinding, FindingStatus, Severity

T = TypeVar("T")

_URL_PATTERN = re.compile(r"https?://[^\s\"'<>]+")

_KNOWN_SECRET_PATTERNS: list[tuple[str, re.Pattern[str], Severity]] = [
    ("aws_access_key", re.compile(r"^AKIA[0-9A-Z]{16}$"), "high"),
    ("google_api_key", re.compile(r"^AIza[0-9A-Za-z_-]{35}$"), "medium"),
    ("github_token", re.compile(r"^gh[pousr]_[A-Za-z0-9_]{20,}$"), "high"),
    ("gitlab_token", re.compile(r"^glpat-[A-Za-z0-9_-]{20,}$"), "high"),
    ("slack_token", re.compile(r"^xox[baprs]-[A-Za-z0-9-]{10,}$"), "high"),
    ("npm_token", re.compile(r"^npm_[A-Za-z0-9]{20,}$"), "high"),
    (
        "jwt",
        re.compile(r"^eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}$"),
        "medium",
    ),
    (
        "private_key_marker",
        re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
        "high",
    ),
    (
        "database_uri",
        re.compile(
            r"(?i)^(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqps?)://"
            r"[^\s/@:]+:[^\s/@]+@\S+$"
        ),
        "high",
    ),
]

_MIN_ENTROPY_FOR_GENERIC_CANDIDATE = 4.0
_GENERIC_CANDIDATE_PATTERN = re.compile(r"^[A-Za-z0-9+/_=.-]+$")


def evaluate_secret_rules(analysis: Any) -> list[ApkFinding]:
    findings = []
    seen: set[tuple[str, str]] = set()
    for index, string_analysis in enumerate(_strings(analysis)):
        if index >= MAX_STRINGS_SCANNED:
            break
        value = _safe_call(string_analysis.get_value, None)
        if not isinstance(value, str):
            continue
        if not (MIN_SECRET_CANDIDATE_LENGTH <= len(value) <= MAX_SECRET_CANDIDATE_LENGTH):
            continue
        category, severity = _classify(value)
        if category is None:
            continue
        dedupe_key = (category, _redact(value))
        if dedupe_key in seen:
            continue
        seen.add(dedupe_key)
        findings.append(_finding_for(string_analysis, category, severity, value))
    return findings


def extract_network_endpoints(analysis: Any) -> list[str]:
    endpoints: set[str] = set()
    for index, string_analysis in enumerate(_strings(analysis)):
        if index >= MAX_STRINGS_SCANNED:
            break
        value = _safe_call(string_analysis.get_value, None)
        if not isinstance(value, str):
            continue
        for match in _URL_PATTERN.finditer(value):
            endpoints.add(match.group(0))
    return sorted(endpoints)


def _classify(value: str) -> tuple[str | None, Severity]:
    for name, pattern, severity in _KNOWN_SECRET_PATTERNS:
        if pattern.search(value):
            return name, severity
    if (
        _GENERIC_CANDIDATE_PATTERN.match(value)
        and _shannon_entropy(value) >= _MIN_ENTROPY_FOR_GENERIC_CANDIDATE
    ):
        return "high_entropy_candidate", "info"
    return None, "info"


def _finding_for(
    string_analysis: Any,
    category: str,
    severity: Severity,
    value: str,
) -> ApkFinding:
    status: FindingStatus = (
        "informational" if category == "high_entropy_candidate" else "risk_hypothesis"
    )
    usage = _usage_locations(string_analysis)
    return ApkFinding(
        id=f"ANDROID-SECRET-{category.upper()}-{_slug(_redact(value))}",
        rule_id=f"android.secrets.{category}",
        title=f"Possible hardcoded secret ({category.replace('_', ' ')})",
        category="secrets",
        severity=severity,
        status=status,
        evidence=[
            ApkEvidence(
                artifact_type="dex_code",
                artifact_path=usage[0] if usage else "unknown",
                location="dex string pool",
                quote=(
                    f"redacted_preview={_redact(value)} length={len(value)} "
                    f"entropy={_shannon_entropy(value):.2f}"
                ),
            )
        ],
        impact=(
            "A hardcoded value matching a known secret pattern was found in the app's "
            "compiled code. If this is a real credential, it is trivially extractable "
            "by anyone who decompiles the APK."
        ),
        recommended_validation=[
            "Confirm whether this value is a live credential and, if so, whether it "
            "grants access to production systems.",
        ],
        remediation=(
            "Remove hardcoded credentials from client code; use a backend-issued, "
            "short-lived token or a secrets manager instead."
        ),
    )


def _usage_locations(string_analysis: Any, limit: int = 3) -> list[str]:
    xrefs: list[Any] = _safe_call(lambda: list(string_analysis.get_xref_from()), [])
    locations = []
    for entry in xrefs[:limit]:
        try:
            class_analysis, method_analysis = entry
        except (TypeError, ValueError):
            continue
        class_name = _class_name(class_analysis)
        method_name = _method_name(method_analysis)
        locations.append(f"{class_name}->{method_name}")
    return locations


def _class_name(class_analysis: Any) -> Any:
    return _safe_call(lambda: class_analysis.get_class().get_name(), "unknown")


def _method_name(method_analysis: Any) -> Any:
    return _safe_call(lambda: method_analysis.get_method().get_name(), "unknown")


def _redact(value: str) -> str:
    if len(value) <= 8:
        return "*" * len(value)
    return f"{value[:4]}...{value[-4:]}"


def _shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    counts: dict[str, int] = {}
    for char in value:
        counts[char] = counts.get(char, 0) + 1
    length = len(value)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def _strings(analysis: Any) -> list[Any]:
    return _safe_call(analysis.get_strings, [])


def _safe_call(fn: Callable[[], T], default: T) -> T:
    try:
        return fn()
    except Exception:
        return default


def _slug(value: str) -> str:
    return "".join(char if char.isalnum() else "-" for char in value).strip("-").upper()
