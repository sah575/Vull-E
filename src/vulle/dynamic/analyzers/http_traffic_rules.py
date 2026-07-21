import base64
import json
import re
from urllib.parse import urlsplit

from vulle.dynamic.limits import MAX_HTTP_FINDINGS_PER_RULE
from vulle.dynamic.models import DynamicEvidence, DynamicFinding
from vulle.models import HttpFlow, HttpHeader
from vulle.security import find_secret_like_matches

_JWT_PATTERN = re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b")


def evaluate_http_traffic_rules(flows: list[HttpFlow]) -> list[DynamicFinding]:
    findings: list[DynamicFinding] = []
    findings.extend(_cleartext_findings(flows))
    findings.extend(_missing_hsts_findings(flows))
    findings.extend(_missing_csp_findings(flows))
    findings.extend(_secret_in_traffic_findings(flows))
    findings.extend(_jwt_alg_none_findings(flows))
    findings.extend(_cookie_flag_findings(flows))
    return findings


def _cleartext_findings(flows: list[HttpFlow]) -> list[DynamicFinding]:
    findings: list[DynamicFinding] = []
    seen: set[tuple[str, str]] = set()
    for flow in flows:
        if flow.scheme != "http":
            continue
        path = urlsplit(flow.url).path or "/"
        key = (flow.host, path)
        if key in seen or len(findings) >= MAX_HTTP_FINDINGS_PER_RULE:
            continue
        seen.add(key)
        findings.append(
            DynamicFinding(
                id=f"DYNAMIC-CLEARTEXT-{_slug(flow.host + path)}",
                rule_id="android.dynamic.cleartext_request",
                title=f"Cleartext HTTP request observed: {flow.host}{path}",
                category="network_traffic",
                severity="high",
                status="confirmed_observation",
                evidence=[_flow_evidence(flow, f"{flow.method} {flow.url} (scheme=http)")],
                impact=(
                    "This request was observed over plaintext HTTP, so its contents "
                    "(headers, body, cookies) are visible to anyone on the network path."
                ),
                recommended_validation=[
                    "Confirm whether this endpoint carries sensitive data and whether "
                    "an HTTPS equivalent exists.",
                ],
                remediation="Serve this endpoint over HTTPS only; redirect or block plain HTTP.",
            )
        )
    return findings


def _missing_hsts_findings(flows: list[HttpFlow]) -> list[DynamicFinding]:
    findings: list[DynamicFinding] = []
    seen: set[str] = set()
    for flow in flows:
        if flow.scheme != "https" or flow.host in seen:
            continue
        if len(findings) >= MAX_HTTP_FINDINGS_PER_RULE:
            continue
        if _header(flow.response_headers, "strict-transport-security") is not None:
            continue
        seen.add(flow.host)
        findings.append(
            DynamicFinding(
                id=f"DYNAMIC-MISSING-HSTS-{_slug(flow.host)}",
                rule_id="android.dynamic.missing_hsts",
                title=f"Missing Strict-Transport-Security header: {flow.host}",
                category="security_headers",
                severity="low",
                status="confirmed_observation",
                evidence=[_flow_evidence(flow, f"Response from {flow.host} had no HSTS header")],
                impact=(
                    "Without HSTS, a client that is tricked into an initial plain-HTTP "
                    "connection can be downgraded/intercepted before being redirected to HTTPS."
                ),
                recommended_validation=["Confirm this is intentional for a mobile-only backend."],
                remediation="Add Strict-Transport-Security with a meaningful max-age.",
            )
        )
    return findings


def _missing_csp_findings(flows: list[HttpFlow]) -> list[DynamicFinding]:
    findings: list[DynamicFinding] = []
    seen: set[str] = set()
    for flow in flows:
        content_type = (_header(flow.response_headers, "content-type") or "").lower()
        if not content_type.startswith("text/html"):
            continue
        if flow.host in seen or len(findings) >= MAX_HTTP_FINDINGS_PER_RULE:
            continue
        if _header(flow.response_headers, "content-security-policy") is not None:
            continue
        seen.add(flow.host)
        findings.append(
            DynamicFinding(
                id=f"DYNAMIC-MISSING-CSP-{_slug(flow.host)}",
                rule_id="android.dynamic.missing_csp",
                title=f"Missing Content-Security-Policy header on HTML response: {flow.host}",
                category="security_headers",
                severity="low",
                status="confirmed_observation",
                evidence=[
                    _flow_evidence(flow, f"HTML response from {flow.host} had no CSP header")
                ],
                impact="Without CSP, an XSS in this HTML surface has fewer built-in mitigations.",
                recommended_validation=[
                    "Confirm whether this HTML surface renders any user input.",
                ],
                remediation="Add a restrictive Content-Security-Policy header.",
            )
        )
    return findings


def _secret_in_traffic_findings(flows: list[HttpFlow]) -> list[DynamicFinding]:
    findings: list[DynamicFinding] = []
    seen: set[str] = set()
    for flow in flows:
        if len(findings) >= MAX_HTTP_FINDINGS_PER_RULE:
            break
        candidates = "\n".join(
            text for text in (flow.url, flow.request_body, flow.response_body) if text
        )
        for match in find_secret_like_matches(candidates):
            if match in seen:
                continue
            seen.add(match)
            findings.append(
                DynamicFinding(
                    id=f"DYNAMIC-SECRET-{_slug(match[:32])}",
                    rule_id="android.dynamic.secret_in_traffic",
                    title="Possible secret observed in captured traffic",
                    category="network_traffic",
                    severity="high",
                    status="risk_hypothesis",
                    evidence=[_flow_evidence(flow, f"redacted_length={len(match)}")],
                    impact=(
                        "A value matching a known secret pattern was observed in captured "
                        "request/response traffic."
                    ),
                    recommended_validation=[
                        "Confirm whether this is a live credential and what it grants access to.",
                    ],
                    remediation="Avoid transmitting long-lived credentials in URLs or bodies.",
                )
            )
            if len(findings) >= MAX_HTTP_FINDINGS_PER_RULE:
                break
    return findings


def _jwt_alg_none_findings(flows: list[HttpFlow]) -> list[DynamicFinding]:
    findings: list[DynamicFinding] = []
    seen: set[str] = set()
    for flow in flows:
        if len(findings) >= MAX_HTTP_FINDINGS_PER_RULE:
            break
        authorization = _header(flow.request_headers, "authorization") or ""
        candidates = "\n".join(
            text
            for text in (authorization, flow.url, flow.request_body, flow.response_body)
            if text
        )
        for token in _JWT_PATTERN.findall(candidates):
            if token in seen:
                continue
            seen.add(token)
            alg = _jwt_alg(token)
            if alg is not None and alg.lower() != "none":
                continue
            findings.append(
                DynamicFinding(
                    id=f"DYNAMIC-JWT-ALG-NONE-{_slug(token[:24])}",
                    rule_id="android.dynamic.jwt_alg_none",
                    title="JWT with missing or 'none' signing algorithm observed",
                    category="authentication",
                    severity="critical",
                    status="risk_hypothesis",
                    evidence=[
                        _flow_evidence(flow, f"JWT header alg={alg!r} (token prefix redacted)")
                    ],
                    impact=(
                        "A JWT with alg=none (or no alg claim) is not cryptographically "
                        "signed and can be forged if the backend does not reject it."
                    ),
                    recommended_validation=[
                        "Confirm the backend rejects unsigned/alg=none JWTs.",
                    ],
                    remediation="Reject tokens whose alg is not an expected signed algorithm.",
                )
            )
            if len(findings) >= MAX_HTTP_FINDINGS_PER_RULE:
                break
    return findings


def _cookie_flag_findings(flows: list[HttpFlow]) -> list[DynamicFinding]:
    findings: list[DynamicFinding] = []
    seen: set[tuple[str, str]] = set()
    for flow in flows:
        if flow.scheme != "https":
            continue
        for header in flow.response_headers:
            if header.name.lower() != "set-cookie" or len(findings) >= MAX_HTTP_FINDINGS_PER_RULE:
                continue
            name, missing = _cookie_missing_flags(header.value)
            key = (flow.host, name)
            if not missing or key in seen:
                continue
            seen.add(key)
            findings.append(
                DynamicFinding(
                    id=f"DYNAMIC-COOKIE-FLAGS-{_slug(flow.host + name)}",
                    rule_id="android.dynamic.cookie_missing_flags",
                    title=f"Cookie '{name}' from {flow.host} is missing: {', '.join(missing)}",
                    category="session_management",
                    severity="medium",
                    status="confirmed_observation",
                    evidence=[_flow_evidence(flow, header.value)],
                    impact=(
                        "Missing cookie flags widen the conditions under which this cookie "
                        "could be exposed (e.g. over a downgraded connection or via script)."
                    ),
                    recommended_validation=[
                        "Confirm whether this cookie carries a session token.",
                    ],
                    remediation="Set Secure, HttpOnly, and explicit SameSite on session cookies.",
                )
            )
    return findings


def _cookie_missing_flags(set_cookie_value: str) -> tuple[str, list[str]]:
    parts = [part.strip() for part in set_cookie_value.split(";")]
    name = parts[0].split("=", 1)[0].strip() if parts else ""
    attributes = {part.split("=", 1)[0].strip().lower() for part in parts[1:]}
    missing = []
    if "secure" not in attributes:
        missing.append("Secure")
    if "httponly" not in attributes:
        missing.append("HttpOnly")
    if "samesite" not in attributes:
        missing.append("SameSite")
    return name, missing


def _jwt_alg(token: str) -> str | None:
    header_segment = token.split(".", 1)[0]
    padded = header_segment + "=" * (-len(header_segment) % 4)
    try:
        decoded = base64.urlsafe_b64decode(padded)
        header = json.loads(decoded)
    except (ValueError, UnicodeDecodeError, json.JSONDecodeError):
        return None
    alg = header.get("alg")
    return str(alg) if alg is not None else None


def _header(headers: list[HttpHeader], name: str) -> str | None:
    for header in headers:
        if header.name.lower() == name.lower():
            return header.value
    return None


def _flow_evidence(flow: HttpFlow, quote: str) -> DynamicEvidence:
    return DynamicEvidence(
        artifact_type="http_flow",
        artifact_path=flow.id,
        location=f"{flow.method} {flow.url}",
        quote=quote,
    )


def _slug(value: str) -> str:
    return "".join(char if char.isalnum() else "-" for char in value).strip("-").upper()
