from collections.abc import Callable
from typing import Any, TypeVar

from vulle.apk.models import ApkEvidence, ApkFinding

T = TypeVar("T")

_TRUST_MANAGER_INTERFACE = "Ljavax/net/ssl/X509TrustManager;"
_HOSTNAME_VERIFIER_INTERFACE = "Landroid/webkit/HostnameVerifier;"
_SSL_ERROR_HANDLER_PROCEED = "SslErrorHandler;->proceed"


def evaluate_tls_rules(analysis: Any) -> list[ApkFinding]:
    findings = []
    findings.extend(
        _permissive_method_findings(
            analysis,
            interface_descriptor=_TRUST_MANAGER_INTERFACE,
            method_name="checkServerTrusted",
            rule_id="android.tls.permissive_trust_manager",
            title_prefix="Trust manager does not appear to validate certificates",
            category="network_security",
        )
    )
    findings.extend(
        _permissive_method_findings(
            analysis,
            interface_descriptor=_HOSTNAME_VERIFIER_INTERFACE,
            method_name="verify",
            rule_id="android.tls.permissive_hostname_verifier",
            title_prefix="Hostname verifier does not appear to validate the hostname",
            category="network_security",
        )
    )
    findings.extend(_ssl_error_proceed_findings(analysis))
    return findings


def _permissive_method_findings(
    analysis: Any,
    *,
    interface_descriptor: str,
    method_name: str,
    rule_id: str,
    title_prefix: str,
    category: str,
) -> list[ApkFinding]:
    findings = []
    for class_analysis in _classes_implementing(analysis, interface_descriptor):
        class_name = _class_name(class_analysis)
        for method_analysis in _methods_named(class_analysis, method_name):
            instructions = list(_instructions(method_analysis))
            if any(instr.get_name() == "throw" for instr in instructions):
                continue
            findings.append(
                ApkFinding(
                    id=f"ANDROID-TLS-{_slug(class_name)}-{method_name.upper()}",
                    rule_id=rule_id,
                    title=f"{title_prefix}: {class_name}.{method_name}",
                    category=category,
                    severity="high",
                    status="risk_hypothesis",
                    evidence=[
                        ApkEvidence(
                            artifact_type="dex_code",
                            artifact_path=class_name,
                            location=f"{class_name}->{method_name}",
                            quote=(
                                f"{method_name} contains no throw instruction "
                                f"({len(instructions)} instructions total)"
                            ),
                        )
                    ],
                    impact=(
                        "This method never throws, suggesting it accepts any "
                        "certificate/hostname without validation. If used for "
                        "network connections, this defeats TLS server "
                        "authentication and allows man-in-the-middle attacks."
                    ),
                    recommended_validation=[
                        "Intercept the app's TLS traffic with an untrusted/self-signed "
                        "certificate and confirm whether the connection is accepted.",
                    ],
                    remediation=(
                        "Implement real certificate/hostname validation, or remove the "
                        "custom TrustManager/HostnameVerifier and use the platform default."
                    ),
                )
            )
    return findings


def _ssl_error_proceed_findings(analysis: Any) -> list[ApkFinding]:
    findings = []
    for class_analysis in _all_classes(analysis):
        class_name = _class_name(class_analysis)
        for method_analysis in _methods_named(class_analysis, "onReceivedSslError"):
            instructions = list(_instructions(method_analysis))
            if not _calls(instructions, _SSL_ERROR_HANDLER_PROCEED):
                continue
            findings.append(
                ApkFinding(
                    id=f"ANDROID-TLS-SSL-ERROR-PROCEED-{_slug(class_name)}",
                    rule_id="android.webview.ssl_error_proceed",
                    title=f"WebView ignores SSL errors: {class_name}.onReceivedSslError",
                    category="network_security",
                    severity="high",
                    status="confirmed_static_misconfiguration",
                    evidence=[
                        ApkEvidence(
                            artifact_type="dex_code",
                            artifact_path=class_name,
                            location=f"{class_name}->onReceivedSslError",
                            quote="onReceivedSslError calls SslErrorHandler.proceed()",
                        )
                    ],
                    impact=(
                        "This WebViewClient proceeds past TLS certificate errors instead "
                        "of canceling the request, allowing a network-position attacker "
                        "to intercept or tamper with WebView traffic using any certificate."
                    ),
                    recommended_validation=[
                        "Load a page in this WebView over a connection with an "
                        "untrusted/self-signed certificate and confirm it loads anyway.",
                    ],
                    remediation=(
                        "Call handler.cancel() on SSL errors instead of proceed(), or "
                        "remove the onReceivedSslError override entirely."
                    ),
                )
            )
    return findings


def _classes_implementing(analysis: Any, interface_descriptor: str) -> list[Any]:
    matches = []
    for class_analysis in _all_classes(analysis):
        interfaces = _class_interfaces(class_analysis)
        if interface_descriptor in interfaces:
            matches.append(class_analysis)
    return matches


def _all_classes(analysis: Any) -> list[Any]:
    return _safe_call(analysis.get_classes, [])


def _class_interfaces(class_analysis: Any) -> list[Any]:
    return _safe_call(lambda: class_analysis.get_class().get_interfaces(), [])


def _methods_named(class_analysis: Any, method_name: str) -> list[Any]:
    methods: list[Any] = _safe_call(class_analysis.get_methods, [])
    return [
        method_analysis
        for method_analysis in methods
        if _method_name(method_analysis) == method_name
    ]


def _method_name(method_analysis: Any) -> Any:
    return _safe_call(lambda: method_analysis.get_method().get_name(), None)


def _instructions(method_analysis: Any) -> list[Any]:
    return _safe_call(lambda: list(method_analysis.get_method().get_instructions()), [])


def _calls(instructions: list[Any], marker: str) -> bool:
    for instr in instructions:
        name = _safe_call(instr.get_name, "") or ""
        if not name.startswith("invoke"):
            continue
        output = _safe_call(instr.get_output, "") or ""
        if marker in output:
            return True
    return False


def _class_name(class_analysis: Any) -> str:
    return str(_safe_call(lambda: class_analysis.get_class().get_name(), "unknown"))


def _safe_call(fn: Callable[[], T], default: T) -> T:
    try:
        return fn()
    except Exception:
        return default


def _slug(value: str) -> str:
    return "".join(char if char.isalnum() else "-" for char in value).strip("-").upper()
