from collections.abc import Callable
from typing import Any, TypeVar

from vulle.apk.models import ApkEvidence, ApkFinding

T = TypeVar("T")

_SET_JAVASCRIPT_ENABLED = "WebSettings;->setJavaScriptEnabled"
_ADD_JAVASCRIPT_INTERFACE = "WebView;->addJavascriptInterface"


def evaluate_webview_rules(analysis: Any) -> list[ApkFinding]:
    findings = []
    for class_analysis in _all_classes(analysis):
        class_name = _class_name(class_analysis)
        methods: list[Any] = _safe_call(class_analysis.get_methods, [])
        instructions = [instr for method in methods for instr in _instructions(method)]
        has_js_enabled = _calls(instructions, _SET_JAVASCRIPT_ENABLED)
        has_js_interface = _calls(instructions, _ADD_JAVASCRIPT_INTERFACE)
        if has_js_interface and has_js_enabled:
            findings.append(_combined_finding(class_name))
        elif has_js_interface:
            findings.append(_interface_only_finding(class_name))
    return findings


def _combined_finding(class_name: str) -> ApkFinding:
    return ApkFinding(
        id=f"ANDROID-WEBVIEW-JS-BRIDGE-{_slug(class_name)}",
        rule_id="android.webview.js_bridge_with_javascript_enabled",
        title=f"WebView JavaScript bridge with JavaScript enabled: {class_name}",
        category="webview",
        severity="high",
        status="risk_hypothesis",
        evidence=[
            ApkEvidence(
                artifact_type="dex_code",
                artifact_path=class_name,
                location=class_name,
                quote=(
                    "class calls both WebSettings.setJavaScriptEnabled and "
                    "WebView.addJavascriptInterface"
                ),
            )
        ],
        impact=(
            "If this WebView can be made to load attacker-influenced content (via a "
            "deep link, Intent extra, or compromised network response), the exposed "
            "JavaScript interface methods may be callable by that content, potentially "
            "leading to local code execution or data access."
        ),
        recommended_validation=[
            "Identify what content this WebView loads and whether any of it is "
            "attacker-influenced (Intent extra, deep link, WebView redirect).",
            "Enumerate the methods exposed via addJavascriptInterface and test calling "
            "them from loaded JavaScript.",
        ],
        remediation=(
            "Restrict addJavascriptInterface to methods that are safe to expose, "
            "only load trusted content in this WebView, and use "
            "WebViewCompat/@JavascriptInterface annotations correctly (API 17+)."
        ),
    )


def _interface_only_finding(class_name: str) -> ApkFinding:
    return ApkFinding(
        id=f"ANDROID-WEBVIEW-JS-INTERFACE-{_slug(class_name)}",
        rule_id="android.webview.js_interface",
        title=f"WebView JavaScript interface exposed: {class_name}",
        category="webview",
        severity="medium",
        status="informational",
        evidence=[
            ApkEvidence(
                artifact_type="dex_code",
                artifact_path=class_name,
                location=class_name,
                quote="class calls WebView.addJavascriptInterface",
            )
        ],
        impact=(
            "A JavaScript interface is exposed to some WebView. Whether this is "
            "reachable by untrusted content depends on what the WebView loads, which "
            "static analysis alone cannot determine."
        ),
        recommended_validation=[
            "Identify which WebView instance this interface is attached to and what "
            "content it loads.",
        ],
        remediation=(
            "Only expose JavaScript interfaces to WebViews that exclusively load "
            "trusted, first-party content."
        ),
    )


def _all_classes(analysis: Any) -> list[Any]:
    return _safe_call(analysis.get_classes, [])


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
