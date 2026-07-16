from collections.abc import Callable
from typing import Any, TypeVar

from vulle.apk.models import ApkEvidence, ApkFinding

T = TypeVar("T")

_SET_JAVASCRIPT_ENABLED = "WebSettings;->setJavaScriptEnabled"
_ADD_JAVASCRIPT_INTERFACE = "WebView;->addJavascriptInterface"
_SET_MIXED_CONTENT_MODE = "WebSettings;->setMixedContentMode"
_SET_ALLOW_UNIVERSAL_FILE_ACCESS = "WebSettings;->setAllowUniversalAccessFromFileURLs"
_SET_WEB_CONTENTS_DEBUGGING = "WebView;->setWebContentsDebuggingEnabled"


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
        if _calls(instructions, _SET_MIXED_CONTENT_MODE):
            findings.append(_mixed_content_finding(class_name))
        if _calls(instructions, _SET_ALLOW_UNIVERSAL_FILE_ACCESS):
            findings.append(_universal_file_access_finding(class_name))
        if _calls(instructions, _SET_WEB_CONTENTS_DEBUGGING):
            findings.append(_web_contents_debugging_finding(class_name))
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


def _mixed_content_finding(class_name: str) -> ApkFinding:
    return ApkFinding(
        id=f"ANDROID-WEBVIEW-MIXED-CONTENT-{_slug(class_name)}",
        rule_id="android.webview.mixed_content_mode",
        title=f"WebView sets a mixed-content mode: {class_name}",
        category="webview",
        severity="medium",
        status="informational",
        evidence=[
            ApkEvidence(
                artifact_type="dex_code",
                artifact_path=class_name,
                location=class_name,
                quote="class calls WebSettings.setMixedContentMode",
            )
        ],
        impact=(
            "This static signal cannot confirm the mode value passed. If set to "
            "MIXED_CONTENT_ALWAYS_ALLOW, an HTTPS page in this WebView could load "
            "HTTP subresources, letting a network attacker tamper with page content."
        ),
        recommended_validation=[
            "Check the actual argument passed to setMixedContentMode in the "
            "decompiled source.",
            "Load an HTTPS page with an HTTP subresource in this WebView and "
            "confirm whether it is blocked.",
        ],
        remediation="Use MIXED_CONTENT_NEVER_ALLOW unless there is a specific, reviewed need.",
    )


def _universal_file_access_finding(class_name: str) -> ApkFinding:
    return ApkFinding(
        id=f"ANDROID-WEBVIEW-UNIVERSAL-FILE-ACCESS-{_slug(class_name)}",
        rule_id="android.webview.universal_file_access",
        title=f"WebView allows universal access from file URLs: {class_name}",
        category="webview",
        severity="high",
        status="risk_hypothesis",
        evidence=[
            ApkEvidence(
                artifact_type="dex_code",
                artifact_path=class_name,
                location=class_name,
                quote="class calls WebSettings.setAllowUniversalAccessFromFileURLs",
            )
        ],
        impact=(
            "If enabled (true), content loaded from a file:// URL can access content "
            "from any origin, including other local files and, combined with a "
            "JavaScript interface, potentially cross-origin web content."
        ),
        recommended_validation=[
            "Check the actual argument passed and whether this WebView ever loads "
            "file:// URLs from an untrusted or attacker-influenced path.",
        ],
        remediation=(
            "Set setAllowUniversalAccessFromFileURLs(false) unless a specific, "
            "reviewed need exists."
        ),
    )


def _web_contents_debugging_finding(class_name: str) -> ApkFinding:
    return ApkFinding(
        id=f"ANDROID-WEBVIEW-DEBUGGING-{_slug(class_name)}",
        rule_id="android.webview.debugging_enabled",
        title=f"WebView content debugging is enabled: {class_name}",
        category="webview",
        severity="low",
        status="informational",
        evidence=[
            ApkEvidence(
                artifact_type="dex_code",
                artifact_path=class_name,
                location=class_name,
                quote="class calls WebView.setWebContentsDebuggingEnabled",
            )
        ],
        impact=(
            "If enabled in a production build, this WebView's content can be "
            "inspected/debugged via Chrome DevTools by anyone with a USB/adb "
            "connection to the device, similar in spirit to android:debuggable."
        ),
        recommended_validation=[
            "Confirm this build variant is test/QA and not the production release.",
        ],
        remediation="Only call setWebContentsDebuggingEnabled(true) in debug builds.",
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
