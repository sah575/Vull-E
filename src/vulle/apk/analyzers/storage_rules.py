from collections.abc import Callable
from typing import Any, TypeVar

from vulle.apk.models import ApkEvidence, ApkFinding

T = TypeVar("T")

_SHARED_PREFERENCES_MARKER = "SharedPreferences;"
_ENCRYPTED_SHARED_PREFERENCES_MARKER = "Landroidx/security/crypto/EncryptedSharedPreferences;"


def evaluate_storage_rules(analysis: Any) -> list[ApkFinding]:
    shared_prefs_classes = []
    uses_encrypted_variant = False
    for class_analysis in _all_classes(analysis):
        class_name = _class_name(class_analysis)
        if class_name == _ENCRYPTED_SHARED_PREFERENCES_MARKER:
            uses_encrypted_variant = True
            continue
        methods: list[Any] = _safe_call(class_analysis.get_methods, [])
        instructions = [instr for method in methods for instr in _instructions(method)]
        if _calls(instructions, _SHARED_PREFERENCES_MARKER):
            shared_prefs_classes.append(class_name)

    if not shared_prefs_classes or uses_encrypted_variant:
        return []

    classes = sorted(set(shared_prefs_classes))
    return [
        ApkFinding(
            id="ANDROID-STORAGE-SHARED-PREFERENCES-UNENCRYPTED",
            rule_id="android.storage.shared_preferences_without_encryption",
            title="SharedPreferences used without EncryptedSharedPreferences anywhere in the app",
            category="data_storage",
            severity="low",
            status="informational",
            evidence=[
                ApkEvidence(
                    artifact_type="dex_code",
                    artifact_path=class_name,
                    location=class_name,
                    quote="class references android.content.SharedPreferences",
                )
                for class_name in classes[:10]
            ],
            impact=(
                "SharedPreferences files are stored as plain XML in app-private storage. "
                "This is only a concern if sensitive data (tokens, PII, credentials) is "
                "stored there; this static signal cannot determine what these classes "
                "actually write to preferences."
            ),
            recommended_validation=[
                "Pull the app's shared_prefs XML files (adb, rooted/debuggable device) "
                "and inspect whether any sensitive values are stored in cleartext.",
            ],
            remediation=(
                "Use androidx.security.crypto.EncryptedSharedPreferences for any "
                "preference file that stores sensitive data."
            ),
        )
    ]


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
