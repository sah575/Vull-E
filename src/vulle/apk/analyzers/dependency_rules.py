from collections.abc import Callable
from typing import Any, Literal, TypeVar

from vulle.apk.models import SdkFingerprint

T = TypeVar("T")
Confidence = Literal["low", "medium", "high"]

_KNOWN_SDK_PREFIXES: list[tuple[str, str]] = [
    ("com/google/firebase", "Firebase"),
    ("com/google/android/gms", "Google Play Services"),
    ("com/google/mlkit", "Google ML Kit"),
    ("com/huawei/hms", "Huawei HMS"),
    ("com/huawei/agconnect", "Huawei AGConnect"),
    ("com/facebook/react", "React Native"),
    ("com/facebook", "Facebook SDK"),
    ("com/adjust/sdk", "Adjust"),
    ("ly/count/android/sdk", "Countly"),
    ("okhttp3", "OkHttp"),
    ("okio", "Okio"),
    ("androidx/work", "AndroidX WorkManager"),
    ("app/notifee", "Notifee"),
]
_SORTED_PREFIXES = sorted(_KNOWN_SDK_PREFIXES, key=lambda item: len(item[0]), reverse=True)


def evaluate_dependency_fingerprints(analysis: Any) -> list[SdkFingerprint]:
    counts: dict[str, int] = {}
    for class_analysis in _all_classes(analysis):
        internal_path = _internal_path(class_analysis)
        if not internal_path:
            continue
        for prefix, _name in _SORTED_PREFIXES:
            if internal_path == prefix or internal_path.startswith(prefix + "/"):
                counts[prefix] = counts.get(prefix, 0) + 1
                break

    fingerprints = []
    for prefix, name in _KNOWN_SDK_PREFIXES:
        count = counts.get(prefix, 0)
        if count == 0:
            continue
        fingerprints.append(
            SdkFingerprint(
                name=name,
                package_prefix=prefix.replace("/", "."),
                class_count=count,
                confidence=_confidence(count),
            )
        )
    return fingerprints


def _confidence(count: int) -> Confidence:
    if count >= 5:
        return "high"
    if count >= 2:
        return "medium"
    return "low"


def _internal_path(class_analysis: Any) -> str:
    class_name = _class_name(class_analysis)
    if class_name.startswith("L"):
        class_name = class_name[1:]
    return class_name.split(";")[0]


def _all_classes(analysis: Any) -> list[Any]:
    return _safe_call(analysis.get_classes, [])


def _class_name(class_analysis: Any) -> str:
    return str(_safe_call(lambda: class_analysis.get_class().get_name(), ""))


def _safe_call(fn: Callable[[], T], default: T) -> T:
    try:
        return fn()
    except Exception:
        return default
