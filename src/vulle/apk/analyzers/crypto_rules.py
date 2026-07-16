from collections.abc import Callable
from typing import Any, TypeVar

from vulle.apk.models import ApkEvidence, ApkFinding

T = TypeVar("T")

_CIPHER_GET_INSTANCE = "Cipher;->getInstance"
_MESSAGE_DIGEST_GET_INSTANCE = "MessageDigest;->getInstance"
_RANDOM_INIT = "Ljava/util/Random;-><init>"
_WEAK_HASH_ALGORITHMS = ("MD5", "SHA-1", "SHA1")


def evaluate_crypto_rules(analysis: Any) -> list[ApkFinding]:
    findings = []
    for class_analysis in _all_classes(analysis):
        class_name = _class_name(class_analysis)
        methods: list[Any] = _safe_call(class_analysis.get_methods, [])
        for method_analysis in methods:
            method_name = _method_name(method_analysis)
            instructions = _instructions(method_analysis)
            findings.extend(_ecb_findings(class_name, method_name, instructions))
            findings.extend(_weak_hash_findings(class_name, method_name, instructions))
            if _calls(instructions, _RANDOM_INIT):
                findings.append(_weak_random_finding(class_name, method_name))
    return findings


def _ecb_findings(class_name: str, method_name: str, instructions: list[Any]) -> list[ApkFinding]:
    findings = []
    for argument in _invocation_arguments(instructions, _CIPHER_GET_INSTANCE):
        if "ECB" not in argument.upper():
            continue
        findings.append(
            ApkFinding(
                id=f"ANDROID-CRYPTO-ECB-{_slug(class_name)}-{_slug(method_name)}",
                rule_id="android.crypto.ecb_cipher_mode",
                title=f"ECB cipher mode used: {class_name}.{method_name}",
                category="cryptography",
                severity="high",
                status="risk_hypothesis",
                evidence=[
                    _evidence(
                        class_name,
                        f"{class_name}->{method_name}",
                        f"Cipher.getInstance({argument.strip() or '...'})",
                    )
                ],
                impact=(
                    "ECB mode encrypts identical plaintext blocks to identical ciphertext "
                    "blocks, leaking data patterns (e.g. repeated structure in images or "
                    "records) even without breaking the key."
                ),
                recommended_validation=[
                    "Confirm what data is encrypted with this Cipher instance and whether "
                    "predictable/repeating plaintext blocks would be exposed.",
                ],
                remediation="Use an authenticated mode such as AES/GCM/NoPadding instead of ECB.",
            )
        )
    return findings


def _weak_hash_findings(
    class_name: str, method_name: str, instructions: list[Any]
) -> list[ApkFinding]:
    findings = []
    for argument in _invocation_arguments(instructions, _MESSAGE_DIGEST_GET_INSTANCE):
        upper = argument.upper()
        algorithm = next((alg for alg in _WEAK_HASH_ALGORITHMS if alg in upper), None)
        if algorithm is None:
            continue
        findings.append(
            ApkFinding(
                id=f"ANDROID-CRYPTO-WEAK-HASH-{_slug(class_name)}-{_slug(method_name)}",
                rule_id="android.crypto.weak_hash_algorithm",
                title=f"Weak hash algorithm ({algorithm}) used: {class_name}.{method_name}",
                category="cryptography",
                severity="low",
                status="informational",
                evidence=[
                    _evidence(
                        class_name,
                        f"{class_name}->{method_name}",
                        f"MessageDigest.getInstance({argument.strip() or '...'})",
                    )
                ],
                impact=(
                    "MD5/SHA-1 are broken for collision-resistant uses (e.g. password "
                    "hashing, integrity signing). This is low-confidence on its own: the "
                    "same call is also commonly used for non-sensitive purposes like file "
                    "fingerprinting or cache keys, which this static signal cannot "
                    "distinguish."
                ),
                recommended_validation=[
                    "Confirm what this hash is used for; if it protects passwords, "
                    "signatures, or integrity checks, it needs replacing.",
                ],
                remediation=(
                    "Use SHA-256 or stronger for integrity/signing; use a dedicated "
                    "password hash (bcrypt/scrypt/Argon2) for credentials."
                ),
            )
        )
    return findings


def _weak_random_finding(class_name: str, method_name: str) -> ApkFinding:
    return ApkFinding(
        id=f"ANDROID-CRYPTO-WEAK-RANDOM-{_slug(class_name)}-{_slug(method_name)}",
        rule_id="android.crypto.weak_random",
        title=f"java.util.Random used instead of SecureRandom: {class_name}.{method_name}",
        category="cryptography",
        severity="low",
        status="informational",
        evidence=[
            _evidence(
                class_name,
                f"{class_name}->{method_name}",
                "new java.util.Random(...) instead of java.security.SecureRandom",
            )
        ],
        impact=(
            "java.util.Random is not cryptographically secure and is predictable if the "
            "seed or prior output is known. This is only a concern if the generated value "
            "is used for a security-sensitive purpose (tokens, keys, nonces); this static "
            "signal cannot distinguish that from non-sensitive uses (e.g. UI jitter)."
        ),
        recommended_validation=[
            "Confirm what this random value is used for; if it's a token, key, or "
            "nonce, it needs replacing.",
        ],
        remediation="Use java.security.SecureRandom for any security-sensitive random value.",
    )


def _invocation_arguments(instructions: list[Any], marker: str) -> list[str]:
    results = []
    for index, instr in enumerate(instructions):
        name = _safe_call(instr.get_name, "") or ""
        if not name.startswith("invoke"):
            continue
        output = _safe_call(instr.get_output, "") or ""
        if marker not in output:
            continue
        results.append(_preceding_string_argument(instructions, index))
    return results


def _preceding_string_argument(instructions: list[Any], invoke_index: int) -> str:
    for index in range(invoke_index - 1, -1, -1):
        name = _safe_call(instructions[index].get_name, "") or ""
        if name == "const-string":
            return _safe_call(instructions[index].get_output, "") or ""
        if name.startswith("invoke"):
            break
    return ""


def _all_classes(analysis: Any) -> list[Any]:
    return _safe_call(analysis.get_classes, [])


def _method_name(method_analysis: Any) -> Any:
    return _safe_call(lambda: method_analysis.get_method().get_name(), "unknown")


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


def _evidence(artifact_path: str, location: str, quote: str) -> ApkEvidence:
    return ApkEvidence(
        artifact_type="dex_code",
        artifact_path=artifact_path,
        location=location,
        quote=quote,
    )


def _safe_call(fn: Callable[[], T], default: T) -> T:
    try:
        return fn()
    except Exception:
        return default


def _slug(value: str) -> str:
    return "".join(char if char.isalnum() else "-" for char in value).strip("-").upper()
