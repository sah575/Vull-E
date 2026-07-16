from vulle.apk.models import ApkEvidence, ApkFinding, NativeLibraryInfo

_ZIP_PATH = "zip_entry"


def evaluate_native_rules(native_libraries: list[NativeLibraryInfo]) -> list[ApkFinding]:
    findings = []
    for library in native_libraries:
        if library.parse_error is not None:
            continue
        if library.nx_enabled is False:
            findings.append(_nx_disabled_finding(library))
        if library.relro == "none":
            findings.append(_relro_missing_finding(library))
    return findings


def _nx_disabled_finding(library: NativeLibraryInfo) -> ApkFinding:
    return ApkFinding(
        id=f"ANDROID-NATIVE-NX-DISABLED-{_slug(library.path)}",
        rule_id="android.native.nx_disabled",
        title=f"Native library has an executable stack (NX disabled): {library.path}",
        category="native_library",
        severity="medium",
        status="risk_hypothesis",
        evidence=[
            ApkEvidence(
                artifact_type="zip_entry",
                artifact_path=library.path,
                location=f"{library.path} (PT_GNU_STACK)",
                quote="PT_GNU_STACK segment is executable (PF_X set)",
            )
        ],
        impact=(
            "An executable stack removes one mitigation against stack-based buffer "
            "overflow exploitation in this native library, making stack-smashing "
            "exploits easier to weaponize if a memory-corruption bug exists."
        ),
        recommended_validation=[
            "Confirm whether this library is a third-party prebuilt binary (often not "
            "rebuildable) or part of the app's own native code (should be fixed).",
        ],
        remediation=(
            "Rebuild with a modern NDK/toolchain default (NX stack) if source is available."
        ),
    )


def _relro_missing_finding(library: NativeLibraryInfo) -> ApkFinding:
    return ApkFinding(
        id=f"ANDROID-NATIVE-RELRO-MISSING-{_slug(library.path)}",
        rule_id="android.native.relro_missing",
        title=f"Native library has no RELRO: {library.path}",
        category="native_library",
        severity="low",
        status="informational",
        evidence=[
            ApkEvidence(
                artifact_type="zip_entry",
                artifact_path=library.path,
                location=library.path,
                quote="no PT_GNU_RELRO segment present",
            )
        ],
        impact=(
            "Without RELRO, the GOT/PLT sections remain writable at runtime, which "
            "widens the set of usable primitives if a memory-corruption bug is later "
            "found in this library. Modern NDK toolchains enable at least partial "
            "RELRO by default, so its absence here may indicate an older build."
        ),
        recommended_validation=[
            "Confirm whether this is a third-party prebuilt library and whether an "
            "updated build with RELRO is available.",
        ],
        remediation="Rebuild with a modern NDK/toolchain default (at least partial RELRO).",
    )


def _slug(value: str) -> str:
    return "".join(char if char.isalnum() else "-" for char in value).strip("-").upper()
