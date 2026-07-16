from vulle.apk.extractors.manifest import ApplicationAttributes, ManifestFacts
from vulle.apk.models import ApkEvidence, ApkFinding, NetworkSecurityConfigInfo

_MANIFEST_PATH = "AndroidManifest.xml"


def evaluate_manifest_rules(facts: ManifestFacts) -> list[ApkFinding]:
    findings = []
    debuggable = _debuggable_finding(facts.application)
    if debuggable is not None:
        findings.append(debuggable)
    allow_backup = _allow_backup_finding(facts.application)
    if allow_backup is not None:
        findings.append(allow_backup)
    cleartext = _cleartext_finding(
        facts.application,
        facts.network_security_config,
        facts.target_sdk,
    )
    if cleartext is not None:
        findings.append(cleartext)
    test_only = _test_only_finding(facts.application)
    if test_only is not None:
        findings.append(test_only)
    return findings


def _debuggable_finding(app: ApplicationAttributes) -> ApkFinding | None:
    if app.debuggable is not True:
        return None
    return ApkFinding(
        id="ANDROID-MANIFEST-DEBUGGABLE",
        rule_id="android.manifest.debuggable",
        title="Application is debuggable",
        category="platform_configuration",
        severity="high",
        status="confirmed_static_misconfiguration",
        evidence=[_evidence("application/@android:debuggable", 'android:debuggable="true"')],
        impact=(
            "A debuggable build allows attaching a debugger, dumping process memory, and "
            "running arbitrary code with the app's privileges on a rooted or engineering "
            "device, even in a production install."
        ),
        recommended_validation=[
            "Confirm this build is a test/QA artifact, not the production release build.",
            "Attach jdb/Frida to the running app to confirm debugging is actually possible.",
        ],
        remediation="Set android:debuggable=false (or omit it) for release builds.",
    )


def _allow_backup_finding(app: ApplicationAttributes) -> ApkFinding | None:
    if app.allow_backup is False:
        return None
    if app.allow_backup is True:
        quote = 'android:allowBackup="true"'
    else:
        quote = 'android:allowBackup not declared; platform default is "true"'
    return ApkFinding(
        id="ANDROID-MANIFEST-ALLOW-BACKUP",
        rule_id="android.manifest.allow_backup",
        title="Application data backup is permitted",
        category="data_storage",
        severity="medium",
        status="confirmed_static_misconfiguration",
        evidence=[_evidence("application/@android:allowBackup", quote)],
        impact=(
            "Application data may be included in adb backup or device-to-device transfer, "
            "depending on Android version and any backup rules, potentially exposing "
            "locally stored session tokens or sensitive data."
        ),
        recommended_validation=[
            "Run `adb backup` (or a device transfer) against a test install and inspect "
            "the extracted data for sensitive content.",
        ],
        remediation=(
            "Set android:allowBackup=false, or define explicit "
            "android:fullBackupContent / android:dataExtractionRules exclusion rules."
        ),
    )


def _cleartext_finding(
    app: ApplicationAttributes,
    nsc: NetworkSecurityConfigInfo,
    target_sdk: str | None,
) -> ApkFinding | None:
    if app.uses_cleartext_traffic is True:
        return _cleartext_finding_for(
            'android:usesCleartextTraffic="true"',
            "application/@android:usesCleartextTraffic",
        )
    if app.uses_cleartext_traffic is False:
        return None
    if nsc.declared:
        if nsc.parse_error or nsc.cleartext_permitted_default is not True:
            return None
        return _cleartext_finding_for(
            "networkSecurityConfig base-config declares "
            'android:cleartextTrafficPermitted="true"',
            "res/xml network security config/base-config/@android:cleartextTrafficPermitted",
        )
    sdk = _safe_int(target_sdk)
    if sdk is not None and sdk >= 28:
        return None
    return _cleartext_finding_for(
        "android:usesCleartextTraffic not declared and no networkSecurityConfig present; "
        f"targetSdkVersion={target_sdk} defaults to permitting cleartext traffic (Android <9)",
        "application/@android:usesCleartextTraffic",
    )


def _cleartext_finding_for(quote: str, location: str) -> ApkFinding:
    return ApkFinding(
        id="ANDROID-MANIFEST-CLEARTEXT-TRAFFIC",
        rule_id="android.manifest.uses_cleartext_traffic",
        title="Cleartext (unencrypted) network traffic is permitted",
        category="network_security",
        severity="high",
        status="confirmed_static_misconfiguration",
        evidence=[_evidence(location, quote)],
        impact=(
            "Network requests may be sent over unencrypted HTTP, allowing a "
            "network-position attacker to read or tamper with traffic."
        ),
        recommended_validation=[
            "Intercept the app's traffic on an untrusted network and confirm whether "
            "any request is sent over plain HTTP.",
        ],
        remediation=(
            "Set android:usesCleartextTraffic=false and define a networkSecurityConfig "
            "that denies cleartext traffic for all domains actually used by the app."
        ),
    )


def _test_only_finding(app: ApplicationAttributes) -> ApkFinding | None:
    if app.test_only is not True:
        return None
    return ApkFinding(
        id="ANDROID-MANIFEST-TEST-ONLY",
        rule_id="android.manifest.test_only",
        title="Application is marked testOnly",
        category="platform_configuration",
        severity="low",
        status="confirmed_static_misconfiguration",
        evidence=[_evidence("application/@android:testOnly", 'android:testOnly="true"')],
        impact=(
            "A testOnly build should never reach production; its presence suggests this "
            "artifact is a test/QA build rather than the release build intended for "
            "deployment."
        ),
        recommended_validation=[
            "Confirm with the release process which build variant/package this artifact "
            "corresponds to.",
        ],
        remediation="Remove android:testOnly (or ensure it is false) before release builds.",
    )


def _evidence(location: str, quote: str) -> ApkEvidence:
    return ApkEvidence(
        artifact_type="manifest",
        artifact_path=_MANIFEST_PATH,
        location=location,
        quote=quote,
    )


def _safe_int(value: str | None) -> int | None:
    if value is None:
        return None
    try:
        return int(value)
    except ValueError:
        return None
