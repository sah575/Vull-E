from vulle.apk.extractors.manifest import ManifestFacts
from vulle.apk.models import ApkEvidence, ApkFinding, ComponentInfo, DeepLinkInfo, SignatureInfo

_MANIFEST_PATH = "AndroidManifest.xml"


def evaluate_component_rules(facts: ManifestFacts) -> list[ApkFinding]:
    findings = []
    for component in facts.components:
        if component.component_type == "provider":
            findings.extend(_provider_findings(component))
        else:
            findings.extend(_exported_component_findings(component))
    findings.extend(_deep_link_findings(facts.deep_links))
    return findings


def evaluate_signature_rules(signature: SignatureInfo) -> list[ApkFinding]:
    findings = []
    for certificate in signature.certificates:
        if not certificate.is_debug_cert:
            continue
        findings.append(
            ApkFinding(
                id="ANDROID-CERT-DEBUG-SIGNER",
                rule_id="android.certificate.debug_signer",
                title="APK is signed with an Android debug certificate",
                category="build_configuration",
                severity="info",
                status="informational",
                evidence=[
                    ApkEvidence(
                        artifact_type="certificate",
                        artifact_path="META-INF signature",
                        location="signer/subject",
                        quote=str(certificate.subject),
                    )
                ],
                impact=(
                    "A debug-signed APK is expected for test/QA builds but must never be "
                    "the artifact deployed to production, since the debug key is shared "
                    "across development machines."
                ),
                recommended_validation=[
                    "Confirm with the release process that this build is a test/QA "
                    "artifact and not the production release build.",
                ],
                remediation="Sign production releases with the bank's production signing key.",
            )
        )
    return findings


def _exported_component_findings(component: ComponentInfo) -> list[ApkFinding]:
    if not component.exported or component.permission:
        return []
    return [
        ApkFinding(
            id=f"ANDROID-COMPONENT-EXPORTED-{_slug(component.class_name)}",
            rule_id="android.component.exported_without_permission",
            title=f"Exported {component.component_type} without a permission requirement: "
            f"{component.class_name}",
            category="component_security",
            severity="medium",
            status="risk_hypothesis",
            evidence=[_component_evidence(component)],
            impact=(
                "Any other application on the device can start or bind to this component "
                "without holding any permission, which may allow triggering unintended "
                "behavior or reaching sensitive functionality."
            ),
            recommended_validation=[
                f"Attempt to launch/bind to {component.class_name} from an unprivileged "
                "test app or adb shell and observe whether the action succeeds.",
            ],
            remediation=(
                "Set android:exported=false if the component is not meant to be used by "
                "other apps, or require a signature/custom permission if it must be exported."
            ),
        )
    ]


def _provider_findings(component: ComponentInfo) -> list[ApkFinding]:
    if not component.exported:
        return []
    if component.permission or component.read_permission or component.write_permission:
        return []
    return [
        ApkFinding(
            id=f"ANDROID-PROVIDER-EXPORTED-{_slug(component.class_name)}",
            rule_id="android.component.exported_provider_without_permission",
            title=f"Exported content provider without any permission: {component.class_name}",
            category="component_security",
            severity="high",
            status="risk_hypothesis",
            evidence=[_component_evidence(component)],
            impact=(
                "Any other application on the device can query, insert, update, or delete "
                "data through this content provider without any permission check, which may "
                "expose sensitive data or allow SQL injection through unsanitized "
                "projection/selection arguments."
            ),
            recommended_validation=[
                f"Query {component.class_name}'s authorities from an unprivileged test app "
                "or adb shell content query and inspect the returned data.",
            ],
            remediation=(
                "Set android:exported=false if the provider is not meant to be used by "
                "other apps, or require a permission for read/write access."
            ),
        )
    ]


def _deep_link_findings(deep_links: list[DeepLinkInfo]) -> list[ApkFinding]:
    findings = []
    for link in deep_links:
        if link.auto_verify:
            continue
        if link.host and link.host != "*":
            continue
        findings.append(
            ApkFinding(
                id=f"ANDROID-DEEPLINK-BROAD-{_slug(link.component_class)}",
                rule_id="android.manifest.broad_deep_link",
                title=(
                    f"Deep link without domain verification: {link.scheme}://"
                    f"{link.host or '*'} on {link.component_class}"
                ),
                category="deep_link",
                severity="medium",
                status="risk_hypothesis",
                evidence=[
                    ApkEvidence(
                        artifact_type="manifest",
                        artifact_path=_MANIFEST_PATH,
                        location=f"{link.component_class}/intent-filter/data",
                        quote=f'android:scheme="{link.scheme}" android:host="{link.host or "*"}"',
                    )
                ],
                impact=(
                    "Without android:autoVerify and App Links domain verification, any "
                    "app can register the same scheme/host and receive URLs intended for "
                    "this activity, or the activity may accept URLs from unexpected hosts."
                ),
                recommended_validation=[
                    "Send an implicit VIEW intent for this scheme/host from another app "
                    "and confirm which app the user is offered to open it with.",
                ],
                remediation=(
                    "Restrict the intent filter to a specific host, and enable "
                    "android:autoVerify with a matching assetlinks.json for App Links."
                ),
            )
        )
    return findings


def _component_evidence(component: ComponentInfo) -> ApkEvidence:
    exported_source = "explicit" if component.exported_explicit else "implicit (has intent-filter)"
    return ApkEvidence(
        artifact_type="manifest",
        artifact_path=_MANIFEST_PATH,
        location=f"{component.component_type}[@android:name='{component.class_name}']",
        quote=f"exported={component.exported} ({exported_source}), permission=none",
    )


def _slug(value: str) -> str:
    return "".join(char if char.isalnum() else "-" for char in value).strip("-").upper()
