from collections import defaultdict

from vulle.apk.extractors.manifest import ManifestFacts
from vulle.apk.models import ApkEvidence, ApkFinding, ComponentInfo, DeepLinkInfo, SignatureInfo

_MANIFEST_PATH = "AndroidManifest.xml"
_MAIN_ACTION = "android.intent.action.MAIN"
_LAUNCHER_CATEGORY = "android.intent.category.LAUNCHER"


def evaluate_component_rules(facts: ManifestFacts) -> list[ApkFinding]:
    findings = []
    for component in facts.components:
        if component.component_type == "provider":
            findings.extend(_provider_findings(component))
        else:
            findings.extend(_exported_component_findings(component))
    findings.extend(_deep_link_findings(facts.deep_links))
    findings.extend(_deep_link_collision_findings(facts.deep_links))
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
    if _is_launcher_entry_point(component):
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
    broad_links = [
        link
        for link in deep_links
        if not link.auto_verify and (not link.host or link.host == "*")
    ]
    grouped: dict[tuple[str | None, str | None], list[str]] = defaultdict(list)
    for link in broad_links:
        grouped[(link.scheme, link.host)].append(link.component_class)

    findings = []
    for (scheme, host), component_classes in grouped.items():
        components = sorted(set(component_classes))
        title = f"Deep link without domain verification: {scheme}://{host or '*'}"
        if len(components) > 1:
            title += f" (declared on {len(components)} components, e.g. {components[0]})"
        else:
            title += f" on {components[0]}"
        slug_source = f"{scheme}-{host or 'wildcard'}"
        findings.append(
            ApkFinding(
                id=f"ANDROID-DEEPLINK-BROAD-{_slug(slug_source)}",
                rule_id="android.manifest.broad_deep_link",
                title=title,
                category="deep_link",
                severity="medium",
                status="risk_hypothesis",
                evidence=[
                    ApkEvidence(
                        artifact_type="manifest",
                        artifact_path=_MANIFEST_PATH,
                        location=f"{component}/intent-filter/data",
                        quote=f'android:scheme="{scheme}" android:host="{host or "*"}"',
                    )
                    for component in components
                ],
                impact=(
                    "Without android:autoVerify and App Links domain verification, any "
                    "app can register the same scheme/host and receive URLs intended for "
                    "these components, or the components may accept URLs from unexpected "
                    "hosts."
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


def _deep_link_collision_findings(deep_links: list[DeepLinkInfo]) -> list[ApkFinding]:
    specific_links = [link for link in deep_links if link.host and link.host != "*"]
    grouped: dict[tuple[str | None, str], list[str]] = defaultdict(list)
    for link in specific_links:
        if link.host is None:
            continue
        grouped[(link.scheme, link.host)].append(link.component_class)

    findings = []
    for (scheme, host), component_classes in grouped.items():
        components = sorted(set(component_classes))
        if len(components) < 2:
            continue
        slug_source = f"{scheme}-{host}"
        findings.append(
            ApkFinding(
                id=f"ANDROID-DEEPLINK-COLLISION-{_slug(slug_source)}",
                rule_id="android.manifest.deep_link_collision",
                title=(
                    f"Multiple components claim the same deep link: {scheme}://{host} "
                    f"({len(components)} components)"
                ),
                category="deep_link",
                severity="medium",
                status="risk_hypothesis",
                evidence=[
                    ApkEvidence(
                        artifact_type="manifest",
                        artifact_path=_MANIFEST_PATH,
                        location=f"{component}/intent-filter/data",
                        quote=f'android:scheme="{scheme}" android:host="{host}"',
                    )
                    for component in components
                ],
                impact=(
                    "More than one component in this app declares an intent filter for "
                    "the same scheme/host. Depending on priority/order and autoVerify "
                    "status, this can cause ambiguous resolution or let one component "
                    "unexpectedly intercept URLs intended for another."
                ),
                recommended_validation=[
                    f"Send a VIEW intent for {scheme}://{host} and confirm which of the "
                    "listed components actually handles it.",
                ],
                remediation=(
                    "Ensure only the intended component declares this scheme/host, or "
                    "differentiate them with distinct paths and android:autoVerify."
                ),
            )
        )
    return findings


def _is_launcher_entry_point(component: ComponentInfo) -> bool:
    return any(
        set(intent_filter.actions) == {_MAIN_ACTION}
        and set(intent_filter.categories) == {_LAUNCHER_CATEGORY}
        for intent_filter in component.intent_filters
    )


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
