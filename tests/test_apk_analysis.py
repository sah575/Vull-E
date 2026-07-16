import builtins
import struct
import time
import xml.etree.ElementTree as ET
import zipfile
from datetime import datetime
from pathlib import Path
from typing import Any

import pytest

from vulle.apk.analyzers.component_rules import evaluate_component_rules, evaluate_signature_rules
from vulle.apk.analyzers.crypto_rules import evaluate_crypto_rules
from vulle.apk.analyzers.dependency_rules import evaluate_dependency_fingerprints
from vulle.apk.analyzers.manifest_rules import evaluate_manifest_rules
from vulle.apk.analyzers.native_rules import evaluate_native_rules
from vulle.apk.analyzers.secret_rules import evaluate_secret_rules, extract_network_endpoints
from vulle.apk.analyzers.storage_rules import evaluate_storage_rules
from vulle.apk.analyzers.tls_rules import evaluate_tls_rules
from vulle.apk.analyzers.webview_rules import evaluate_webview_rules
from vulle.apk.extractors.certificates import extract_signature_info
from vulle.apk.extractors.manifest import (
    ApplicationAttributes,
    ManifestFacts,
    extract_manifest_facts,
    load_apk,
)
from vulle.apk.models import (
    CertificateInfo,
    ComponentInfo,
    DeepLinkInfo,
    IntentFilterInfo,
    NativeLibraryInfo,
    NetworkSecurityConfigInfo,
    SignatureInfo,
)
from vulle.apk.pipeline import analyze_apk_static
from vulle.errors import VulleError


class FakeApk:
    def __init__(
        self,
        *,
        package: str = "com.example.app",
        version_name: str = "1.0",
        version_code: str = "1",
        min_sdk: str = "21",
        target_sdk: str = "34",
        permissions: list[str] | None = None,
        declared_permissions: dict[str, dict[str, str]] | None = None,
        tags: dict[str, list[Any]] | None = None,
        certificates: list[Any] | None = None,
        signed: tuple[bool, bool, bool] = (True, True, False),
        resources: Any = None,
        files: dict[str, bytes] | None = None,
    ) -> None:
        self._package = package
        self._version_name = version_name
        self._version_code = version_code
        self._min_sdk = min_sdk
        self._target_sdk = target_sdk
        self._permissions = permissions or []
        self._declared_permissions = declared_permissions or {}
        self._tags = tags or {}
        self._certificates = certificates or []
        self._signed = signed
        self._resources = resources
        self._files = files or {}

    def get_package(self) -> str:
        return self._package

    def get_androidversion_name(self) -> str:
        return self._version_name

    def get_androidversion_code(self) -> str:
        return self._version_code

    def get_min_sdk_version(self) -> str:
        return self._min_sdk

    def get_target_sdk_version(self) -> str:
        return self._target_sdk

    def get_permissions(self) -> list[str]:
        return self._permissions

    def get_declared_permissions_details(self) -> dict[str, dict[str, str]]:
        return self._declared_permissions

    def find_tags(self, tag_name: str) -> list[Any]:
        return self._tags.get(tag_name, [])

    def get_value_from_tag(self, tag: Any, attribute: str) -> str | None:
        return tag.get(attribute)

    def get_certificates(self) -> list[Any]:
        return self._certificates

    def is_signed_v1(self) -> bool:
        return self._signed[0]

    def is_signed_v2(self) -> bool:
        return self._signed[1]

    def is_signed_v3(self) -> bool:
        return self._signed[2]

    def get_android_resources(self) -> Any:
        return self._resources

    def get_file(self, filename: str) -> bytes:
        return self._files[filename]


def _element(tag: str, attrib: dict[str, str] | None = None) -> ET.Element:
    return ET.Element(tag, attrib or {})


def _application_tag(**attrib: str) -> ET.Element:
    return _element("application", attrib)


def _activity_tag(
    *,
    name: str,
    intent_filters: list[ET.Element] | None = None,
    **attrib: str,
) -> ET.Element:
    element = _element("activity", {"name": name, **attrib})
    for intent_filter in intent_filters or []:
        element.append(intent_filter)
    return element


def _intent_filter(
    *,
    actions: list[str] | None = None,
    categories: list[str] | None = None,
    data: list[dict[str, str]] | None = None,
    auto_verify: str | None = None,
) -> ET.Element:
    attrib = {"autoVerify": auto_verify} if auto_verify is not None else {}
    element = _element("intent-filter", attrib)
    for action in actions or []:
        element.append(_element("action", {"name": action}))
    for category in categories or []:
        element.append(_element("category", {"name": category}))
    for data_attrs in data or []:
        element.append(_element("data", data_attrs))
    return element


# ---------------------------------------------------------------------------
# extractors/manifest.py
# ---------------------------------------------------------------------------


def test_extract_manifest_facts_reads_basic_metadata() -> None:
    apk = FakeApk(package="com.example.testbank", version_name="2.3.1", version_code="42")

    facts = extract_manifest_facts(apk)

    assert facts.package_name == "com.example.testbank"
    assert facts.version_name == "2.3.1"
    assert facts.version_code == "42"


def test_custom_permissions_are_mapped_with_protection_level() -> None:
    apk = FakeApk(
        declared_permissions={
            "com.example.CUSTOM": {"protectionLevel": "signature", "label": "Custom"},
        }
    )

    facts = extract_manifest_facts(apk)

    assert len(facts.custom_permissions) == 1
    assert facts.custom_permissions[0].name == "com.example.CUSTOM"
    assert facts.custom_permissions[0].protection_level == "signature"


def test_custom_permission_protection_level_hex_is_decoded_to_name() -> None:
    apk = FakeApk(
        declared_permissions={
            "com.example.CUSTOM": {"protectionLevel": "0x00000002"},
        }
    )

    facts = extract_manifest_facts(apk)

    assert facts.custom_permissions[0].protection_level == "signature"


def test_custom_permission_protection_level_unknown_hex_passes_through() -> None:
    apk = FakeApk(
        declared_permissions={
            "com.example.CUSTOM": {"protectionLevel": "not-a-number"},
        }
    )

    facts = extract_manifest_facts(apk)

    assert facts.custom_permissions[0].protection_level == "not-a-number"


def test_application_attributes_are_parsed() -> None:
    apk = FakeApk(
        tags={
            "application": [
                _application_tag(
                    debuggable="true",
                    allowBackup="false",
                    usesCleartextTraffic="true",
                    testOnly="true",
                )
            ]
        }
    )

    facts = extract_manifest_facts(apk)

    assert facts.application.debuggable is True
    assert facts.application.allow_backup is False
    assert facts.application.uses_cleartext_traffic is True
    assert facts.application.test_only is True


def test_application_attributes_default_to_none_when_undeclared() -> None:
    apk = FakeApk(tags={"application": [_application_tag()]})

    facts = extract_manifest_facts(apk)

    assert facts.application.debuggable is None
    assert facts.application.allow_backup is None


def test_application_attributes_include_legacy_storage_and_extract_native_libs() -> None:
    apk = FakeApk(
        tags={
            "application": [
                _application_tag(
                    requestLegacyExternalStorage="true",
                    extractNativeLibs="false",
                )
            ]
        }
    )

    facts = extract_manifest_facts(apk)

    assert facts.application.request_legacy_external_storage is True
    assert facts.application.extract_native_libs is False


def test_shared_user_id_is_extracted_from_manifest_root() -> None:
    apk = FakeApk(
        tags={
            "manifest": [_element("manifest", {"sharedUserId": "com.example.uid"})],
            "application": [_application_tag()],
        }
    )

    facts = extract_manifest_facts(apk)

    assert facts.application.shared_user_id == "com.example.uid"


def test_shared_user_id_is_none_when_not_declared() -> None:
    apk = FakeApk(tags={"application": [_application_tag()]})

    facts = extract_manifest_facts(apk)

    assert facts.application.shared_user_id is None


def test_component_process_and_direct_boot_aware_are_extracted() -> None:
    apk = FakeApk(
        tags={
            "activity": [
                _activity_tag(
                    name="com.example.Activity",
                    process=":remote",
                    directBootAware="true",
                )
            ]
        }
    )

    facts = extract_manifest_facts(apk)

    assert facts.components[0].process == ":remote"
    assert facts.components[0].direct_boot_aware is True


def test_explicit_exported_true_is_respected_even_without_intent_filter() -> None:
    apk = FakeApk(tags={"activity": [_activity_tag(name="com.example.Explicit", exported="true")]})

    facts = extract_manifest_facts(apk)

    component = facts.components[0]
    assert component.exported is True
    assert component.exported_explicit is True


def test_explicit_exported_false_is_respected_even_with_intent_filter() -> None:
    apk = FakeApk(
        tags={
            "activity": [
                _activity_tag(
                    name="com.example.ExplicitFalse",
                    exported="false",
                    intent_filters=[_intent_filter(actions=["android.intent.action.VIEW"])],
                )
            ]
        }
    )

    facts = extract_manifest_facts(apk)

    component = facts.components[0]
    assert component.exported is False
    assert component.exported_explicit is True


def test_implicit_export_true_when_intent_filter_present_without_explicit_flag() -> None:
    apk = FakeApk(
        tags={
            "activity": [
                _activity_tag(
                    name="com.example.Implicit",
                    intent_filters=[_intent_filter(actions=["android.intent.action.VIEW"])],
                )
            ]
        }
    )

    facts = extract_manifest_facts(apk)

    component = facts.components[0]
    assert component.exported is True
    assert component.exported_explicit is False


def test_implicit_export_false_when_no_intent_filter_and_no_explicit_flag() -> None:
    apk = FakeApk(tags={"activity": [_activity_tag(name="com.example.Plain")]})

    facts = extract_manifest_facts(apk)

    component = facts.components[0]
    assert component.exported is False
    assert component.exported_explicit is False


def test_provider_authorities_are_split_on_semicolon() -> None:
    apk = FakeApk(
        tags={
            "provider": [
                _element(
                    "provider",
                    {"name": "com.example.Provider", "authorities": "a.b.c;d.e.f"},
                )
            ]
        }
    )

    facts = extract_manifest_facts(apk)

    assert facts.components[0].authorities == ["a.b.c", "d.e.f"]


def test_deep_link_is_derived_from_browsable_view_intent_filter() -> None:
    apk = FakeApk(
        tags={
            "activity": [
                _activity_tag(
                    name="com.example.DeepLinkActivity",
                    intent_filters=[
                        _intent_filter(
                            actions=["android.intent.action.VIEW"],
                            categories=["android.intent.category.BROWSABLE"],
                            data=[{"scheme": "https", "host": "bank.example.com"}],
                            auto_verify="true",
                        )
                    ],
                )
            ]
        }
    )

    facts = extract_manifest_facts(apk)

    assert len(facts.deep_links) == 1
    link = facts.deep_links[0]
    assert link.scheme == "https"
    assert link.host == "bank.example.com"
    assert link.auto_verify is True
    assert link.component_class == "com.example.DeepLinkActivity"


def test_non_browsable_intent_filter_does_not_produce_deep_link() -> None:
    apk = FakeApk(
        tags={
            "activity": [
                _activity_tag(
                    name="com.example.Plain",
                    intent_filters=[_intent_filter(actions=["android.intent.action.MAIN"])],
                )
            ]
        }
    )

    facts = extract_manifest_facts(apk)

    assert facts.deep_links == []


def test_network_security_config_not_declared_when_attribute_absent() -> None:
    apk = FakeApk(tags={"application": [_application_tag()]})

    facts = extract_manifest_facts(apk)

    assert facts.network_security_config.declared is False


def test_network_security_config_records_parse_error_when_unresolvable() -> None:
    apk = FakeApk(
        tags={
            "application": [
                _application_tag(networkSecurityConfig="@xml/network_security_config")
            ]
        },
        resources=None,
    )

    facts = extract_manifest_facts(apk)

    assert facts.network_security_config.declared is True
    assert facts.network_security_config.parse_error is not None


def test_load_apk_raises_clear_error_when_androguard_is_missing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    real_import = builtins.__import__

    def fake_import(name: str, *args: Any, **kwargs: Any) -> Any:
        if name == "androguard.core.apk":
            raise ImportError("simulated missing dependency")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", fake_import)

    with pytest.raises(VulleError, match="androguard is required"):
        load_apk(tmp_path / "sample.apk")


# ---------------------------------------------------------------------------
# extractors/certificates.py
# ---------------------------------------------------------------------------


class FakeName:
    def __init__(self, human_friendly: str) -> None:
        self.human_friendly = human_friendly


class FakeCertificate:
    def __init__(
        self,
        *,
        subject: str,
        issuer: str,
        sha256_fingerprint: str = "AB:CD",
        not_valid_before: datetime | None = None,
        not_valid_after: datetime | None = None,
    ) -> None:
        self.subject = FakeName(subject)
        self.issuer = FakeName(issuer)
        self.sha256_fingerprint = sha256_fingerprint
        self.not_valid_before = not_valid_before or datetime(2024, 1, 1)
        self.not_valid_after = not_valid_after or datetime(2034, 1, 1)


def test_extract_signature_info_flags_debug_certificate() -> None:
    apk = FakeApk(
        certificates=[
            FakeCertificate(
                subject="C=US, O=Android, CN=Android Debug",
                issuer="C=US, O=Android, CN=Android Debug",
            )
        ],
        signed=(True, False, False),
    )

    signature = extract_signature_info(apk)

    assert signature.signed_v1 is True
    assert signature.signed_v2 is False
    assert signature.signer_count == 1
    assert signature.certificates[0].is_debug_cert is True


def test_extract_signature_info_does_not_flag_production_certificate() -> None:
    apk = FakeApk(
        certificates=[
            FakeCertificate(subject="CN=Example Bank Production", issuer="CN=Example Bank CA")
        ]
    )

    signature = extract_signature_info(apk)

    assert signature.certificates[0].is_debug_cert is False


# ---------------------------------------------------------------------------
# analyzers/manifest_rules.py
# ---------------------------------------------------------------------------


def test_debuggable_true_is_flagged() -> None:
    facts = ManifestFacts(application=ApplicationAttributes(debuggable=True))

    findings = evaluate_manifest_rules(facts)

    assert any(f.id == "ANDROID-MANIFEST-DEBUGGABLE" for f in findings)


def test_debuggable_false_is_not_flagged() -> None:
    facts = ManifestFacts(application=ApplicationAttributes(debuggable=False))

    findings = evaluate_manifest_rules(facts)

    assert not any(f.id == "ANDROID-MANIFEST-DEBUGGABLE" for f in findings)


def test_allow_backup_unset_defaults_to_flagged() -> None:
    facts = ManifestFacts(application=ApplicationAttributes())

    findings = evaluate_manifest_rules(facts)

    assert any(f.id == "ANDROID-MANIFEST-ALLOW-BACKUP" for f in findings)


def test_allow_backup_explicit_false_is_not_flagged() -> None:
    facts = ManifestFacts(application=ApplicationAttributes(allow_backup=False))

    findings = evaluate_manifest_rules(facts)

    assert not any(f.id == "ANDROID-MANIFEST-ALLOW-BACKUP" for f in findings)


def test_cleartext_explicit_true_is_flagged() -> None:
    facts = ManifestFacts(application=ApplicationAttributes(uses_cleartext_traffic=True))

    findings = evaluate_manifest_rules(facts)

    assert any(f.id == "ANDROID-MANIFEST-CLEARTEXT-TRAFFIC" for f in findings)


def test_cleartext_explicit_false_is_not_flagged_even_with_low_target_sdk() -> None:
    facts = ManifestFacts(
        application=ApplicationAttributes(uses_cleartext_traffic=False),
        target_sdk="19",
    )

    findings = evaluate_manifest_rules(facts)

    assert not any(f.id == "ANDROID-MANIFEST-CLEARTEXT-TRAFFIC" for f in findings)


def test_cleartext_defaults_to_flagged_on_old_target_sdk_without_nsc() -> None:
    facts = ManifestFacts(application=ApplicationAttributes(), target_sdk="21")

    findings = evaluate_manifest_rules(facts)

    assert any(f.id == "ANDROID-MANIFEST-CLEARTEXT-TRAFFIC" for f in findings)


def test_cleartext_not_flagged_on_modern_target_sdk_without_nsc() -> None:
    facts = ManifestFacts(application=ApplicationAttributes(), target_sdk="34")

    findings = evaluate_manifest_rules(facts)

    assert not any(f.id == "ANDROID-MANIFEST-CLEARTEXT-TRAFFIC" for f in findings)


def test_cleartext_flagged_when_nsc_base_config_permits_it() -> None:
    facts = ManifestFacts(
        application=ApplicationAttributes(),
        target_sdk="34",
        network_security_config=NetworkSecurityConfigInfo(
            declared=True, cleartext_permitted_default=True
        ),
    )

    findings = evaluate_manifest_rules(facts)

    assert any(f.id == "ANDROID-MANIFEST-CLEARTEXT-TRAFFIC" for f in findings)


def test_cleartext_not_flagged_when_nsc_parse_failed() -> None:
    facts = ManifestFacts(
        application=ApplicationAttributes(),
        target_sdk="21",
        network_security_config=NetworkSecurityConfigInfo(
            declared=True, parse_error="boom"
        ),
    )

    findings = evaluate_manifest_rules(facts)

    assert not any(f.id == "ANDROID-MANIFEST-CLEARTEXT-TRAFFIC" for f in findings)


def test_test_only_true_is_flagged() -> None:
    facts = ManifestFacts(application=ApplicationAttributes(test_only=True))

    findings = evaluate_manifest_rules(facts)

    assert any(f.id == "ANDROID-MANIFEST-TEST-ONLY" for f in findings)


def test_legacy_external_storage_true_is_flagged() -> None:
    facts = ManifestFacts(
        application=ApplicationAttributes(request_legacy_external_storage=True)
    )

    findings = evaluate_manifest_rules(facts)

    assert any(f.id == "ANDROID-MANIFEST-LEGACY-EXTERNAL-STORAGE" for f in findings)


def test_legacy_external_storage_unset_is_not_flagged() -> None:
    facts = ManifestFacts(application=ApplicationAttributes())

    findings = evaluate_manifest_rules(facts)

    assert not any(f.id == "ANDROID-MANIFEST-LEGACY-EXTERNAL-STORAGE" for f in findings)


def test_shared_user_id_declared_is_flagged_informational() -> None:
    facts = ManifestFacts(application=ApplicationAttributes(shared_user_id="com.example.uid"))

    findings = evaluate_manifest_rules(facts)

    assert any(
        f.id == "ANDROID-MANIFEST-SHARED-USER-ID" and f.status == "informational"
        for f in findings
    )


def test_shared_user_id_unset_is_not_flagged() -> None:
    facts = ManifestFacts(application=ApplicationAttributes())

    findings = evaluate_manifest_rules(facts)

    assert not any(f.id == "ANDROID-MANIFEST-SHARED-USER-ID" for f in findings)


# ---------------------------------------------------------------------------
# analyzers/component_rules.py
# ---------------------------------------------------------------------------


def _component(**overrides: Any) -> ComponentInfo:
    defaults: dict[str, Any] = {
        "component_type": "activity",
        "class_name": "com.example.Component",
        "exported": True,
        "exported_explicit": True,
        "permission": None,
    }
    defaults.update(overrides)
    return ComponentInfo(**defaults)


def test_exported_component_without_permission_is_flagged() -> None:
    facts = ManifestFacts(components=[_component()])

    findings = evaluate_component_rules(facts)

    assert any(f.rule_id == "android.component.exported_without_permission" for f in findings)


def test_exported_component_with_permission_is_not_flagged() -> None:
    facts = ManifestFacts(components=[_component(permission="com.example.CUSTOM")])

    findings = evaluate_component_rules(facts)

    assert findings == []


def test_non_exported_component_is_not_flagged() -> None:
    facts = ManifestFacts(components=[_component(exported=False, exported_explicit=True)])

    findings = evaluate_component_rules(facts)

    assert findings == []


def test_launcher_entry_point_is_not_flagged_as_exported_without_permission() -> None:
    facts = ManifestFacts(
        components=[
            _component(
                class_name="com.example.MainActivity",
                intent_filters=[
                    IntentFilterInfo(
                        actions=["android.intent.action.MAIN"],
                        categories=["android.intent.category.LAUNCHER"],
                    )
                ],
            )
        ]
    )

    findings = evaluate_component_rules(facts)

    assert findings == []


def test_launcher_alias_with_extra_deep_link_still_flags_the_deep_link() -> None:
    facts = ManifestFacts(
        components=[
            _component(
                component_type="activity-alias",
                class_name="com.example.MainActivitySeasonal",
                intent_filters=[
                    IntentFilterInfo(
                        actions=["android.intent.action.MAIN"],
                        categories=["android.intent.category.LAUNCHER"],
                    )
                ],
            )
        ],
        deep_links=[
            DeepLinkInfo(
                scheme="myapp",
                host=None,
                auto_verify=False,
                component_class="com.example.MainActivitySeasonal",
            )
        ],
    )

    findings = evaluate_component_rules(facts)

    assert not any(
        f.rule_id == "android.component.exported_without_permission" for f in findings
    )
    assert any(f.rule_id == "android.manifest.broad_deep_link" for f in findings)


def test_duplicate_broad_deep_links_across_components_are_merged() -> None:
    facts = ManifestFacts(
        deep_links=[
            DeepLinkInfo(
                scheme="myapp",
                host=None,
                auto_verify=False,
                component_class="com.example.MainActivityJanuary",
            ),
            DeepLinkInfo(
                scheme="myapp",
                host=None,
                auto_verify=False,
                component_class="com.example.MainActivityFebruary",
            ),
        ]
    )

    findings = evaluate_component_rules(facts)

    matching = [f for f in findings if f.rule_id == "android.manifest.broad_deep_link"]
    assert len(matching) == 1
    assert len(matching[0].evidence) == 2


def test_exported_provider_without_permission_is_flagged_high() -> None:
    facts = ManifestFacts(
        components=[_component(component_type="provider", class_name="com.example.Provider")]
    )

    findings = evaluate_component_rules(facts)

    assert any(
        f.rule_id == "android.component.exported_provider_without_permission"
        and f.severity == "high"
        for f in findings
    )


def test_exported_provider_with_read_permission_is_not_flagged() -> None:
    facts = ManifestFacts(
        components=[
            _component(
                component_type="provider",
                class_name="com.example.Provider",
                read_permission="com.example.READ",
            )
        ]
    )

    findings = evaluate_component_rules(facts)

    assert findings == []


def test_broad_deep_link_without_host_is_flagged() -> None:
    facts = ManifestFacts(
        deep_links=[
            DeepLinkInfo(
                scheme="myapp",
                host=None,
                auto_verify=False,
                component_class="com.example.DeepLinkActivity",
            )
        ]
    )

    findings = evaluate_component_rules(facts)

    assert any(f.rule_id == "android.manifest.broad_deep_link" for f in findings)


def test_verified_deep_link_is_not_flagged() -> None:
    facts = ManifestFacts(
        deep_links=[
            DeepLinkInfo(
                scheme="https",
                host="bank.example.com",
                auto_verify=True,
                component_class="com.example.DeepLinkActivity",
            )
        ]
    )

    findings = evaluate_component_rules(facts)

    assert findings == []


def test_deep_link_collision_across_components_is_flagged() -> None:
    facts = ManifestFacts(
        deep_links=[
            DeepLinkInfo(
                scheme="https",
                host="bank.example.com",
                auto_verify=True,
                component_class="com.example.FirstActivity",
            ),
            DeepLinkInfo(
                scheme="https",
                host="bank.example.com",
                auto_verify=True,
                component_class="com.example.SecondActivity",
            ),
        ]
    )

    findings = evaluate_component_rules(facts)

    assert any(f.rule_id == "android.manifest.deep_link_collision" for f in findings)


def test_single_component_deep_link_is_not_flagged_as_collision() -> None:
    facts = ManifestFacts(
        deep_links=[
            DeepLinkInfo(
                scheme="https",
                host="bank.example.com",
                auto_verify=True,
                component_class="com.example.OnlyActivity",
            ),
        ]
    )

    findings = evaluate_component_rules(facts)

    assert not any(f.rule_id == "android.manifest.deep_link_collision" for f in findings)


def test_debug_signer_is_flagged_informational() -> None:
    signature = SignatureInfo(
        certificates=[
            CertificateInfo(subject="C=US, O=Android, CN=Android Debug", is_debug_cert=True)
        ]
    )

    findings = evaluate_signature_rules(signature)

    assert any(
        f.id == "ANDROID-CERT-DEBUG-SIGNER" and f.status == "informational" for f in findings
    )


def test_production_signer_is_not_flagged() -> None:
    signature = SignatureInfo(
        certificates=[CertificateInfo(subject="CN=Example Bank", is_debug_cert=False)]
    )

    assert evaluate_signature_rules(signature) == []


# ---------------------------------------------------------------------------
# pipeline.py
# ---------------------------------------------------------------------------


def test_analyze_apk_static_end_to_end(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    apk_path = tmp_path / "sample.apk"
    with zipfile.ZipFile(apk_path, "w") as archive:
        archive.writestr("AndroidManifest.xml", b"manifest")
        archive.writestr("classes.dex", b"dex")
        archive.writestr("lib/arm64-v8a/libnative.so", b"native")

    fake_apk = FakeApk(
        package="com.example.testbank.qa",
        tags={
            "application": [_application_tag(debuggable="true", allowBackup="true")],
            "provider": [
                _element(
                    "provider",
                    {"name": "com.example.testbank.ExportedProvider", "exported": "true"},
                )
            ],
        },
        certificates=[
            FakeCertificate(
                subject="C=US, O=Android, CN=Android Debug",
                issuer="C=US, O=Android, CN=Android Debug",
            )
        ],
    )
    monkeypatch.setattr("vulle.apk.pipeline.load_apk", lambda path: fake_apk)

    report = analyze_apk_static(apk_path)

    assert report.metadata.package_name == "com.example.testbank.qa"
    assert report.metadata.dex_files == ["classes.dex"]
    assert report.metadata.native_libraries[0].abi == "arm64-v8a"
    assert any(f.id == "ANDROID-MANIFEST-DEBUGGABLE" for f in report.findings)
    assert any(f.id == "ANDROID-MANIFEST-ALLOW-BACKUP" for f in report.findings)
    assert any(
        f.rule_id == "android.component.exported_provider_without_permission"
        for f in report.findings
    )
    assert any(f.id == "ANDROID-CERT-DEBUG-SIGNER" for f in report.findings)
    assert len(report.metadata.sha1) == 40
    assert len(report.metadata.sha256) == 64


def test_analyze_apk_static_degrades_instead_of_crashing_on_malformed_manifest(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    apk_path = tmp_path / "sample.apk"
    with zipfile.ZipFile(apk_path, "w") as archive:
        archive.writestr("AndroidManifest.xml", b"garbage")
        archive.writestr("classes.dex", b"dex")

    class BrokenManifestApk(FakeApk):
        def get_androidversion_name(self) -> str:
            raise KeyError("Name")

    monkeypatch.setattr("vulle.apk.pipeline.load_apk", lambda path: BrokenManifestApk())

    report = analyze_apk_static(apk_path)

    assert report.metadata.package_name is None
    assert report.metadata.dex_files == ["classes.dex"]
    assert any("Failed to extract manifest facts" in note for note in report.analysis_limitations)


# ---------------------------------------------------------------------------
# Faz 2 test doubles: androguard Analysis/ClassAnalysis/MethodAnalysis/
# StringAnalysis, implementing only the subset of methods our code calls.
# ---------------------------------------------------------------------------


class FakeInstruction:
    def __init__(self, name: str, output: str = "") -> None:
        self._name = name
        self._output = output

    def get_name(self) -> str:
        return self._name

    def get_output(self) -> str:
        return self._output


class FakeEncodedMethod:
    def __init__(self, name: str, instructions: list[FakeInstruction] | None = None) -> None:
        self._name = name
        self._instructions = instructions or []

    def get_name(self) -> str:
        return self._name

    def get_instructions(self) -> Any:
        return iter(self._instructions)


class FakeMethodAnalysis:
    def __init__(self, encoded_method: FakeEncodedMethod) -> None:
        self._encoded_method = encoded_method

    def get_method(self) -> FakeEncodedMethod:
        return self._encoded_method


class FakeClassDef:
    def __init__(self, name: str, interfaces: list[str] | None = None) -> None:
        self._name = name
        self._interfaces = interfaces or []

    def get_name(self) -> str:
        return self._name

    def get_interfaces(self) -> list[str]:
        return self._interfaces


class FakeClassAnalysis:
    def __init__(
        self,
        class_def: FakeClassDef,
        methods: list[FakeMethodAnalysis] | None = None,
    ) -> None:
        self._class_def = class_def
        self._methods = methods or []

    def get_class(self) -> FakeClassDef:
        return self._class_def

    def get_methods(self) -> list[FakeMethodAnalysis]:
        return self._methods


class FakeStringAnalysis:
    def __init__(
        self,
        value: str,
        xrefs: list[tuple[FakeClassAnalysis, FakeMethodAnalysis]] | None = None,
    ) -> None:
        self._value = value
        self._xrefs = xrefs or []

    def get_value(self) -> str:
        return self._value

    def get_xref_from(self) -> list[tuple[FakeClassAnalysis, FakeMethodAnalysis]]:
        return self._xrefs


class FakeDexAnalysis:
    def __init__(
        self,
        classes: list[FakeClassAnalysis] | None = None,
        strings: list[FakeStringAnalysis] | None = None,
    ) -> None:
        self._classes = classes or []
        self._strings = strings or []

    def get_classes(self) -> list[FakeClassAnalysis]:
        return self._classes

    def get_strings(self) -> list[FakeStringAnalysis]:
        return self._strings


# ---------------------------------------------------------------------------
# analyzers/tls_rules.py
# ---------------------------------------------------------------------------


def test_tls_rules_flags_trivially_permissive_trust_manager() -> None:
    method = FakeEncodedMethod("checkServerTrusted", [FakeInstruction("return-void")])
    class_def = FakeClassDef(
        "Lcom/example/InsecureTrustManager;",
        interfaces=["Ljavax/net/ssl/X509TrustManager;"],
    )
    analysis = FakeDexAnalysis(
        classes=[FakeClassAnalysis(class_def, methods=[FakeMethodAnalysis(method)])]
    )

    findings = evaluate_tls_rules(analysis)

    assert any(f.rule_id == "android.tls.permissive_trust_manager" for f in findings)


def test_tls_rules_does_not_flag_trust_manager_with_throw() -> None:
    method = FakeEncodedMethod(
        "checkServerTrusted",
        [FakeInstruction("invoke-virtual", "Ljava/security/cert/CertificateException;"),
         FakeInstruction("throw")],
    )
    class_def = FakeClassDef(
        "Lcom/example/RealTrustManager;",
        interfaces=["Ljavax/net/ssl/X509TrustManager;"],
    )
    analysis = FakeDexAnalysis(
        classes=[FakeClassAnalysis(class_def, methods=[FakeMethodAnalysis(method)])]
    )

    findings = evaluate_tls_rules(analysis)

    assert findings == []


def test_tls_rules_flags_ssl_error_handler_proceed() -> None:
    method = FakeEncodedMethod(
        "onReceivedSslError",
        [FakeInstruction("invoke-virtual", "Landroid/webkit/SslErrorHandler;->proceed()V")],
    )
    class_def = FakeClassDef("Lcom/example/InsecureWebViewClient;")
    analysis = FakeDexAnalysis(
        classes=[FakeClassAnalysis(class_def, methods=[FakeMethodAnalysis(method)])]
    )

    findings = evaluate_tls_rules(analysis)

    assert any(
        f.rule_id == "android.webview.ssl_error_proceed"
        and f.status == "confirmed_static_misconfiguration"
        for f in findings
    )


def test_tls_rules_does_not_flag_ssl_error_handler_that_cancels() -> None:
    method = FakeEncodedMethod(
        "onReceivedSslError",
        [FakeInstruction("invoke-virtual", "Landroid/webkit/SslErrorHandler;->cancel()V")],
    )
    class_def = FakeClassDef("Lcom/example/SafeWebViewClient;")
    analysis = FakeDexAnalysis(
        classes=[FakeClassAnalysis(class_def, methods=[FakeMethodAnalysis(method)])]
    )

    findings = evaluate_tls_rules(analysis)

    assert findings == []


# ---------------------------------------------------------------------------
# analyzers/webview_rules.py
# ---------------------------------------------------------------------------


def test_webview_rules_flags_js_interface_with_javascript_enabled() -> None:
    method = FakeEncodedMethod(
        "setup",
        [
            FakeInstruction(
                "invoke-virtual", "Landroid/webkit/WebSettings;->setJavaScriptEnabled(Z)V"
            ),
            FakeInstruction(
                "invoke-virtual",
                "Landroid/webkit/WebView;->addJavascriptInterface(Ljava/lang/Object;"
                "Ljava/lang/String;)V",
            ),
        ],
    )
    class_def = FakeClassDef("Lcom/example/MainActivity;")
    analysis = FakeDexAnalysis(
        classes=[FakeClassAnalysis(class_def, methods=[FakeMethodAnalysis(method)])]
    )

    findings = evaluate_webview_rules(analysis)

    assert any(
        f.rule_id == "android.webview.js_bridge_with_javascript_enabled" for f in findings
    )


def test_webview_rules_flags_interface_only_as_informational() -> None:
    method = FakeEncodedMethod(
        "setup",
        [
            FakeInstruction(
                "invoke-virtual",
                "Landroid/webkit/WebView;->addJavascriptInterface(Ljava/lang/Object;"
                "Ljava/lang/String;)V",
            ),
        ],
    )
    class_def = FakeClassDef("Lcom/example/MainActivity;")
    analysis = FakeDexAnalysis(
        classes=[FakeClassAnalysis(class_def, methods=[FakeMethodAnalysis(method)])]
    )

    findings = evaluate_webview_rules(analysis)

    assert any(
        f.rule_id == "android.webview.js_interface" and f.status == "informational"
        for f in findings
    )


def test_webview_rules_does_not_flag_class_without_webview_calls() -> None:
    method = FakeEncodedMethod("unrelated", [FakeInstruction("return-void")])
    class_def = FakeClassDef("Lcom/example/Unrelated;")
    analysis = FakeDexAnalysis(
        classes=[FakeClassAnalysis(class_def, methods=[FakeMethodAnalysis(method)])]
    )

    findings = evaluate_webview_rules(analysis)

    assert findings == []


def test_webview_rules_flags_mixed_content_mode() -> None:
    method = FakeEncodedMethod(
        "setup",
        [
            FakeInstruction(
                "invoke-virtual", "Landroid/webkit/WebSettings;->setMixedContentMode(I)V"
            ),
        ],
    )
    class_def = FakeClassDef("Lcom/example/MainActivity;")
    analysis = FakeDexAnalysis(
        classes=[FakeClassAnalysis(class_def, methods=[FakeMethodAnalysis(method)])]
    )

    findings = evaluate_webview_rules(analysis)

    assert any(f.rule_id == "android.webview.mixed_content_mode" for f in findings)


def test_webview_rules_flags_universal_file_access() -> None:
    method = FakeEncodedMethod(
        "setup",
        [
            FakeInstruction(
                "invoke-virtual",
                "Landroid/webkit/WebSettings;->setAllowUniversalAccessFromFileURLs(Z)V",
            ),
        ],
    )
    class_def = FakeClassDef("Lcom/example/MainActivity;")
    analysis = FakeDexAnalysis(
        classes=[FakeClassAnalysis(class_def, methods=[FakeMethodAnalysis(method)])]
    )

    findings = evaluate_webview_rules(analysis)

    assert any(
        f.rule_id == "android.webview.universal_file_access" and f.severity == "high"
        for f in findings
    )


def test_webview_rules_flags_web_contents_debugging() -> None:
    method = FakeEncodedMethod(
        "setup",
        [
            FakeInstruction(
                "invoke-static",
                "Landroid/webkit/WebView;->setWebContentsDebuggingEnabled(Z)V",
            ),
        ],
    )
    class_def = FakeClassDef("Lcom/example/MainActivity;")
    analysis = FakeDexAnalysis(
        classes=[FakeClassAnalysis(class_def, methods=[FakeMethodAnalysis(method)])]
    )

    findings = evaluate_webview_rules(analysis)

    assert any(f.rule_id == "android.webview.debugging_enabled" for f in findings)


# ---------------------------------------------------------------------------
# analyzers/crypto_rules.py
# ---------------------------------------------------------------------------


def test_crypto_rules_flags_ecb_cipher_mode() -> None:
    method = FakeEncodedMethod(
        "encrypt",
        [
            FakeInstruction("const-string", 'v0, "AES/ECB/PKCS5Padding"'),
            FakeInstruction(
                "invoke-static", "Ljavax/crypto/Cipher;->getInstance(Ljava/lang/String;)..."
            ),
        ],
    )
    class_def = FakeClassDef("Lcom/example/Crypto;")
    analysis = FakeDexAnalysis(
        classes=[FakeClassAnalysis(class_def, methods=[FakeMethodAnalysis(method)])]
    )

    findings = evaluate_crypto_rules(analysis)

    assert any(f.rule_id == "android.crypto.ecb_cipher_mode" for f in findings)


def test_crypto_rules_does_not_flag_gcm_cipher_mode() -> None:
    method = FakeEncodedMethod(
        "encrypt",
        [
            FakeInstruction("const-string", 'v0, "AES/GCM/NoPadding"'),
            FakeInstruction(
                "invoke-static", "Ljavax/crypto/Cipher;->getInstance(Ljava/lang/String;)..."
            ),
        ],
    )
    class_def = FakeClassDef("Lcom/example/Crypto;")
    analysis = FakeDexAnalysis(
        classes=[FakeClassAnalysis(class_def, methods=[FakeMethodAnalysis(method)])]
    )

    findings = evaluate_crypto_rules(analysis)

    assert findings == []


def test_crypto_rules_flags_weak_hash_algorithm() -> None:
    method = FakeEncodedMethod(
        "hash",
        [
            FakeInstruction("const-string", 'v0, "MD5"'),
            FakeInstruction(
                "invoke-static",
                "Ljava/security/MessageDigest;->getInstance(Ljava/lang/String;)...",
            ),
        ],
    )
    class_def = FakeClassDef("Lcom/example/Hasher;")
    analysis = FakeDexAnalysis(
        classes=[FakeClassAnalysis(class_def, methods=[FakeMethodAnalysis(method)])]
    )

    findings = evaluate_crypto_rules(analysis)

    assert any(
        f.rule_id == "android.crypto.weak_hash_algorithm" and f.status == "informational"
        for f in findings
    )


def test_crypto_rules_flags_weak_random() -> None:
    method = FakeEncodedMethod(
        "generate",
        [FakeInstruction("invoke-direct", "Ljava/util/Random;-><init>()V")],
    )
    class_def = FakeClassDef("Lcom/example/TokenGenerator;")
    analysis = FakeDexAnalysis(
        classes=[FakeClassAnalysis(class_def, methods=[FakeMethodAnalysis(method)])]
    )

    findings = evaluate_crypto_rules(analysis)

    assert any(f.rule_id == "android.crypto.weak_random" for f in findings)


# ---------------------------------------------------------------------------
# analyzers/storage_rules.py
# ---------------------------------------------------------------------------


def test_storage_rules_flags_shared_preferences_without_encrypted_variant() -> None:
    method = FakeEncodedMethod(
        "load",
        [
            FakeInstruction(
                "invoke-interface",
                "Landroid/content/SharedPreferences;->getString"
                "(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;",
            )
        ],
    )
    class_def = FakeClassDef("Lcom/example/PrefsHelper;")
    analysis = FakeDexAnalysis(
        classes=[FakeClassAnalysis(class_def, methods=[FakeMethodAnalysis(method)])]
    )

    findings = evaluate_storage_rules(analysis)

    assert any(
        f.rule_id == "android.storage.shared_preferences_without_encryption"
        for f in findings
    )


def test_storage_rules_does_not_flag_when_encrypted_variant_is_used() -> None:
    prefs_method = FakeEncodedMethod(
        "load",
        [
            FakeInstruction(
                "invoke-interface",
                "Landroid/content/SharedPreferences;->getString"
                "(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;",
            )
        ],
    )
    analysis = FakeDexAnalysis(
        classes=[
            FakeClassAnalysis(
                FakeClassDef("Lcom/example/PrefsHelper;"),
                methods=[FakeMethodAnalysis(prefs_method)],
            ),
            FakeClassAnalysis(
                FakeClassDef("Landroidx/security/crypto/EncryptedSharedPreferences;"),
                methods=[],
            ),
        ]
    )

    findings = evaluate_storage_rules(analysis)

    assert findings == []


def test_storage_rules_does_not_flag_when_no_shared_preferences_usage() -> None:
    method = FakeEncodedMethod("unrelated", [FakeInstruction("return-void")])
    class_def = FakeClassDef("Lcom/example/Unrelated;")
    analysis = FakeDexAnalysis(
        classes=[FakeClassAnalysis(class_def, methods=[FakeMethodAnalysis(method)])]
    )

    findings = evaluate_storage_rules(analysis)

    assert findings == []


# ---------------------------------------------------------------------------
# analyzers/secret_rules.py
# ---------------------------------------------------------------------------


def test_secret_rules_flags_known_pattern_with_redacted_evidence() -> None:
    # Built via concatenation so no secret-scanner-shaped literal appears in source.
    secret_value = "AKIA" + "ABCDEFGHIJKLMNOP"
    class_def = FakeClassDef("Lcom/example/Config;")
    method = FakeEncodedMethod("init")
    string_analysis = FakeStringAnalysis(
        secret_value,
        xrefs=[(FakeClassAnalysis(class_def), FakeMethodAnalysis(method))],
    )
    analysis = FakeDexAnalysis(strings=[string_analysis])

    findings = evaluate_secret_rules(analysis)

    assert len(findings) == 1
    assert findings[0].rule_id == "android.secrets.aws_access_key"
    assert secret_value not in findings[0].evidence[0].quote
    assert secret_value not in findings[0].id


def test_secret_rules_never_includes_raw_secret_value_in_evidence() -> None:
    # Built via concatenation so no secret-scanner-shaped literal appears in source.
    secret_value = "glpat-" + "ABCDEFGHIJKLMNOPQRST"
    string_analysis = FakeStringAnalysis(secret_value)
    analysis = FakeDexAnalysis(strings=[string_analysis])

    findings = evaluate_secret_rules(analysis)

    for finding in findings:
        for evidence in finding.evidence:
            assert secret_value not in evidence.quote
            assert secret_value not in evidence.artifact_path
            assert secret_value not in evidence.location


def test_secret_rules_does_not_flag_plain_sentence() -> None:
    string_analysis = FakeStringAnalysis("Please enter your username and password")
    analysis = FakeDexAnalysis(strings=[string_analysis])

    findings = evaluate_secret_rules(analysis)

    assert findings == []


def test_secret_rules_does_not_flag_camelcase_identifier_without_digits() -> None:
    # Real APK data showed ordinary Android identifiers like "AccessibilityCompat"
    # tripping the old digit-less entropy heuristic - regression guard.
    string_analysis = FakeStringAnalysis("AccessibilityCompatActivityImplementation")
    analysis = FakeDexAnalysis(strings=[string_analysis])

    findings = evaluate_secret_rules(analysis)

    assert findings == []


def test_secret_rules_caps_generic_high_entropy_candidates() -> None:
    candidates = [
        FakeStringAnalysis(f"Xk9{i}Zq7Wp2Rt5{i}Vb3Nm8Lc1Hf6")
        for i in range(30)
    ]
    analysis = FakeDexAnalysis(strings=candidates)

    findings = evaluate_secret_rules(analysis)

    assert len(findings) <= 15


def test_network_endpoints_are_deduplicated_and_not_findings() -> None:
    analysis = FakeDexAnalysis(
        strings=[
            FakeStringAnalysis("https://api.example.com/v1/login"),
            FakeStringAnalysis("https://api.example.com/v1/login"),
            FakeStringAnalysis("https://api.example.com/v1/logout"),
        ]
    )

    endpoints = extract_network_endpoints(analysis)
    findings = evaluate_secret_rules(analysis)

    assert endpoints == [
        "https://api.example.com/v1/login",
        "https://api.example.com/v1/logout",
    ]
    assert findings == []


# ---------------------------------------------------------------------------
# pipeline.py — Faz 2 integration
# ---------------------------------------------------------------------------


def test_analyze_apk_static_includes_code_analysis_findings(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    apk_path = tmp_path / "sample.apk"
    with zipfile.ZipFile(apk_path, "w") as archive:
        archive.writestr("AndroidManifest.xml", b"manifest")
        archive.writestr("classes.dex", b"dex")

    fake_apk = FakeApk(tags={"application": [_application_tag(allowBackup="false")]})
    ssl_method = FakeEncodedMethod(
        "onReceivedSslError",
        [FakeInstruction("invoke-virtual", "Landroid/webkit/SslErrorHandler;->proceed()V")],
    )
    fake_dex_analysis = FakeDexAnalysis(
        classes=[
            FakeClassAnalysis(
                FakeClassDef("Lcom/example/InsecureWebViewClient;"),
                methods=[FakeMethodAnalysis(ssl_method)],
            )
        ],
        strings=[FakeStringAnalysis("https://backend.example.com/api")],
    )
    monkeypatch.setattr("vulle.apk.pipeline.load_apk", lambda path: fake_apk)
    monkeypatch.setattr(
        "vulle.apk.pipeline.build_dex_analysis", lambda apk: fake_dex_analysis
    )

    report = analyze_apk_static(apk_path)

    assert any(f.rule_id == "android.webview.ssl_error_proceed" for f in report.findings)
    assert report.network_endpoints == ["https://backend.example.com/api"]


def test_pipeline_degrades_when_dex_analysis_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    apk_path = tmp_path / "sample.apk"
    with zipfile.ZipFile(apk_path, "w") as archive:
        archive.writestr("AndroidManifest.xml", b"manifest")
        archive.writestr("classes.dex", b"dex")

    fake_apk = FakeApk()

    def _broken_dex_analysis(apk: Any) -> Any:
        raise RuntimeError("dex parsing exploded")

    monkeypatch.setattr("vulle.apk.pipeline.load_apk", lambda path: fake_apk)
    monkeypatch.setattr("vulle.apk.pipeline.build_dex_analysis", _broken_dex_analysis)

    report = analyze_apk_static(apk_path)

    assert report.network_endpoints == []
    assert any(
        "Failed to run DEX/bytecode analysis" in note for note in report.analysis_limitations
    )


def test_pipeline_degrades_instead_of_crashing_when_dex_analysis_times_out(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    apk_path = tmp_path / "sample.apk"
    with zipfile.ZipFile(apk_path, "w") as archive:
        archive.writestr("AndroidManifest.xml", b"manifest")
        archive.writestr("classes.dex", b"dex")

    fake_apk = FakeApk()

    def _slow_dex_analysis(apk: Any) -> Any:
        time.sleep(0.2)
        return FakeDexAnalysis()

    monkeypatch.setattr("vulle.apk.pipeline.load_apk", lambda path: fake_apk)
    monkeypatch.setattr("vulle.apk.pipeline.build_dex_analysis", _slow_dex_analysis)
    monkeypatch.setattr("vulle.apk.pipeline.CODE_ANALYSIS_TIMEOUT_SECONDS", 0.01)

    report = analyze_apk_static(apk_path)

    assert report.network_endpoints == []
    assert any(
        "did not complete within" in note for note in report.analysis_limitations
    )
    assert report.metadata.package_name is not None


# ---------------------------------------------------------------------------
# extractors/native_analysis.py — real, hand-built minimal ELF64 binaries.
# pyelftools parses genuine ELF bytes, so androguard-style fake objects
# don't apply here; these tests are skipped if `elftools` isn't installed.
# ---------------------------------------------------------------------------

_PT_GNU_STACK = 0x6474E551
_PT_GNU_RELRO = 0x6474E552
_PF_X, _PF_W, _PF_R = 1, 2, 4
_SHT_STRTAB, _SHT_DYNAMIC, _SHT_DYNSYM = 3, 6, 11
_DT_NULL, _DT_FLAGS = 0, 30
_DF_BIND_NOW = 0x8
_STB_GLOBAL, _STT_FUNC, _SHN_UNDEF = 1, 2, 0


def _build_minimal_elf(
    *, stack_executable: bool, include_relro: bool, bind_now: bool
) -> bytes:
    ehdr_size, phdr_size, shdr_size, sym_size = 64, 56, 64, 24

    stack_flags = (_PF_R | _PF_W | _PF_X) if stack_executable else (_PF_R | _PF_W)
    phdrs = [("GNU_STACK", _PT_GNU_STACK, stack_flags)]
    if include_relro:
        phdrs.append(("GNU_RELRO", _PT_GNU_RELRO, _PF_R))
    n_phdr = len(phdrs)

    dynstr = b"\x00__stack_chk_fail\x00Java_com_example_test\x00"
    off_stack_chk = 1
    off_java_sym = 1 + len(b"__stack_chk_fail\x00")

    shstrtab = b"\x00.dynsym\x00.dynstr\x00.dynamic\x00.shstrtab\x00"
    off_dynsym_name = 1
    off_dynstr_name = off_dynsym_name + len(b".dynsym\x00")
    off_dynamic_name = off_dynstr_name + len(b".dynstr\x00")
    off_shstrtab_name = off_dynamic_name + len(b".dynamic\x00")

    def sym_entry(name_off: int, shndx: int, defined: bool) -> bytes:
        st_info = (_STB_GLOBAL << 4) | _STT_FUNC
        return struct.pack(
            "<IBBHQQ",
            name_off,
            st_info,
            0,
            shndx if defined else _SHN_UNDEF,
            0x1000 if defined else 0,
            0,
        )

    symtab = (
        sym_entry(0, 0, False)
        + sym_entry(off_stack_chk, 0, False)
        + sym_entry(off_java_sym, 1, True)
    )

    dynamic = b""
    if bind_now:
        dynamic += struct.pack("<qQ", _DT_FLAGS, _DF_BIND_NOW)
    dynamic += struct.pack("<qQ", _DT_NULL, 0)

    off = ehdr_size + n_phdr * phdr_size
    off_dynstr = off
    off += len(dynstr)
    off_symtab = off
    off += len(symtab)
    off_dynamic = off
    off += len(dynamic)
    off_shstrtab = off
    off += len(shstrtab)
    off_shdrs = off

    def section(
        name_off: int, sh_type: int, link: int, offset: int, size: int, entsize: int
    ) -> bytes:
        return struct.pack(
            "<IIQQQQIIQQ", name_off, sh_type, 0, 0, offset, size, link, 0, 8, entsize
        )

    sections = [
        struct.pack("<IIQQQQIIQQ", 0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
        section(off_dynsym_name, _SHT_DYNSYM, 2, off_symtab, len(symtab), sym_size),
        section(off_dynstr_name, _SHT_STRTAB, 0, off_dynstr, len(dynstr), 0),
        section(off_dynamic_name, _SHT_DYNAMIC, 2, off_dynamic, len(dynamic), 16),
        section(off_shstrtab_name, _SHT_STRTAB, 0, off_shstrtab, len(shstrtab), 0),
    ]

    e_ident = b"\x7fELF" + bytes([2, 1, 1, 0]) + b"\x00" * 8
    ehdr = e_ident + struct.pack(
        "<HHIQQQIHHHHHH",
        3,  # ET_DYN
        62,  # EM_X86_64
        1,
        0,
        ehdr_size,
        off_shdrs,
        0,
        ehdr_size,
        phdr_size,
        n_phdr,
        shdr_size,
        len(sections),
        4,  # shstrndx
    )

    phdr_bytes = b"".join(
        struct.pack("<IIQQQQQQ", p_type, p_flags, 0, 0, 0, 0, 0, 0x1000)
        for _name, p_type, p_flags in phdrs
    )

    return ehdr + phdr_bytes + dynstr + symtab + dynamic + shstrtab + b"".join(sections)


def test_parse_elf_detects_nx_enabled_and_full_relro() -> None:
    pytest.importorskip("elftools")
    from vulle.apk.extractors.native_analysis import _parse_elf

    data = _build_minimal_elf(stack_executable=False, include_relro=True, bind_now=True)

    facts = _parse_elf(data)

    assert facts["nx_enabled"] is True
    assert facts["relro"] == "full"
    assert facts["stack_canary_detected"] is True
    assert facts["exported_jni_symbols"] == ["Java_com_example_test"]


def test_parse_elf_detects_nx_disabled_and_no_relro() -> None:
    pytest.importorskip("elftools")
    from vulle.apk.extractors.native_analysis import _parse_elf

    data = _build_minimal_elf(stack_executable=True, include_relro=False, bind_now=False)

    facts = _parse_elf(data)

    assert facts["nx_enabled"] is False
    assert facts["relro"] == "none"


def test_parse_elf_detects_partial_relro_without_bind_now() -> None:
    pytest.importorskip("elftools")
    from vulle.apk.extractors.native_analysis import _parse_elf

    data = _build_minimal_elf(stack_executable=False, include_relro=True, bind_now=False)

    facts = _parse_elf(data)

    assert facts["relro"] == "partial"


def test_analyze_native_libraries_only_analyzes_preferred_abi(tmp_path: Path) -> None:
    pytest.importorskip("elftools")
    from vulle.apk.extractors.native_analysis import analyze_native_libraries

    good_elf = _build_minimal_elf(stack_executable=False, include_relro=True, bind_now=True)
    zip_path = tmp_path / "sample.apk"
    with zipfile.ZipFile(zip_path, "w") as archive:
        archive.writestr("lib/arm64-v8a/libfoo.so", good_elf)
        archive.writestr("lib/armeabi-v7a/libfoo.so", good_elf)

    libraries = [
        NativeLibraryInfo(path="lib/arm64-v8a/libfoo.so", abi="arm64-v8a"),
        NativeLibraryInfo(path="lib/armeabi-v7a/libfoo.so", abi="armeabi-v7a"),
    ]
    with zipfile.ZipFile(zip_path) as archive:
        analyzed = analyze_native_libraries(archive, libraries)

    arm64 = next(lib for lib in analyzed if lib.abi == "arm64-v8a")
    armeabi = next(lib for lib in analyzed if lib.abi == "armeabi-v7a")
    assert arm64.nx_enabled is True
    assert armeabi.nx_enabled is None


def test_analyze_native_libraries_sets_parse_error_on_garbage(tmp_path: Path) -> None:
    pytest.importorskip("elftools")
    from vulle.apk.extractors.native_analysis import analyze_native_libraries

    zip_path = tmp_path / "sample.apk"
    with zipfile.ZipFile(zip_path, "w") as archive:
        archive.writestr("lib/arm64-v8a/libbad.so", b"not an elf file")

    with zipfile.ZipFile(zip_path) as archive:
        libraries = [NativeLibraryInfo(path="lib/arm64-v8a/libbad.so", abi="arm64-v8a")]
        analyzed = analyze_native_libraries(archive, libraries)

    assert analyzed[0].parse_error is not None
    assert analyzed[0].nx_enabled is None


# ---------------------------------------------------------------------------
# analyzers/native_rules.py
# ---------------------------------------------------------------------------


def test_native_rules_flags_nx_disabled() -> None:
    library = NativeLibraryInfo(path="lib/arm64-v8a/libfoo.so", abi="arm64-v8a", nx_enabled=False)

    findings = evaluate_native_rules([library])

    assert any(f.rule_id == "android.native.nx_disabled" for f in findings)


def test_native_rules_flags_missing_relro() -> None:
    library = NativeLibraryInfo(path="lib/arm64-v8a/libfoo.so", abi="arm64-v8a", relro="none")

    findings = evaluate_native_rules([library])

    assert any(f.rule_id == "android.native.relro_missing" for f in findings)


def test_native_rules_does_not_flag_when_protections_enabled() -> None:
    library = NativeLibraryInfo(
        path="lib/arm64-v8a/libfoo.so", abi="arm64-v8a", nx_enabled=True, relro="full"
    )

    findings = evaluate_native_rules([library])

    assert findings == []


def test_native_rules_skips_libraries_with_parse_error() -> None:
    library = NativeLibraryInfo(
        path="lib/arm64-v8a/libfoo.so",
        abi="arm64-v8a",
        nx_enabled=False,
        parse_error="ELFError: bad format",
    )

    findings = evaluate_native_rules([library])

    assert findings == []


# ---------------------------------------------------------------------------
# analyzers/dependency_rules.py
# ---------------------------------------------------------------------------


def test_dependency_fingerprints_detects_known_sdk() -> None:
    classes = [
        FakeClassAnalysis(FakeClassDef(f"Lcom/google/firebase/Foo{i};"))
        for i in range(3)
    ]
    analysis = FakeDexAnalysis(classes=classes)

    fingerprints = evaluate_dependency_fingerprints(analysis)

    assert any(fp.name == "Firebase" and fp.class_count == 3 for fp in fingerprints)


def test_dependency_fingerprints_prefers_more_specific_prefix() -> None:
    classes = [FakeClassAnalysis(FakeClassDef("Lcom/facebook/react/ReactActivity;"))]
    analysis = FakeDexAnalysis(classes=classes)

    fingerprints = evaluate_dependency_fingerprints(analysis)

    names = {fp.name for fp in fingerprints}
    assert "React Native" in names
    assert "Facebook SDK" not in names


def test_dependency_fingerprints_ignores_unknown_packages() -> None:
    classes = [FakeClassAnalysis(FakeClassDef("Lcom/example/bank/MainActivity;"))]
    analysis = FakeDexAnalysis(classes=classes)

    fingerprints = evaluate_dependency_fingerprints(analysis)

    assert fingerprints == []
