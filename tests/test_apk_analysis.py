import builtins
import xml.etree.ElementTree as ET
import zipfile
from datetime import datetime
from pathlib import Path
from typing import Any

import pytest

from vulle.apk.analyzers.component_rules import evaluate_component_rules, evaluate_signature_rules
from vulle.apk.analyzers.manifest_rules import evaluate_manifest_rules
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
    apk = FakeApk(package="com.fibabanka.test", version_name="2.3.1", version_code="42")

    facts = extract_manifest_facts(apk)

    assert facts.package_name == "com.fibabanka.test"
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
            FakeCertificate(subject="CN=Fibabanka Production", issuer="CN=Fibabanka CA")
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
        certificates=[CertificateInfo(subject="CN=Fibabanka", is_debug_cert=False)]
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
        package="com.fibabanka.Fibabanka.test",
        tags={
            "application": [_application_tag(debuggable="true", allowBackup="true")],
            "provider": [
                _element("provider", {"name": "com.fibabanka.ExportedProvider", "exported": "true"})
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

    assert report.metadata.package_name == "com.fibabanka.Fibabanka.test"
    assert report.metadata.dex_files == ["classes.dex"]
    assert report.metadata.native_libraries[0].abi == "arm64-v8a"
    assert any(f.id == "ANDROID-MANIFEST-DEBUGGABLE" for f in report.findings)
    assert any(f.id == "ANDROID-MANIFEST-ALLOW-BACKUP" for f in report.findings)
    assert any(
        f.rule_id == "android.component.exported_provider_without_permission"
        for f in report.findings
    )
    assert any(f.id == "ANDROID-CERT-DEBUG-SIGNER" for f in report.findings)


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
