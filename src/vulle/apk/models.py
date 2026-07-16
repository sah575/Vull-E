from typing import Literal

from pydantic import BaseModel, Field

RULE_VERSION = "1.0.0"

Severity = Literal["info", "low", "medium", "high", "critical"]
FindingStatus = Literal[
    "confirmed_static_misconfiguration",
    "probable_vulnerability",
    "risk_hypothesis",
    "informational",
    "analysis_limitation",
]
ComponentType = Literal["activity", "activity-alias", "service", "receiver", "provider"]


class NativeLibraryInfo(BaseModel):
    path: str
    abi: str


class ApkMetadata(BaseModel):
    file_name: str
    file_size: int
    sha256: str
    package_name: str | None = None
    version_name: str | None = None
    version_code: str | None = None
    min_sdk: str | None = None
    target_sdk: str | None = None
    dex_files: list[str] = Field(default_factory=list)
    native_libraries: list[NativeLibraryInfo] = Field(default_factory=list)


class CertificateInfo(BaseModel):
    subject: str | None = None
    issuer: str | None = None
    valid_from: str | None = None
    valid_to: str | None = None
    sha256_fingerprint: str | None = None
    is_debug_cert: bool = False


class SignatureInfo(BaseModel):
    signed_v1: bool = False
    signed_v2: bool = False
    signed_v3: bool = False
    signer_count: int = 0
    certificates: list[CertificateInfo] = Field(default_factory=list)


class IntentFilterData(BaseModel):
    scheme: str | None = None
    host: str | None = None
    path: str | None = None
    path_pattern: str | None = None
    path_prefix: str | None = None
    mime_type: str | None = None


class IntentFilterInfo(BaseModel):
    actions: list[str] = Field(default_factory=list)
    categories: list[str] = Field(default_factory=list)
    data: list[IntentFilterData] = Field(default_factory=list)
    auto_verify: bool = False

    @property
    def is_browsable_view(self) -> bool:
        return (
            "android.intent.action.VIEW" in self.actions
            and "android.intent.category.BROWSABLE" in self.categories
        )


class ComponentInfo(BaseModel):
    component_type: ComponentType
    class_name: str
    exported: bool
    exported_explicit: bool
    permission: str | None = None
    read_permission: str | None = None
    write_permission: str | None = None
    grant_uri_permissions: bool = False
    authorities: list[str] = Field(default_factory=list)
    intent_filters: list[IntentFilterInfo] = Field(default_factory=list)


class DeepLinkInfo(BaseModel):
    scheme: str | None = None
    host: str | None = None
    path_pattern: str | None = None
    auto_verify: bool
    component_class: str


class NetworkSecurityConfigInfo(BaseModel):
    declared: bool = False
    cleartext_permitted_default: bool | None = None
    parse_error: str | None = None


class CustomPermissionInfo(BaseModel):
    name: str
    protection_level: str | None = None


class ApkEvidence(BaseModel):
    artifact_type: Literal["manifest", "certificate", "zip_entry", "dex_code"]
    artifact_path: str
    location: str
    quote: str


class ApkFinding(BaseModel):
    id: str
    rule_id: str
    title: str
    category: str
    severity: Severity
    status: FindingStatus
    evidence: list[ApkEvidence] = Field(default_factory=list)
    impact: str
    recommended_validation: list[str] = Field(default_factory=list)
    remediation: str


class ApkStaticAnalysisReport(BaseModel):
    app_version: str
    rule_version: str = RULE_VERSION
    metadata: ApkMetadata
    signature: SignatureInfo = Field(default_factory=SignatureInfo)
    permissions: list[str] = Field(default_factory=list)
    custom_permissions: list[CustomPermissionInfo] = Field(default_factory=list)
    components: list[ComponentInfo] = Field(default_factory=list)
    deep_links: list[DeepLinkInfo] = Field(default_factory=list)
    network_security_config: NetworkSecurityConfigInfo = Field(
        default_factory=NetworkSecurityConfigInfo
    )
    findings: list[ApkFinding] = Field(default_factory=list)
    network_endpoints: list[str] = Field(default_factory=list)
    analysis_limitations: list[str] = Field(default_factory=list)
