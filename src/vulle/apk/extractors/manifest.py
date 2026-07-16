from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

from vulle.apk.models import (
    ComponentInfo,
    ComponentType,
    CustomPermissionInfo,
    DeepLinkInfo,
    IntentFilterData,
    IntentFilterInfo,
    NetworkSecurityConfigInfo,
)
from vulle.errors import VulleError

_COMPONENT_TAGS: dict[str, ComponentType] = {
    "activity": "activity",
    "activity-alias": "activity-alias",
    "service": "service",
    "receiver": "receiver",
    "provider": "provider",
}

_VIEW_ACTION = "android.intent.action.VIEW"
_BROWSABLE_CATEGORY = "android.intent.category.BROWSABLE"


class ApplicationAttributes(BaseModel):
    debuggable: bool | None = None
    allow_backup: bool | None = None
    uses_cleartext_traffic: bool | None = None
    test_only: bool | None = None
    full_backup_content: str | None = None
    network_security_config_ref: str | None = None


class ManifestFacts(BaseModel):
    package_name: str | None = None
    version_name: str | None = None
    version_code: str | None = None
    min_sdk: str | None = None
    target_sdk: str | None = None
    permissions: list[str] = Field(default_factory=list)
    custom_permissions: list[CustomPermissionInfo] = Field(default_factory=list)
    application: ApplicationAttributes = Field(default_factory=ApplicationAttributes)
    components: list[ComponentInfo] = Field(default_factory=list)
    deep_links: list[DeepLinkInfo] = Field(default_factory=list)
    network_security_config: NetworkSecurityConfigInfo = Field(
        default_factory=NetworkSecurityConfigInfo
    )


def load_apk(path: Path) -> Any:
    try:
        from androguard.core.apk import APK
    except ImportError as exc:
        raise VulleError(
            "androguard is required for analyze-apk. "
            "Install with `pip install -e '.[mobile]'`."
        ) from exc
    try:
        return APK(str(path))
    except Exception as exc:
        raise VulleError(
            f"Failed to parse APK with androguard: {exc.__class__.__name__}: {exc}"
        ) from exc


def extract_manifest_facts(apk: Any) -> ManifestFacts:
    components = _extract_components(apk)
    application = _extract_application_attributes(apk)
    custom_permissions = [
        CustomPermissionInfo(name=name, protection_level=details.get("protectionLevel"))
        for name, details in apk.get_declared_permissions_details().items()
    ]
    return ManifestFacts(
        package_name=apk.get_package(),
        version_name=apk.get_androidversion_name(),
        version_code=apk.get_androidversion_code(),
        min_sdk=apk.get_min_sdk_version(),
        target_sdk=apk.get_target_sdk_version(),
        permissions=list(apk.get_permissions()),
        custom_permissions=custom_permissions,
        application=application,
        components=components,
        deep_links=_extract_deep_links(components),
        network_security_config=_extract_network_security_config(
            apk, apk.get_package(), application.network_security_config_ref
        ),
    )


def _extract_components(apk: Any) -> list[ComponentInfo]:
    components = []
    for tag_name, component_type in _COMPONENT_TAGS.items():
        for element in apk.find_tags(tag_name):
            components.append(_component_from_element(apk, element, component_type))
    return components


def _component_from_element(apk: Any, element: Any, component_type: ComponentType) -> ComponentInfo:
    name = apk.get_value_from_tag(element, "name") or ""
    intent_filters = _extract_intent_filters(apk, element)
    exported_raw = apk.get_value_from_tag(element, "exported")
    exported_explicit = exported_raw is not None
    exported = _bool_attr(exported_raw) if exported_explicit else bool(intent_filters)
    authorities_raw = apk.get_value_from_tag(element, "authorities") or ""
    authorities = [part.strip() for part in authorities_raw.split(";") if part.strip()]
    return ComponentInfo(
        component_type=component_type,
        class_name=name,
        exported=bool(exported),
        exported_explicit=exported_explicit,
        permission=apk.get_value_from_tag(element, "permission"),
        read_permission=apk.get_value_from_tag(element, "readPermission"),
        write_permission=apk.get_value_from_tag(element, "writePermission"),
        grant_uri_permissions=bool(
            _bool_attr(apk.get_value_from_tag(element, "grantUriPermissions"))
        ),
        authorities=authorities,
        intent_filters=intent_filters,
    )


def _extract_intent_filters(apk: Any, element: Any) -> list[IntentFilterInfo]:
    filters = []
    for intent_filter_el in element.findall("intent-filter"):
        actions = [
            value
            for action_el in intent_filter_el.findall("action")
            if (value := apk.get_value_from_tag(action_el, "name"))
        ]
        categories = [
            value
            for category_el in intent_filter_el.findall("category")
            if (value := apk.get_value_from_tag(category_el, "name"))
        ]
        data_entries = [
            IntentFilterData(
                scheme=apk.get_value_from_tag(data_el, "scheme"),
                host=apk.get_value_from_tag(data_el, "host"),
                path=apk.get_value_from_tag(data_el, "path"),
                path_pattern=apk.get_value_from_tag(data_el, "pathPattern"),
                path_prefix=apk.get_value_from_tag(data_el, "pathPrefix"),
                mime_type=apk.get_value_from_tag(data_el, "mimeType"),
            )
            for data_el in intent_filter_el.findall("data")
        ]
        filters.append(
            IntentFilterInfo(
                actions=actions,
                categories=categories,
                data=data_entries,
                auto_verify=bool(
                    _bool_attr(apk.get_value_from_tag(intent_filter_el, "autoVerify"))
                ),
            )
        )
    return filters


def _extract_deep_links(components: list[ComponentInfo]) -> list[DeepLinkInfo]:
    deep_links = []
    for component in components:
        for intent_filter in component.intent_filters:
            if not intent_filter.is_browsable_view:
                continue
            for data in intent_filter.data:
                if not data.scheme:
                    continue
                deep_links.append(
                    DeepLinkInfo(
                        scheme=data.scheme,
                        host=data.host,
                        path_pattern=data.path_pattern or data.path or data.path_prefix,
                        auto_verify=intent_filter.auto_verify,
                        component_class=component.class_name,
                    )
                )
    return deep_links


def _extract_application_attributes(apk: Any) -> ApplicationAttributes:
    elements = apk.find_tags("application")
    if not elements:
        return ApplicationAttributes()
    element = elements[0]
    return ApplicationAttributes(
        debuggable=_bool_attr(apk.get_value_from_tag(element, "debuggable")),
        allow_backup=_bool_attr(apk.get_value_from_tag(element, "allowBackup")),
        uses_cleartext_traffic=_bool_attr(
            apk.get_value_from_tag(element, "usesCleartextTraffic")
        ),
        test_only=_bool_attr(apk.get_value_from_tag(element, "testOnly")),
        full_backup_content=apk.get_value_from_tag(element, "fullBackupContent"),
        network_security_config_ref=apk.get_value_from_tag(element, "networkSecurityConfig"),
    )


def _extract_network_security_config(
    apk: Any,
    package: str | None,
    ref: str | None,
) -> NetworkSecurityConfigInfo:
    if not ref:
        return NetworkSecurityConfigInfo(declared=False)
    try:
        cleartext_default = _resolve_cleartext_default(apk, package, ref)
        return NetworkSecurityConfigInfo(
            declared=True,
            cleartext_permitted_default=cleartext_default,
        )
    except Exception as exc:  # defensive: never let NSC parsing crash the pipeline
        return NetworkSecurityConfigInfo(
            declared=True,
            parse_error=f"{exc.__class__.__name__}: {exc}",
        )


def _resolve_cleartext_default(apk: Any, package: str | None, ref: str) -> bool | None:
    from androguard.core.axml import AXMLPrinter

    parsed = _parse_resource_reference(ref)
    if parsed is None:
        raise ValueError(f"Unsupported resource reference format: {ref}")
    arsc = apk.get_android_resources()
    if arsc is None:
        raise ValueError("resources.arsc is not present in the APK")
    if isinstance(parsed, int):
        res_id: int | None = parsed
    else:
        res_type, res_name = parsed
        res_id = arsc.get_res_id_by_key(package, res_type, res_name)
    if not res_id:
        raise ValueError(f"Resource not found for reference: {ref}")
    configs = arsc.get_resolved_res_configs(res_id)
    file_path = next((value for _, value in configs if isinstance(value, str)), None)
    if not file_path:
        raise ValueError(f"No file mapping found for resource: {ref}")
    raw = apk.get_file(file_path)
    root = AXMLPrinter(raw).get_xml_obj()
    base_config = root.find("base-config")
    if base_config is None:
        return None
    value = apk.get_value_from_tag(base_config, "cleartextTrafficPermitted")
    return _bool_attr(value)


def _parse_resource_reference(value: str) -> tuple[str, str] | int | None:
    stripped = value.strip()
    if stripped.startswith("@0x") or stripped.startswith("0x"):
        try:
            return int(stripped.removeprefix("@"), 16)
        except ValueError:
            return None
    if stripped.startswith("@"):
        parts = stripped[1:].split("/", 1)
        if len(parts) == 2 and parts[0] and parts[1]:
            return (parts[0], parts[1])
    return None


def _bool_attr(value: str | None) -> bool | None:
    if value is None:
        return None
    return value.strip().lower() == "true"
