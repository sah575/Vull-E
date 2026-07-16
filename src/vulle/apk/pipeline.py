from pathlib import Path

from vulle import __version__
from vulle.apk.analyzers.component_rules import (
    evaluate_component_rules,
    evaluate_signature_rules,
)
from vulle.apk.analyzers.crypto_rules import evaluate_crypto_rules
from vulle.apk.analyzers.manifest_rules import evaluate_manifest_rules
from vulle.apk.analyzers.secret_rules import evaluate_secret_rules, extract_network_endpoints
from vulle.apk.analyzers.storage_rules import evaluate_storage_rules
from vulle.apk.analyzers.tls_rules import evaluate_tls_rules
from vulle.apk.analyzers.webview_rules import evaluate_webview_rules
from vulle.apk.extractors.certificates import extract_signature_info
from vulle.apk.extractors.dex_analysis import build_dex_analysis
from vulle.apk.extractors.manifest import ManifestFacts, extract_manifest_facts, load_apk
from vulle.apk.extractors.metadata import extract_dex_files, extract_native_libraries
from vulle.apk.limits import CODE_ANALYSIS_TIMEOUT_SECONDS, PARSE_TIMEOUT_SECONDS
from vulle.apk.models import ApkFinding, ApkMetadata, ApkStaticAnalysisReport
from vulle.apk.workspace import compute_sha1, compute_sha256, run_with_timeout, validate_apk_zip
from vulle.errors import ApkAnalysisTimeoutError


def analyze_apk_static(path: Path) -> ApkStaticAnalysisReport:
    path = Path(path)
    archive = validate_apk_zip(path)
    try:
        dex_files = extract_dex_files(archive)
        native_libraries = extract_native_libraries(archive)
    finally:
        archive.close()

    analysis_limitations = []
    apk = run_with_timeout(lambda: load_apk(path), timeout=PARSE_TIMEOUT_SECONDS)
    try:
        manifest_facts = run_with_timeout(
            lambda: extract_manifest_facts(apk),
            timeout=PARSE_TIMEOUT_SECONDS,
        )
    except ApkAnalysisTimeoutError:
        raise
    except Exception as exc:
        manifest_facts = ManifestFacts()
        analysis_limitations.append(
            f"Failed to extract manifest facts, likely a malformed or unexpected "
            f"AndroidManifest.xml: {exc.__class__.__name__}: {exc}"
        )
    signature = run_with_timeout(
        lambda: extract_signature_info(apk),
        timeout=PARSE_TIMEOUT_SECONDS,
    )

    if manifest_facts.network_security_config.parse_error:
        analysis_limitations.append(
            "Could not parse the declared networkSecurityConfig: "
            f"{manifest_facts.network_security_config.parse_error}"
        )

    code_findings: list[ApkFinding] = []
    network_endpoints: list[str] = []
    try:
        dex_analysis = run_with_timeout(
            lambda: build_dex_analysis(apk),
            timeout=CODE_ANALYSIS_TIMEOUT_SECONDS,
        )
        code_findings = [
            *evaluate_tls_rules(dex_analysis),
            *evaluate_webview_rules(dex_analysis),
            *evaluate_secret_rules(dex_analysis),
            *evaluate_crypto_rules(dex_analysis),
            *evaluate_storage_rules(dex_analysis),
        ]
        network_endpoints = extract_network_endpoints(dex_analysis)
    except ApkAnalysisTimeoutError:
        analysis_limitations.append(
            "DEX/bytecode analysis did not complete within "
            f"{CODE_ANALYSIS_TIMEOUT_SECONDS} seconds and was abandoned; "
            "TLS/WebView/secret findings are unavailable for this run."
        )
    except Exception as exc:
        analysis_limitations.append(
            f"Failed to run DEX/bytecode analysis: {exc.__class__.__name__}: {exc}"
        )

    metadata = ApkMetadata(
        file_name=path.name,
        file_size=path.stat().st_size,
        sha256=compute_sha256(path),
        sha1=compute_sha1(path),
        package_name=manifest_facts.package_name,
        version_name=manifest_facts.version_name,
        version_code=manifest_facts.version_code,
        min_sdk=manifest_facts.min_sdk,
        target_sdk=manifest_facts.target_sdk,
        dex_files=dex_files,
        native_libraries=native_libraries,
    )

    findings = [
        *evaluate_manifest_rules(manifest_facts),
        *evaluate_component_rules(manifest_facts),
        *evaluate_signature_rules(signature),
        *code_findings,
    ]

    return ApkStaticAnalysisReport(
        app_version=__version__,
        metadata=metadata,
        signature=signature,
        permissions=manifest_facts.permissions,
        custom_permissions=manifest_facts.custom_permissions,
        components=manifest_facts.components,
        deep_links=manifest_facts.deep_links,
        network_security_config=manifest_facts.network_security_config,
        findings=findings,
        network_endpoints=network_endpoints,
        analysis_limitations=analysis_limitations,
    )
