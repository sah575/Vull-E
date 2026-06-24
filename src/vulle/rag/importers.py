import csv
import hashlib
import re
import shutil
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Literal

SourceKind = Literal["owasp-wstg", "owasp-api", "payloads", "mitre-cwe", "mitre-capec"]


@dataclass
class ImportReport:
    source_kind: SourceKind
    source_path: str
    output_path: str
    files_scanned: int = 0
    files_written: int = 0
    files_skipped: int = 0
    records_scanned: int = 0
    records_written: int = 0
    warnings: list[str] = field(default_factory=list)

    def model_dump(self) -> dict[str, object]:
        return {
            "source_kind": self.source_kind,
            "source_path": self.source_path,
            "output_path": self.output_path,
            "files_scanned": self.files_scanned,
            "files_written": self.files_written,
            "files_skipped": self.files_skipped,
            "records_scanned": self.records_scanned,
            "records_written": self.records_written,
            "warnings": self.warnings,
        }


OWASP_WSTG_PATTERNS = [
    "**/*Testing_for_APIs*.md",
    "**/*Authentication_Testing/**/*.md",
    "**/*Authorization_Testing/**/*.md",
    "**/*Input_Validation_Testing/**/*.md",
    "**/*Testing_for_Error_Handling/**/*.md",
    "**/*Testing_for_Business_Logic/**/*.md",
    "**/*Testing_for_Session_Management/**/*.md",
    "**/*Testing_for_Weak_Cryptography/**/*.md",
    "**/*WSTG-ATHN*.md",
    "**/*WSTG-ATHZ*.md",
    "**/*WSTG-INPV*.md",
    "**/*WSTG-SESS*.md",
    "**/*WSTG-BUSL*.md",
    "**/*WSTG-ERRH*.md",
]
OWASP_API_PATTERNS = [
    "editions/2023/en/**/*.md",
    "docs/**/*.md",
]
PAYLOADS_PATTERNS = [
    "**/SQL Injection/**/*.md",
    "**/NoSQL Injection/**/*.md",
    "**/Insecure Direct Object References/**/*.md",
    "**/IDOR/**/*.md",
    "**/Server Side Request Forgery/**/*.md",
    "**/Upload Insecure Files/**/*.md",
    "**/XXE Injection/**/*.md",
    "**/JSON Web Token/**/*.md",
    "**/JWT/**/*.md",
    "**/OAuth/**/*.md",
    "**/Open Redirect/**/*.md",
    "**/CORS Misconfiguration/**/*.md",
    "**/Web Cache Deception/**/*.md",
    "**/Race Condition/**/*.md",
    "**/Request Smuggling/**/*.md",
    "**/GraphQL Injection/**/*.md",
    "**/Mass Assignment/**/*.md",
]
LOW_VALUE_NAMES = {
    "LICENSE",
    "CONTRIBUTING.md",
    "DISCLAIMER.md",
    "mkdocs.yml",
}
MITRE_KEYWORDS = {
    "authorization",
    "access control",
    "authentication",
    "session",
    "injection",
    "sql",
    "nosql",
    "ssrf",
    "server-side request forgery",
    "xxe",
    "file upload",
    "deserialization",
    "sensitive",
    "logging",
    "cors",
    "csrf",
    "graphql",
    "open redirect",
    "rate limit",
    "business logic",
    "race condition",
    "request smuggling",
}


def import_owasp_wstg(source: Path, output_root: Path) -> ImportReport:
    return _import_markdown_tree(
        source=source,
        output_root=output_root,
        source_kind="owasp-wstg",
        source_label="OWASP WSTG",
        allow_patterns=OWASP_WSTG_PATTERNS,
        source_url="https://github.com/OWASP/wstg",
        license_note="CC-BY-SA-4.0",
    )


def import_owasp_api(source: Path, output_root: Path) -> ImportReport:
    return _import_markdown_tree(
        source=source,
        output_root=output_root,
        source_kind="owasp-api",
        source_label="OWASP API Security",
        allow_patterns=OWASP_API_PATTERNS,
        source_url="https://github.com/OWASP/API-Security",
        license_note="CC-BY-SA-4.0",
    )


def import_payloads(source: Path, output_root: Path) -> ImportReport:
    return _import_markdown_tree(
        source=source,
        output_root=output_root,
        source_kind="payloads",
        source_label="PayloadsAllTheThings",
        allow_patterns=PAYLOADS_PATTERNS,
        source_url="https://github.com/swisskyrepo/PayloadsAllTheThings",
        license_note="MIT",
    )


def import_mitre_cwe(source: Path, output_root: Path) -> ImportReport:
    return _import_mitre(source, output_root, source_kind="mitre-cwe", source_label="MITRE CWE")


def import_mitre_capec(source: Path, output_root: Path) -> ImportReport:
    return _import_mitre(
        source,
        output_root,
        source_kind="mitre-capec",
        source_label="MITRE CAPEC",
    )


def _import_markdown_tree(
    *,
    source: Path,
    output_root: Path,
    source_kind: SourceKind,
    source_label: str,
    allow_patterns: list[str],
    source_url: str,
    license_note: str,
) -> ImportReport:
    _validate_source(source)
    output_dir = output_root / source_kind
    _reset_output_dir(output_dir)
    report = ImportReport(
        source_kind=source_kind,
        source_path=str(source),
        output_path=str(output_dir),
    )
    for path in sorted(source.rglob("*.md")):
        report.files_scanned += 1
        relative = path.relative_to(source).as_posix()
        if path.name in LOW_VALUE_NAMES or not _matches_any(relative, allow_patterns):
            report.files_skipped += 1
            continue
        text = _read_text(path, report, relative)
        if not text or _low_value_markdown(text):
            report.files_skipped += 1
            continue
        normalized = _normalized_markdown(
            title=_title_for(text, path.stem),
            source_label=source_label,
            source_url=source_url,
            source_path=relative,
            license_note=license_note,
            body=text,
        )
        destination = _unique_destination(output_dir / _safe_relative_markdown_path(relative))
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(normalized, encoding="utf-8")
        report.files_written += 1
    if report.files_written == 0:
        report.warnings.append(
            "No markdown files were imported. Check the source path and expected repository layout."
        )
    return report


def _import_mitre(
    source: Path,
    output_root: Path,
    *,
    source_kind: SourceKind,
    source_label: str,
) -> ImportReport:
    _validate_source(source)
    output_dir = output_root / source_kind
    _reset_output_dir(output_dir)
    report = ImportReport(
        source_kind=source_kind,
        source_path=str(source),
        output_path=str(output_dir),
    )
    records = _mitre_records(source, report)
    for record in records:
        report.records_scanned += 1
        if not _mitre_record_is_relevant(record):
            continue
        identifier = _first_present(record, ["ID", "CWE-ID", "CAPEC-ID", "Name"]).strip()
        name = _first_present(record, ["Name", "Title"]).strip() or identifier
        if not identifier:
            identifier = _slugify(name)
        body = _mitre_markdown(source_label, identifier, name, record)
        destination = output_dir / f"{_slugify(identifier + '-' + name)}.md"
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(body, encoding="utf-8")
        report.records_written += 1
        report.files_written += 1
    if report.records_written == 0:
        report.warnings.append(
            "No MITRE records were imported. Use CWE/CAPEC CSV or XML downloads and verify columns."
        )
    return report


def _mitre_records(source: Path, report: ImportReport) -> list[dict[str, str]]:
    files = (
        [source]
        if source.is_file()
        else sorted([*source.rglob("*.csv"), *source.rglob("*.xml")])
    )
    records: list[dict[str, str]] = []
    for path in files:
        report.files_scanned += 1
        suffix = path.suffix.lower()
        if suffix == ".csv":
            records.extend(_csv_records(path, report))
        elif suffix == ".xml":
            records.extend(_xml_records(path, report))
        else:
            report.files_skipped += 1
    return records


def _csv_records(path: Path, report: ImportReport) -> list[dict[str, str]]:
    try:
        with path.open(encoding="utf-8-sig", newline="") as handle:
            return [
                {str(key or "").strip(): str(value or "").strip() for key, value in row.items()}
                for row in csv.DictReader(handle)
            ]
    except (OSError, UnicodeDecodeError, csv.Error) as exc:
        report.warnings.append(f"Skipped unreadable CSV {path}: {exc.__class__.__name__}")
        return []


def _xml_records(path: Path, report: ImportReport) -> list[dict[str, str]]:
    try:
        root = ET.parse(path).getroot()
    except (OSError, ET.ParseError) as exc:
        report.warnings.append(f"Skipped unreadable XML {path}: {exc.__class__.__name__}")
        return []
    records: list[dict[str, str]] = []
    for element in root.iter():
        tag = _local_name(element.tag)
        if tag not in {"Weakness", "Attack_Pattern"}:
            continue
        record = {
            "ID": element.attrib.get("ID", ""),
            "Name": element.attrib.get("Name", ""),
            "Abstraction": element.attrib.get("Abstraction", ""),
            "Status": element.attrib.get("Status", ""),
        }
        for child in element.iter():
            child_tag = _local_name(child.tag)
            if child_tag in {
                "Description",
                "Extended_Description",
                "Likelihood_Of_Exploit",
                "Typical_Severity",
                "Alternate_Terms",
            }:
                value = _element_text(child)
                if value:
                    record[child_tag.replace("_", " ")] = value
        records.append(record)
    return records


def _mitre_record_is_relevant(record: dict[str, str]) -> bool:
    haystack = " ".join(record.values()).lower()
    if any(keyword in haystack for keyword in MITRE_KEYWORDS):
        return True
    identifier = _first_present(record, ["ID", "CWE-ID", "CAPEC-ID"])
    return identifier in {
        "20",
        "22",
        "78",
        "79",
        "89",
        "200",
        "201",
        "285",
        "287",
        "306",
        "352",
        "434",
        "502",
        "522",
        "532",
        "601",
        "611",
        "639",
        "862",
        "863",
        "918",
    }


def _mitre_markdown(
    source_label: str,
    identifier: str,
    name: str,
    record: dict[str, str],
) -> str:
    lines = [
        f"# {source_label} - {identifier}: {name}".strip(),
        "",
        f"- Source: {source_label}",
        f"- Source ID: {identifier}",
        "- Imported for: Vull-E Tier-1 risk classification and test planning",
        "",
    ]
    preferred = [
        "Description",
        "Extended Description",
        "Extended_Description",
        "Abstraction",
        "Status",
        "Typical Severity",
        "Typical_Severity",
        "Likelihood Of Exploit",
        "Likelihood_Of_Exploit",
    ]
    for key in preferred:
        value = record.get(key)
        if value:
            lines.extend([f"## {key.replace('_', ' ')}", "", _clean_text(value), ""])
    remaining = [
        (key, value)
        for key, value in sorted(record.items())
        if key not in preferred and value and key not in {"ID", "CWE-ID", "CAPEC-ID", "Name"}
    ]
    if remaining:
        lines.extend(["## Additional Fields", ""])
        for key, value in remaining:
            lines.append(f"- {key}: {_clean_text(value)}")
        lines.append("")
    return "\n".join(lines).strip() + "\n"


def _normalized_markdown(
    *,
    title: str,
    source_label: str,
    source_url: str,
    source_path: str,
    license_note: str,
    body: str,
) -> str:
    stripped_body = _strip_front_matter(body).strip()
    return (
        f"# {title}\n\n"
        f"- Source: {source_label}\n"
        f"- Upstream: {source_url}\n"
        f"- Upstream path: `{source_path}`\n"
        f"- License: {license_note}\n"
        "- Imported for: Vull-E Tier-1/Tier-2 security guidance\n\n"
        "## Imported Content\n\n"
        f"{stripped_body}\n"
    )


def _validate_source(source: Path) -> None:
    if not source.exists():
        raise FileNotFoundError(f"Source path does not exist: {source}")


def _reset_output_dir(path: Path) -> None:
    if path.exists():
        shutil.rmtree(path)
    path.mkdir(parents=True, exist_ok=True)


def _read_text(path: Path, report: ImportReport, relative: str) -> str | None:
    try:
        return path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        try:
            return path.read_text(encoding="utf-8-sig")
        except UnicodeDecodeError:
            report.warnings.append(f"Skipped non-UTF-8 markdown: {relative}")
            return None


def _matches_any(value: str, patterns: list[str]) -> bool:
    normalized = value.replace("\\", "/")
    return any(
        PurePosixPath(normalized).match(pattern)
        or (pattern.startswith("**/") and PurePosixPath(normalized).match(pattern[3:]))
        or _relaxed_pattern_match(normalized, pattern)
        for pattern in patterns
    )


def _relaxed_pattern_match(value: str, pattern: str) -> bool:
    normalized = value.lower()
    probe = pattern.lower()
    probe = probe.replace("**/", "").replace("/**/*.md", "")
    probe = probe.replace("*.md", "").replace("*", "")
    probe = probe.strip("/")
    if not probe:
        return False
    return probe in normalized


def _low_value_markdown(text: str) -> bool:
    words = re.findall(r"[A-Za-z0-9_]+", text)
    return len(words) < 20


def _title_for(text: str, fallback: str) -> str:
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("#"):
            return stripped.lstrip("#").strip() or fallback
    return fallback.replace("-", " ").replace("_", " ").strip().title()


def _strip_front_matter(text: str) -> str:
    lines = text.splitlines()
    if lines and lines[0].strip() == "---":
        for index, line in enumerate(lines[1:], start=1):
            if line.strip() == "---":
                return "\n".join(lines[index + 1 :])
    return text


def _safe_relative_markdown_path(value: str) -> Path:
    path = Path(value)
    parts = [_slugify(part) for part in path.with_suffix("").parts]
    return Path(*parts).with_suffix(".md")


def _unique_destination(path: Path) -> Path:
    if not path.exists():
        return path
    digest = hashlib.sha256(path.as_posix().encode("utf-8")).hexdigest()[:8]
    candidate = path.with_name(f"{path.stem}-{digest}{path.suffix}")
    index = 2
    while candidate.exists():
        candidate = path.with_name(f"{path.stem}-{digest}-{index}{path.suffix}")
        index += 1
    return candidate


def _slugify(value: str) -> str:
    value = value.strip().lower()
    value = re.sub(r"[^a-z0-9._-]+", "-", value)
    value = re.sub(r"-{2,}", "-", value).strip("-._")
    return value or "item"


def _first_present(record: dict[str, str], keys: list[str]) -> str:
    for key in keys:
        value = record.get(key)
        if value:
            return value
    return ""


def _clean_text(value: str) -> str:
    return re.sub(r"\s+", " ", value).strip()


def _local_name(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _element_text(element: ET.Element) -> str:
    return _clean_text(" ".join(text for text in element.itertext() if text.strip()))
