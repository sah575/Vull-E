import hashlib
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from uuid import NAMESPACE_URL, uuid5

from vulle.models import RagChunk, RagIndexReport
from vulle.rag.hacktricks import (
    HACKTRICKS_SOURCE_NAME,
    HACKTRICKS_SOURCE_TYPE,
    HackTricksLoadReport,
    classify_security_domains,
    hacktricks_chunk_id,
    is_low_value_chunk,
    load_hacktricks_config,
    select_hacktricks_documents,
)
from vulle.security import PiiRedactionMode, redact_text

SUPPORTED_EXTENSIONS = {".md", ".txt", ".json"}
DEFAULT_EXCLUDED_DIRS = {
    ".git",
    ".venv",
    "venv",
    "node_modules",
    "__pycache__",
    "dist",
    "build",
    "assets",
    "asset",
    "img",
    "images",
}
CONTROL_AREA_TERMS = {
    "access_control": {"authorization", "idor", "bola", "role", "permission", "maker", "checker"},
    "authentication": {"authentication", "login", "session", "token", "mfa", "otp", "password"},
    "business_logic": {"workflow", "approve", "reject", "limit", "payment", "transfer", "race"},
    "data_protection": {"pii", "kvkk", "gdpr", "masking", "sensitive", "iban", "logging"},
    "file_handling": {"upload", "download", "file", "document", "mime", "deserialization"},
    "injection": {"injection", "sql", "command", "xss", "template"},
    "integration_security": {"ssrf", "webhook", "callback", "integration", "third-party"},
}
HEADING_PATTERN = re.compile(r"^(#{1,6})\s+(.+?)\s*$")
TABLE_SEPARATOR_PATTERN = re.compile(
    r"^\s*\|?(?:\s*:?-{3,}:?\s*\|)+\s*:?-{3,}:?\s*\|?\s*$"
)


@dataclass
class DocumentPart:
    title: str
    text: str
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class DocumentLoadOptions:
    source_name: str = "local"
    tenant_id: str = "default"
    environment: str = "preprod"
    knowledge_base_id: str = "default"
    index_schema_version: int = 2
    max_file_size_mb: int = 10
    max_total_files: int = 10000
    max_chunks_per_document: int = 500
    follow_symlinks: bool = False


@dataclass
class DocumentLoadResult:
    chunks: list[RagChunk]
    report: RagIndexReport


def load_documents(
    path: Path,
    *,
    pii_mode: PiiRedactionMode = "off",
    source_profile: str = "default",
    id_namespace: str = "",
    options: DocumentLoadOptions | None = None,
) -> list[RagChunk]:
    if source_profile == "hacktricks":
        hacktricks_chunks, _ = load_hacktricks_documents(
            path,
            pii_mode=pii_mode,
            id_namespace=id_namespace,
            options=options,
        )
        return hacktricks_chunks

    return load_documents_with_report(
        path,
        pii_mode=pii_mode,
        options=options,
    ).chunks


def load_documents_with_report(
    path: Path,
    *,
    pii_mode: PiiRedactionMode = "off",
    options: DocumentLoadOptions | None = None,
) -> DocumentLoadResult:
    options = options or DocumentLoadOptions()
    files, report = _iter_supported_files_with_report(path, options)
    index_root = normalized_path(path)
    chunks: list[RagChunk] = []
    seen_chunk_ids: set[str] = set()
    for file_path in files:
        relative_source = logical_relative_path(file_path, path)
        raw_text = _read_text(file_path, relative_source, report)
        if raw_text is None:
            continue
        text = redact_text(raw_text, pii_mode=pii_mode) or ""
        source = relative_source
        document_id = scoped_document_id(
            source_name=options.source_name,
            tenant_id=options.tenant_id,
            environment=options.environment,
            knowledge_base_id=options.knowledge_base_id,
            relative_path=relative_source,
            index_schema_version=options.index_schema_version,
        )
        content_hash = hashlib.sha256(text.encode("utf-8")).hexdigest()
        title = _title_for(file_path, text)
        parts = _document_parts(file_path, text)
        chunk_index = 0
        document_chunks = 0
        report.files_accepted += 1
        for part in parts:
            atomic = part.metadata.get("chunk_type") in {
                "json",
                "markdown_code",
                "markdown_table",
            }
            part_chunks = [part.text] if atomic else chunk_text_by_words(part.text)
            for chunk_text in part_chunks:
                if document_chunks >= options.max_chunks_per_document:
                    report.chunks_truncated += 1
                    report.warnings.append(
                        f"Chunk limit reached for {relative_source}; remaining chunks skipped."
                    )
                    break
                heading_path = [str(item) for item in part.metadata.get("section_path", [])]
                chunk_id = scoped_chunk_id(
                    document_id=document_id,
                    heading_path=heading_path,
                    content=chunk_text,
                    index_schema_version=options.index_schema_version,
                )
                if chunk_id in seen_chunk_ids:
                    report.duplicate_chunks += 1
                    continue
                seen_chunk_ids.add(chunk_id)
                source_type = _source_type(file_path)
                report.source_type_distribution[source_type] = (
                    report.source_type_distribution.get(source_type, 0) + 1
                )
                chunks.append(
                    RagChunk(
                        id=chunk_id,
                        source=source,
                        title=part.title or title,
                        text=chunk_text,
                        metadata={
                            "source": source,
                            "title": title,
                            "section": part.title,
                            **part.metadata,
                            "chunk_index": chunk_index,
                            "document_id": document_id,
                            "content_hash": content_hash,
                            "index_root": index_root,
                            "source_name": options.source_name,
                            "source_type": source_type,
                            "source_priority": _source_priority(file_path),
                            "is_template": ".template." in file_path.name,
                            "index_schema_version": options.index_schema_version,
                            "control_areas": _control_areas(chunk_text),
                        },
                    )
                )
                chunk_index += 1
                document_chunks += 1
    report.chunks_created = len(chunks)
    return DocumentLoadResult(chunks=chunks, report=report)


def load_hacktricks_documents(
    path: Path,
    *,
    pii_mode: PiiRedactionMode = "off",
    id_namespace: str = "",
    options: DocumentLoadOptions | None = None,
) -> tuple[list[RagChunk], HackTricksLoadReport]:
    options = options or DocumentLoadOptions(source_name=HACKTRICKS_SOURCE_NAME)
    config = load_hacktricks_config()
    documents, report = select_hacktricks_documents(
        path,
        config=config,
        max_file_size_mb=options.max_file_size_mb,
        max_total_files=options.max_total_files,
    )
    index_root = normalized_path(path)
    chunks: list[RagChunk] = []
    seen_content_hashes: set[str] = set()
    for document in documents:
        text = redact_text(document.text, pii_mode=pii_mode) or ""
        source = f"{HACKTRICKS_SOURCE_NAME}:{document.relative_path}"
        document_id = scoped_document_id(
            source_name=HACKTRICKS_SOURCE_NAME,
            tenant_id=options.tenant_id,
            environment=options.environment,
            knowledge_base_id=id_namespace or options.knowledge_base_id,
            relative_path=document.relative_path,
            index_schema_version=options.index_schema_version,
        )
        content_hash = hashlib.sha256(text.encode("utf-8")).hexdigest()
        parts = _chunk_markdown_parts(text)
        security_domains = classify_security_domains(
            document.relative_path,
            document.title,
            text,
            config,
        )
        chunk_index = 0
        for part in parts:
            heading_path = part.metadata.get("section_path") or []
            header = _hacktricks_chunk_header(document.title, heading_path)
            atomic = part.metadata.get("chunk_type") in {
                "markdown_code",
                "markdown_table",
            }
            part_chunks = [part.text] if atomic else chunk_text_by_words(part.text)
            for raw_chunk_text in part_chunks:
                chunk_text = f"{header}\n\nContent:\n{raw_chunk_text}".strip()
                if is_low_value_chunk(
                    chunk_text,
                    minimum_chars=config.minimum_content_chars,
                ):
                    continue
                chunk_hash = hashlib.sha256(
                    " ".join(chunk_text.lower().split()).encode("utf-8")
                ).hexdigest()
                if chunk_hash in seen_content_hashes:
                    report.deduplicated_chunks += 1
                    continue
                seen_content_hashes.add(chunk_hash)
                chunk_id = hacktricks_chunk_id(
                    source_name=HACKTRICKS_SOURCE_NAME,
                    relative_path=document.relative_path,
                    heading_path=[str(item) for item in heading_path],
                    content=chunk_text,
                    knowledge_base_id=id_namespace or "default",
                    tenant_id=options.tenant_id,
                    environment=options.environment,
                    index_schema_version=options.index_schema_version,
                )
                chunks.append(
                    RagChunk(
                        id=chunk_id,
                        source=source,
                        title=part.title or document.title,
                        text=chunk_text,
                        metadata={
                            "source": source,
                            "title": document.title,
                            "section": part.title,
                            **part.metadata,
                            "heading_path": heading_path,
                            "chunk_index": chunk_index,
                            "document_id": document_id,
                            "content_hash": content_hash,
                            "index_root": index_root,
                            "source_type": HACKTRICKS_SOURCE_TYPE,
                            "source_name": HACKTRICKS_SOURCE_NAME,
                            "source_priority": config.source_priority,
                            "evidence_type": "security_guidance",
                            "authority_level": "guidance",
                            "is_internal": False,
                            "security_domain": document.security_domain,
                            "security_domains": security_domains,
                            "document_path": document.relative_path,
                            "language": config.language,
                            "version": report.commit_sha,
                            "license_review_required": True,
                            "is_template": False,
                            "index_schema_version": options.index_schema_version,
                            "control_areas": _control_areas(
                                f"{document.security_domain} {chunk_text}"
                            ),
                        },
                    )
                )
                report.domain_counts[document.security_domain] = (
                    report.domain_counts.get(document.security_domain, 0) + 1
                )
                chunk_index += 1
    report.chunk_count = len(chunks)
    return chunks, report


def chunk_markdown_sections(text: str, max_section_words: int = 700) -> list[tuple[str, str]]:
    return [
        (part.title, part.text)
        for part in _chunk_markdown_parts(text, max_section_words=max_section_words)
    ]


def _chunk_markdown_parts(
    text: str,
    *,
    max_section_words: int = 700,
) -> list[DocumentPart]:
    sections: list[tuple[str, list[str]]] = []
    heading_stack: list[str] = []
    current_path: list[str] = []
    current_lines: list[str] = []

    for line in text.splitlines():
        match = HEADING_PATTERN.match(line.strip())
        if match:
            if current_lines:
                sections.append((" > ".join(current_path), current_lines))
            level = len(match.group(1))
            heading_stack = heading_stack[: level - 1]
            heading_stack.append(match.group(2).strip())
            current_path = list(heading_stack)
            current_lines = [line]
        else:
            current_lines.append(line)
    if current_lines:
        sections.append((" > ".join(current_path), current_lines))

    result: list[DocumentPart] = []
    for section_title, lines in sections:
        section_text = "\n".join(lines).strip()
        if not section_text:
            continue
        if len(section_text.split()) <= max_section_words:
            result.append(
                DocumentPart(
                    title=section_title,
                    text=section_text,
                    metadata={
                        "chunk_type": "markdown_section",
                        "section_path": section_title.split(" > ") if section_title else [],
                    },
                )
            )
            continue
        blocks = _markdown_blocks(section_text)
        for index, (block_type, block_text) in enumerate(blocks):
            chunks = (
                _chunk_table(block_text, max_section_words)
                if block_type == "table"
                else [block_text]
                if block_type == "code"
                else chunk_text_by_words(
                    block_text,
                    chunk_words=max_section_words,
                    overlap_words=80,
                )
            )
            for part_index, chunk in enumerate(chunks):
                suffix = f" part {index + 1}.{part_index + 1}"
                result.append(
                    DocumentPart(
                        title=f"{section_title}{suffix}".strip(),
                        text=chunk,
                        metadata={
                            "chunk_type": f"markdown_{block_type}",
                            "section_path": (
                                section_title.split(" > ") if section_title else []
                            ),
                        },
                    )
                )
    return result


def _document_parts(path: Path, text: str) -> list[DocumentPart]:
    suffix = path.suffix.lower()
    if suffix == ".md":
        return _chunk_markdown_parts(text)
    if suffix == ".json":
        return _chunk_json_parts(text)
    return [DocumentPart(title="", text=text, metadata={"chunk_type": "text"})]


def _chunk_json_parts(text: str, max_words: int = 350) -> list[DocumentPart]:
    try:
        payload = json.loads(text)
    except json.JSONDecodeError:
        return [DocumentPart(title="", text=text, metadata={"chunk_type": "json_invalid"})]

    parts: list[DocumentPart] = []

    def visit(value: Any, path: list[str]) -> None:
        serialized = json.dumps(value, ensure_ascii=False, indent=2)
        if len(serialized.split()) <= max_words or not isinstance(value, (dict, list)):
            title = " > ".join(path) or "JSON document"
            parts.append(
                DocumentPart(
                    title=title,
                    text=serialized,
                    metadata={
                        "chunk_type": "json",
                        "json_path": path,
                        "section_path": path,
                    },
                )
            )
            return
        items = value.items() if isinstance(value, dict) else enumerate(value)
        for key, child in items:
            visit(child, [*path, str(key)])

    visit(payload, [])
    return parts


def _markdown_blocks(text: str) -> list[tuple[str, str]]:
    lines = text.splitlines()
    blocks: list[tuple[str, str]] = []
    prose: list[str] = []
    index = 0

    def flush_prose() -> None:
        if prose:
            value = "\n".join(prose).strip()
            if value:
                blocks.append(("prose", value))
            prose.clear()

    while index < len(lines):
        line = lines[index]
        if line.strip().startswith("```"):
            flush_prose()
            code = [line]
            index += 1
            while index < len(lines):
                code.append(lines[index])
                if lines[index].strip().startswith("```"):
                    index += 1
                    break
                index += 1
            blocks.append(("code", "\n".join(code)))
            continue
        if (
            "|" in line
            and index + 1 < len(lines)
            and TABLE_SEPARATOR_PATTERN.match(lines[index + 1])
        ):
            flush_prose()
            table = [line, lines[index + 1]]
            index += 2
            while index < len(lines) and "|" in lines[index] and lines[index].strip():
                table.append(lines[index])
                index += 1
            blocks.append(("table", "\n".join(table)))
            continue
        prose.append(line)
        index += 1
    flush_prose()
    return blocks


def _chunk_table(text: str, max_words: int) -> list[str]:
    if len(text.split()) <= max_words:
        return [text]
    lines = text.splitlines()
    if len(lines) < 3:
        return chunk_text_by_words(text, chunk_words=max_words, overlap_words=0)
    header = lines[:2]
    chunks: list[str] = []
    current = list(header)
    for row in lines[2:]:
        candidate = "\n".join([*current, row])
        if len(candidate.split()) > max_words and len(current) > 2:
            chunks.append("\n".join(current))
            current = [*header, row]
        else:
            current.append(row)
    if len(current) > 2:
        chunks.append("\n".join(current))
    return chunks


def chunk_text_by_words(text: str, chunk_words: int = 350, overlap_words: int = 60) -> list[str]:
    words = text.split()
    if not words:
        return []
    chunks: list[str] = []
    step = max(chunk_words - overlap_words, 1)
    for start in range(0, len(words), step):
        part = words[start : start + chunk_words]
        if part:
            chunks.append(" ".join(part))
        if start + chunk_words >= len(words):
            break
    return chunks


def stable_chunk_id(source: str, index: int, text: str) -> str:
    digest = hashlib.sha256(f"{source}:{index}:{text}".encode()).hexdigest()
    return str(uuid5(NAMESPACE_URL, digest))


def stable_document_id(source: str) -> str:
    return str(uuid5(NAMESPACE_URL, f"vulle-document:{source}"))


def scoped_document_id(
    *,
    source_name: str,
    tenant_id: str,
    environment: str,
    knowledge_base_id: str,
    relative_path: str,
    index_schema_version: int,
) -> str:
    identity = "|".join(
        [
            str(index_schema_version),
            source_name,
            tenant_id,
            environment,
            knowledge_base_id,
            normalize_logical_path(relative_path),
        ]
    )
    return str(uuid5(NAMESPACE_URL, f"vulle-document:{identity}"))


def scoped_chunk_id(
    *,
    document_id: str,
    heading_path: list[str],
    content: str,
    index_schema_version: int,
) -> str:
    content_hash = hashlib.sha256(content.encode("utf-8")).hexdigest()
    identity = "|".join(
        [
            str(index_schema_version),
            document_id,
            " > ".join(heading_path),
            content_hash,
        ]
    )
    return str(uuid5(NAMESPACE_URL, f"vulle-chunk:{identity}"))


def document_ids_for_path(
    path: Path,
    options: DocumentLoadOptions | None = None,
) -> list[str]:
    if options is not None:
        files = _iter_supported_files_with_report(path, options)[0]
        return [
            scoped_document_id(
                source_name=options.source_name,
                tenant_id=options.tenant_id,
                environment=options.environment,
                knowledge_base_id=options.knowledge_base_id,
                relative_path=logical_relative_path(file_path, path),
                index_schema_version=options.index_schema_version,
            )
            for file_path in files
        ]
    return [
        stable_document_id(normalized_path(file_path))
        for file_path in _iter_supported_files(path)
    ]


def hacktricks_document_ids_for_path(
    path: Path,
    options: DocumentLoadOptions | None = None,
) -> list[str]:
    options = options or DocumentLoadOptions(source_name=HACKTRICKS_SOURCE_NAME)
    documents, _ = select_hacktricks_documents(
        path,
        max_file_size_mb=options.max_file_size_mb,
        max_total_files=options.max_total_files,
    )
    return [
        scoped_document_id(
            source_name=HACKTRICKS_SOURCE_NAME,
            tenant_id=options.tenant_id,
            environment=options.environment,
            knowledge_base_id=options.knowledge_base_id,
            relative_path=document.relative_path,
            index_schema_version=options.index_schema_version,
        )
        for document in documents
    ]


def _iter_supported_files(path: Path) -> list[Path]:
    return _iter_supported_files_with_report(path, DocumentLoadOptions())[0]


def _iter_supported_files_with_report(
    path: Path,
    options: DocumentLoadOptions,
) -> tuple[list[Path], RagIndexReport]:
    report = RagIndexReport()
    root = path if path.is_dir() else path.parent
    try:
        resolved_root = root.resolve()
    except OSError as exc:
        report.errors.append(f"Index root could not be resolved: {exc.__class__.__name__}")
        return [], report
    if path.is_file():
        candidates = [path]
    else:
        candidates = [
            item
            for item in path.rglob("*")
            if not _has_excluded_dir(item, path)
        ]
    files: list[Path] = []
    for item in sorted(candidates):
        if item.is_dir():
            continue
        report.files_scanned += 1
        if item.is_symlink() and not options.follow_symlinks:
            report.files_skipped += 1
            report.warnings.append(f"Skipped symlink: {logical_relative_path(item, root)}")
            continue
        try:
            resolved_file = item.resolve()
        except OSError as exc:
            report.files_failed += 1
            report.warnings.append(
                f"Skipped unresolved path {logical_relative_path(item, root)}: "
                f"{exc.__class__.__name__}"
            )
            continue
        if not _is_relative_to(resolved_file, resolved_root):
            report.files_skipped += 1
            report.warnings.append(
                f"Skipped path outside index root: {logical_relative_path(item, root)}"
            )
            continue
        if item.suffix.lower() not in SUPPORTED_EXTENSIONS:
            report.files_skipped += 1
            continue
        try:
            size = item.stat().st_size
        except OSError as exc:
            report.files_failed += 1
            report.warnings.append(
                f"Skipped unreadable file {logical_relative_path(item, root)}: "
                f"{exc.__class__.__name__}"
            )
            continue
        if size > options.max_file_size_mb * 1024 * 1024:
            report.files_skipped += 1
            report.warnings.append(
                f"Skipped oversized file: {logical_relative_path(item, root)}"
            )
            continue
        files.append(item)
        if len(files) > options.max_total_files:
            report.errors.append(
                f"Maximum file count exceeded: {options.max_total_files}"
            )
            return files[: options.max_total_files], report
    return files, report


def _read_text(path: Path, relative_path: str, report: RagIndexReport) -> str | None:
    try:
        return path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        try:
            return path.read_text(encoding="utf-8-sig")
        except UnicodeDecodeError:
            report.files_failed += 1
            report.warnings.append(f"Skipped non-UTF-8 file: {relative_path}")
            return None


def logical_relative_path(path: Path, root: Path) -> str:
    base = root if root.is_dir() else root.parent
    try:
        value = path.resolve().relative_to(base.resolve()).as_posix()
    except (OSError, ValueError):
        value = path.as_posix()
    return normalize_logical_path(value)


def normalize_logical_path(value: str) -> str:
    return value.replace("\\", "/").lstrip("/")


def _has_excluded_dir(path: Path, root: Path) -> bool:
    try:
        parts = path.relative_to(root).parts
    except ValueError:
        parts = path.parts
    return any(part in DEFAULT_EXCLUDED_DIRS for part in parts[:-1])


def _is_relative_to(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True


def normalized_path(path: Path) -> str:
    try:
        return path.resolve().relative_to(Path.cwd().resolve()).as_posix()
    except ValueError:
        return path.resolve().as_posix()


def _title_for(path: Path, text: str) -> str:
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("#"):
            return stripped.lstrip("#").strip() or path.stem
        if stripped:
            return stripped[:120]
    return path.stem


def _source_type(path: Path) -> str:
    parts = set(path.parts)
    if "internal" in parts:
        return "internal"
    if "portswigger" in parts:
        return "portswigger"
    if "mitre" in parts or any(part.startswith("mitre-") for part in parts):
        return "mitre"
    if "owasp" in parts or any(part.startswith("owasp-") for part in parts):
        return "owasp"
    if "payloads" in parts or "payloadsallthethings" in parts:
        return "payloads"
    return "local"


def _source_priority(path: Path) -> float:
    if ".template." in path.name:
        return 0.15
    source_type = _source_type(path)
    return {
        "internal": 1.0,
        "local": 0.75,
        "mitre": 0.65,
        "owasp": 0.60,
        "portswigger": 0.55,
        "payloads": 0.50,
    }[source_type]


def _hacktricks_chunk_header(title: str, heading_path: list[Any]) -> str:
    section = " > ".join(str(item) for item in heading_path if item)
    if section:
        return f"Title: {title}\nSection: {section}"
    return f"Title: {title}"


def _control_areas(text: str) -> list[str]:
    terms = set(text.lower().replace("-", " ").split())
    return [
        area
        for area, keywords in CONTROL_AREA_TERMS.items()
        if terms.intersection(keywords)
    ]
