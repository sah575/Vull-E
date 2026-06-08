import hashlib
from pathlib import Path
from uuid import NAMESPACE_URL, uuid5

from vulle.models import RagChunk
from vulle.security import redact_text


SUPPORTED_EXTENSIONS = {".md", ".txt", ".json"}
CONTROL_AREA_TERMS = {
    "access_control": {"authorization", "idor", "bola", "role", "permission", "maker", "checker"},
    "authentication": {"authentication", "login", "session", "token", "mfa", "otp", "password"},
    "business_logic": {"workflow", "approve", "reject", "limit", "payment", "transfer", "race"},
    "data_protection": {"pii", "kvkk", "gdpr", "masking", "sensitive", "iban", "logging"},
    "file_handling": {"upload", "download", "file", "document", "mime", "deserialization"},
    "injection": {"injection", "sql", "command", "xss", "template"},
    "integration_security": {"ssrf", "webhook", "callback", "integration", "third-party"},
}


def load_documents(path: Path) -> list[RagChunk]:
    files = _iter_supported_files(path)
    chunks: list[RagChunk] = []
    for file_path in files:
        text = redact_text(file_path.read_text(encoding="utf-8")) or ""
        title = _title_for(file_path, text)
        sections = chunk_markdown_sections(text) if file_path.suffix.lower() == ".md" else [("", text)]
        chunk_index = 0
        for section_title, section_text in sections:
            for chunk_text in chunk_text_by_words(section_text):
                chunk_id = stable_chunk_id(str(file_path), chunk_index, chunk_text)
                chunks.append(
                    RagChunk(
                        id=chunk_id,
                        source=str(file_path),
                        title=section_title or title,
                        text=chunk_text,
                        metadata={
                            "source": str(file_path),
                            "title": title,
                            "section": section_title,
                            "chunk_index": chunk_index,
                            "source_type": _source_type(file_path),
                            "source_priority": _source_priority(file_path),
                            "is_template": ".template." in file_path.name,
                            "control_areas": _control_areas(chunk_text),
                        },
                    )
                )
                chunk_index += 1
    return chunks


def chunk_markdown_sections(text: str, max_section_words: int = 700) -> list[tuple[str, str]]:
    sections: list[tuple[str, list[str]]] = []
    current_title = ""
    current_lines: list[str] = []

    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("#"):
            if current_lines:
                sections.append((current_title, current_lines))
            current_title = stripped.lstrip("#").strip()
            current_lines = [line]
        else:
            current_lines.append(line)
    if current_lines:
        sections.append((current_title, current_lines))

    result: list[tuple[str, str]] = []
    for section_title, lines in sections:
        section_text = "\n".join(lines).strip()
        if not section_text:
            continue
        if len(section_text.split()) <= max_section_words:
            result.append((section_title, section_text))
            continue
        for index, chunk in enumerate(chunk_text_by_words(section_text, chunk_words=max_section_words, overlap_words=80)):
            suffix = f" part {index + 1}" if section_title else ""
            result.append((f"{section_title}{suffix}".strip(), chunk))
    return result


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
    digest = hashlib.sha256(f"{source}:{index}:{text}".encode("utf-8")).hexdigest()
    return str(uuid5(NAMESPACE_URL, digest))


def _iter_supported_files(path: Path) -> list[Path]:
    if path.is_file():
        return [path] if path.suffix.lower() in SUPPORTED_EXTENSIONS else []
    return sorted(
        item
        for item in path.rglob("*")
        if item.is_file() and item.suffix.lower() in SUPPORTED_EXTENSIONS
    )


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
    if "mitre" in parts:
        return "mitre"
    if "owasp" in parts:
        return "owasp"
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
    }[source_type]


def _control_areas(text: str) -> list[str]:
    terms = set(text.lower().replace("-", " ").split())
    return [
        area
        for area, keywords in CONTROL_AREA_TERMS.items()
        if terms.intersection(keywords)
    ]
