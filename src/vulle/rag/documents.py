import hashlib
from pathlib import Path
from uuid import NAMESPACE_URL, uuid5

from vulle.models import RagChunk


SUPPORTED_EXTENSIONS = {".md", ".txt", ".json"}


def load_documents(path: Path) -> list[RagChunk]:
    files = _iter_supported_files(path)
    chunks: list[RagChunk] = []
    for file_path in files:
        text = file_path.read_text(encoding="utf-8")
        title = _title_for(file_path, text)
        for index, chunk_text in enumerate(chunk_text_by_words(text)):
            chunk_id = stable_chunk_id(str(file_path), index, chunk_text)
            chunks.append(
                RagChunk(
                    id=chunk_id,
                    source=str(file_path),
                    title=title,
                    text=chunk_text,
                    metadata={
                        "source": str(file_path),
                        "title": title,
                        "chunk_index": index,
                    },
                )
            )
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
