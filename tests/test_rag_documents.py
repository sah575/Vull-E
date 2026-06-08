from pathlib import Path

from vulle.rag.documents import chunk_markdown_sections, load_documents, stable_chunk_id


def test_stable_chunk_id_is_stable_uuid() -> None:
    first = stable_chunk_id("source.md", 0, "hello")
    second = stable_chunk_id("source.md", 0, "hello")
    assert first == second
    assert len(first) == 36


def test_chunk_markdown_sections_preserves_headings() -> None:
    sections = chunk_markdown_sections("# Title\n\nIntro\n\n## Table\n\n| A | B |\n| - | - |\n| 1 | 2 |")
    titles = [title for title, _ in sections]
    assert "Title" in titles
    assert "Table" in titles


def test_load_documents_adds_source_type_metadata() -> None:
    chunks = load_documents(Path("docs/knowledge/portswigger"))
    assert chunks
    assert all(chunk.metadata["source_type"] == "portswigger" for chunk in chunks)
    assert all("source_priority" in chunk.metadata for chunk in chunks)
    assert all("control_areas" in chunk.metadata for chunk in chunks)


def test_template_documents_are_marked_low_priority() -> None:
    chunks = load_documents(Path("docs/knowledge/internal/role-matrix.template.md"))

    assert chunks
    assert all(chunk.metadata["is_template"] for chunk in chunks)
    assert all(chunk.metadata["source_priority"] == 0.15 for chunk in chunks)


def test_load_documents_redacts_secrets_before_indexing(tmp_path: Path) -> None:
    document = tmp_path / "knowledge.md"
    document.write_text("# Note\nAuthorization: Bearer secret-token", encoding="utf-8")

    chunks = load_documents(document)

    assert chunks
    assert "secret-token" not in chunks[0].text
    assert "[REDACTED]" in chunks[0].text
