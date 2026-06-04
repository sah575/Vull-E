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
