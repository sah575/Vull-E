import json
from pathlib import Path

from vulle.rag.documents import (
    chunk_markdown_sections,
    document_ids_for_path,
    load_documents,
    stable_chunk_id,
    stable_document_id,
)


def test_stable_chunk_id_is_stable_uuid() -> None:
    first = stable_chunk_id("source.md", 0, "hello")
    second = stable_chunk_id("source.md", 0, "hello")
    assert first == second
    assert len(first) == 36


def test_stable_document_id_depends_only_on_source() -> None:
    assert stable_document_id("docs/a.md") == stable_document_id("docs/a.md")
    assert stable_document_id("docs/a.md") != stable_document_id("docs/b.md")


def test_chunk_markdown_sections_preserves_headings() -> None:
    sections = chunk_markdown_sections(
        "# Title\n\nIntro\n\n## Table\n\n| A | B |\n| - | - |\n| 1 | 2 |"
    )
    titles = [title for title, _ in sections]
    assert "Title" in titles
    assert "Title > Table" in titles


def test_load_documents_adds_source_type_metadata() -> None:
    chunks = load_documents(Path("docs/knowledge/portswigger"))
    assert chunks
    assert all(chunk.metadata["source_type"] == "portswigger" for chunk in chunks)
    assert all("source_priority" in chunk.metadata for chunk in chunks)
    assert all("control_areas" in chunk.metadata for chunk in chunks)
    assert all("document_id" in chunk.metadata for chunk in chunks)
    assert all("content_hash" in chunk.metadata for chunk in chunks)
    assert all("index_root" in chunk.metadata for chunk in chunks)


def test_generated_source_directories_keep_authority_metadata(tmp_path: Path) -> None:
    root = tmp_path / "docs/knowledge/generated"
    for source_dir, expected_type, expected_priority in [
        ("owasp-wstg", "owasp", 0.60),
        ("mitre-cwe", "mitre", 0.65),
        ("payloads", "payloads", 0.50),
    ]:
        path = root / source_dir / "example.md"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            "# Example\n\nAuthorization and injection testing guidance for APIs.",
            encoding="utf-8",
        )
        chunks = load_documents(path)
        assert chunks
        assert chunks[0].metadata["source_type"] == expected_type
        assert chunks[0].metadata["source_priority"] == expected_priority


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


def test_empty_document_still_has_document_id(tmp_path: Path) -> None:
    document = tmp_path / "empty.md"
    document.write_text("", encoding="utf-8")

    assert load_documents(document) == []
    assert len(document_ids_for_path(document)) == 1


def test_markdown_code_block_is_not_split(tmp_path: Path) -> None:
    document = tmp_path / "code.md"
    document.write_text(
        "# Example\n\n" + "```text\n" + ("token line\n" * 400) + "```\n",
        encoding="utf-8",
    )

    chunks = load_documents(document)

    code_chunks = [
        chunk for chunk in chunks if chunk.metadata["chunk_type"] == "markdown_code"
    ]
    assert len(code_chunks) == 1
    assert code_chunks[0].text.startswith("```text")
    assert code_chunks[0].text.endswith("```")


def test_large_markdown_table_repeats_header(tmp_path: Path) -> None:
    document = tmp_path / "roles.md"
    rows = "\n".join(f"| role-{index} | action-{index} |" for index in range(250))
    document.write_text(
        "# Roles\n\n| Role | Action |\n| --- | --- |\n" + rows,
        encoding="utf-8",
    )

    chunks = load_documents(document)

    table_chunks = [
        chunk for chunk in chunks if chunk.metadata["chunk_type"] == "markdown_table"
    ]
    assert len(table_chunks) > 1
    assert all("| Role | Action |" in chunk.text for chunk in table_chunks)


def test_json_chunks_preserve_valid_json_and_path(tmp_path: Path) -> None:
    document = tmp_path / "inventory.json"
    payload = {
        "services": {
            f"service-{index}": {"endpoint": f"/api/{index}", "method": "GET"}
            for index in range(300)
        }
    }
    document.write_text(json.dumps(payload), encoding="utf-8")

    chunks = load_documents(document)

    assert chunks
    assert all(json.loads(chunk.text) is not None for chunk in chunks)
    assert all(chunk.metadata["chunk_type"] == "json" for chunk in chunks)
    assert any(chunk.metadata["json_path"] for chunk in chunks)
