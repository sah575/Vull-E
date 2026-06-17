from pathlib import Path

import pytest

from vulle.config import Settings
from vulle.models import RagChunk
from vulle.rag.documents import (
    DocumentLoadOptions,
    load_documents_with_report,
    normalize_logical_path,
    scoped_chunk_id,
    scoped_document_id,
)
from vulle.rag.indexing import RagIndexBatchError, RetryPolicy, batch_count, batched, run_with_retry
from vulle.rag.service import RagService


class FakeEmbeddings:
    def __init__(self, *, fail_batch: int | None = None, mismatch: bool = False) -> None:
        self.calls: list[list[str]] = []
        self.fail_batch = fail_batch
        self.mismatch = mismatch

    def embed_texts(self, texts: list[str]) -> list[list[float]]:
        self.calls.append(texts)
        if self.fail_batch == len(self.calls):
            raise TimeoutError("temporary")
        if self.mismatch:
            return [[0.0] for _ in texts[:-1]]
        return [[float(index)] for index, _ in enumerate(texts)]


class FakeStore:
    def __init__(self, *, fail_upsert_once: bool = False) -> None:
        self.deleted: list[dict[str, object]] = []
        self.synced: list[dict[str, object]] = []
        self.upserts: list[list[str]] = []
        self.fail_upsert_once = fail_upsert_once

    def delete_documents(self, document_ids, *, source_name=None, source_type=None) -> None:
        self.deleted.append(
            {
                "document_ids": document_ids,
                "source_name": source_name,
                "source_type": source_type,
            }
        )

    def sync_index_root(
        self,
        index_root,
        chunks,
        vectors,
        *,
        source_name=None,
        source_type=None,
    ) -> None:
        self.synced.append(
            {
                "index_root": index_root,
                "source_name": source_name,
                "source_type": source_type,
            }
        )

    def upsert_chunks(self, chunks: list[RagChunk], vectors: list[list[float]]) -> None:
        if self.fail_upsert_once:
            self.fail_upsert_once = False
            raise ConnectionError("qdrant unavailable")
        self.upserts.append([chunk.id for chunk in chunks])


def _service(settings: Settings, embeddings: FakeEmbeddings, store: FakeStore) -> RagService:
    service = object.__new__(RagService)
    service._settings = settings
    service._embeddings = embeddings
    service._store = store
    return service


def _write_docs(root: Path, count: int) -> None:
    root.mkdir(parents=True, exist_ok=True)
    for index in range(count):
        (root / f"doc-{index}.md").write_text(
            f"# Doc {index}\n\nAuthorization test content {index}.",
            encoding="utf-8",
        )


def test_batched_boundaries() -> None:
    assert list(batched([], 32)) == []
    assert [len(batch) for batch in batched([1], 32)] == [1]
    assert [len(batch) for batch in batched(list(range(33)), 32)] == [32, 1]
    assert batch_count(0, 32) == 0
    assert batch_count(33, 32) == 2


def test_retry_succeeds_without_real_sleep() -> None:
    sleeps: list[float] = []
    attempts = {"count": 0}

    def operation() -> str:
        attempts["count"] += 1
        if attempts["count"] == 1:
            raise TimeoutError("temporary")
        return "ok"

    result, failures = run_with_retry(
        operation,
        operation_name="embedding",
        batch_number=2,
        total_batches=3,
        policy=RetryPolicy(3, 1.0, sleeps.append),
    )

    assert result == "ok"
    assert failures == 1
    assert sleeps == [1.0]


def test_retry_limit_reports_batch_number() -> None:
    with pytest.raises(RagIndexBatchError, match="qdrant_upsert batch 2/4"):
        run_with_retry(
            lambda: (_ for _ in ()).throw(ConnectionError("down")),
            operation_name="qdrant_upsert",
            batch_number=2,
            total_batches=4,
            policy=RetryPolicy(2, 0.0, lambda _: None),
        )


def test_dry_run_does_not_call_embedding_or_qdrant(tmp_path: Path) -> None:
    _write_docs(tmp_path, 3)
    embeddings = FakeEmbeddings()
    store = FakeStore()
    service = _service(Settings(_env_file=None), embeddings, store)

    report = service.index_path_report(tmp_path, dry_run=True)

    assert report.dry_run
    assert report.files_accepted == 3
    assert report.chunks_created == 3
    assert report.embedding_batches == 1
    assert not embeddings.calls
    assert not store.deleted
    assert not store.synced
    assert not store.upserts


def test_hacktricks_dry_run_does_not_call_embedding_or_qdrant() -> None:
    embeddings = FakeEmbeddings()
    store = FakeStore()
    service = _service(Settings(_env_file=None), embeddings, store)

    report = service.index_hacktricks_report(
        Path("tests/fixtures/hacktricks"),
        sync=True,
        dry_run=True,
    )

    assert report.dry_run
    assert report.files_accepted == 4
    assert report.commit_sha
    assert not embeddings.calls
    assert not store.deleted
    assert not store.synced
    assert not store.upserts


def test_embedding_and_qdrant_batches_are_bounded(tmp_path: Path) -> None:
    _write_docs(tmp_path, 33)
    embeddings = FakeEmbeddings()
    store = FakeStore()
    settings = Settings(
        _env_file=None,
        embedding_batch_size=32,
        qdrant_upsert_batch_size=16,
        rag_index_retry_base_delay_seconds=0,
    )

    report = _service(settings, embeddings, store).index_path_report(tmp_path)

    assert [len(call) for call in embeddings.calls] == [32, 1]
    assert [len(batch) for batch in store.upserts] == [16, 16, 1]
    assert report.embedding_batches == 2
    assert report.qdrant_batches == 3
    assert report.chunks_upserted == 33


def test_embedding_count_mismatch_fails(tmp_path: Path) -> None:
    _write_docs(tmp_path, 2)
    service = _service(
        Settings(_env_file=None, embedding_batch_size=2),
        FakeEmbeddings(mismatch=True),
        FakeStore(),
    )

    with pytest.raises(ValueError, match="Embedding response count mismatch"):
        service.index_path_report(tmp_path)


def test_second_embedding_batch_error_reports_batch(tmp_path: Path) -> None:
    _write_docs(tmp_path, 33)
    service = _service(
        Settings(
            _env_file=None,
            embedding_batch_size=32,
            rag_index_retry_count=1,
            rag_index_retry_base_delay_seconds=0,
        ),
        FakeEmbeddings(fail_batch=2),
        FakeStore(),
    )

    with pytest.raises(RagIndexBatchError, match="embedding batch 2/2"):
        service.index_path_report(tmp_path)


def test_qdrant_retry_does_not_duplicate_successful_point(tmp_path: Path) -> None:
    _write_docs(tmp_path, 1)
    store = FakeStore(fail_upsert_once=True)
    settings = Settings(
        _env_file=None,
        rag_index_retry_count=2,
        rag_index_retry_base_delay_seconds=0,
    )

    report = _service(settings, FakeEmbeddings(), store).index_path_report(tmp_path)

    assert report.retry_count == 1
    assert len(store.upserts) == 1
    assert len(store.upserts[0]) == 1


def test_file_security_skips_symlink_big_file_git_and_bad_encoding(tmp_path: Path) -> None:
    root = tmp_path / "docs"
    root.mkdir()
    (root / "ok.md").write_text("# OK\n\nsmall content", encoding="utf-8")
    (root / ".git").mkdir()
    (root / ".git" / "hidden.md").write_text("# Hidden", encoding="utf-8")
    (root / "big.md").write_text("x" * (1024 * 1024 + 1), encoding="utf-8")
    (root / "bad.md").write_bytes(b"\xff\xfe\x00")
    outside = tmp_path / "outside.md"
    outside.write_text("# Outside", encoding="utf-8")
    (root / "outside-link.md").symlink_to(outside)

    result = load_documents_with_report(
        root,
        options=DocumentLoadOptions(max_file_size_mb=1, follow_symlinks=False),
    )

    assert [chunk.source for chunk in result.chunks] == ["ok.md"]
    assert result.report.files_accepted == 1
    assert result.report.files_skipped >= 2
    assert result.report.files_failed == 1
    assert any("symlink" in warning for warning in result.report.warnings)
    assert any("non-UTF-8" in warning for warning in result.report.warnings)


def test_max_file_and_chunk_limits_are_reported(tmp_path: Path) -> None:
    root = tmp_path / "docs"
    root.mkdir()
    (root / "a.md").write_text("# A\n\none", encoding="utf-8")
    (root / "b.md").write_text("# B\n\ntwo", encoding="utf-8")

    limited_files = load_documents_with_report(
        root,
        options=DocumentLoadOptions(max_total_files=1),
    )
    assert limited_files.report.errors

    many_sections = root / "many.md"
    many_sections.write_text(
        "\n".join(f"## Section {index}\ncontent {index}" for index in range(5)),
        encoding="utf-8",
    )
    limited_chunks = load_documents_with_report(
        many_sections,
        options=DocumentLoadOptions(max_chunks_per_document=2),
    )
    assert len(limited_chunks.chunks) == 2
    assert limited_chunks.report.chunks_truncated > 0


def test_scoped_ids_are_machine_independent_and_isolated() -> None:
    first = scoped_document_id(
        source_name="local",
        tenant_id="bank-a",
        environment="preprod",
        knowledge_base_id="kb",
        relative_path="docs\\file.md",
        index_schema_version=2,
    )
    second = scoped_document_id(
        source_name="local",
        tenant_id="bank-a",
        environment="preprod",
        knowledge_base_id="kb",
        relative_path="docs/file.md",
        index_schema_version=2,
    )
    other_tenant = scoped_document_id(
        source_name="local",
        tenant_id="bank-b",
        environment="preprod",
        knowledge_base_id="kb",
        relative_path="docs/file.md",
        index_schema_version=2,
    )

    assert normalize_logical_path("C:\\tmp\\docs\\file.md") == "C:/tmp/docs/file.md"
    assert first == second
    assert first != other_tenant
    assert scoped_chunk_id(
        document_id=first,
        heading_path=["A"],
        content="one",
        index_schema_version=2,
    ) != scoped_chunk_id(
        document_id=first,
        heading_path=["A"],
        content="two",
        index_schema_version=2,
    )


def test_sync_zero_accepted_files_does_not_delete(tmp_path: Path) -> None:
    (tmp_path / "unsupported.bin").write_bytes(b"binary")
    store = FakeStore()
    service = _service(Settings(_env_file=None), FakeEmbeddings(), store)

    report = service.index_path_report(tmp_path, sync=True)

    assert report.files_accepted == 0
    assert not store.synced
    assert any("Sync delete skipped" in warning for warning in report.warnings)
