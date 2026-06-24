from types import SimpleNamespace
from uuid import uuid4

from vulle.config import Settings
from vulle.models import RagChunk
from vulle.rag.qdrant_store import QdrantRagStore


class _Client:
    def __init__(self) -> None:
        self.deleted = []
        self.queries = []
        self.upserts = []

    def get_collections(self):
        return SimpleNamespace(collections=[SimpleNamespace(name="knowledge")])

    def create_payload_index(self, **kwargs) -> None:
        return None

    def delete(self, **kwargs) -> None:
        self.deleted.append(kwargs)

    def upsert(self, **kwargs) -> None:
        self.upserts.append(kwargs)

    def query_points(self, **kwargs):
        self.queries.append(kwargs)
        return SimpleNamespace(points=[])


def _store() -> tuple[QdrantRagStore, _Client]:
    store = object.__new__(QdrantRagStore)
    store._settings = Settings(
        qdrant_collection="knowledge",
        rag_tenant_id="bank-a",
        rag_environment="preprod",
        rag_knowledge_base_id="bank-a-security-v1",
    )
    store._scope = {
        "tenant_id": "bank-a",
        "environment": "preprod",
        "knowledge_base_id": "bank-a-security-v1",
    }
    store._payload_indexes_ready = False
    client = _Client()
    store._client = client
    return store, client


def test_search_always_applies_scope_filter() -> None:
    store, client = _store()

    store.search([0.1, 0.2], 5)

    query_filter = client.queries[0]["query_filter"]
    conditions = {
        condition.key: condition.match.value
        for condition in query_filter.must
    }
    assert conditions == {
        "tenant_id": "bank-a",
        "environment": "preprod",
        "knowledge_base_id": "bank-a-security-v1",
    }


def test_sync_deletes_only_scoped_index_root() -> None:
    store, client = _store()

    store.sync_index_root("docs/knowledge", [], [])

    delete_filter = client.deleted[0]["points_selector"]
    conditions = {
        condition.key: condition.match.value
        for condition in delete_filter.must
    }
    assert conditions["tenant_id"] == "bank-a"
    assert conditions["index_root"] == "docs/knowledge"


def test_sync_can_be_limited_to_source_name_and_type() -> None:
    store, client = _store()

    store.sync_index_root(
        "hacktricks-root",
        [],
        [],
        source_name="hacktricks",
        source_type="external_pentest_methodology",
    )

    delete_filter = client.deleted[0]["points_selector"]
    conditions = {
        condition.key: condition.match.value
        for condition in delete_filter.must
    }
    assert conditions["tenant_id"] == "bank-a"
    assert conditions["environment"] == "preprod"
    assert conditions["knowledge_base_id"] == "bank-a-security-v1"
    assert conditions["source_name"] == "hacktricks"
    assert conditions["source_type"] == "external_pentest_methodology"


def test_replace_documents_deletes_previous_document_chunks() -> None:
    store, client = _store()
    chunk = RagChunk(
        id="1",
        source="docs/a.md",
        title="A",
        text="text",
        metadata={"document_id": "doc-1"},
    )

    store.replace_documents([chunk], [[0.1, 0.2]])

    delete_filter = client.deleted[0]["points_selector"]
    document_condition = next(
        condition
        for condition in delete_filter.must
        if condition.key == "document_id"
    )
    assert document_condition.match.any == ["doc-1"]
    assert len(client.upserts) == 1


def test_scope_metadata_cannot_be_overridden_by_chunk() -> None:
    store, client = _store()
    chunk = RagChunk(
        id="1",
        source="docs/a.md",
        title="A",
        text="text",
        metadata={
            "document_id": "doc-1",
            "tenant_id": "attacker",
            "knowledge_base_id": "other",
        },
    )

    store.upsert_chunks([chunk], [[0.1, 0.2]])
    payload = client.upserts[0]["points"][0].payload
    assert payload["tenant_id"] == "bank-a"
    assert payload["knowledge_base_id"] == "bank-a-security-v1"


def test_local_qdrant_path_supports_upsert_and_search(tmp_path) -> None:
    settings = Settings(
        _env_file=None,
        qdrant_path=tmp_path / "qdrant_local",
        qdrant_collection="knowledge",
        embedding_dimensions=2,
        rag_tenant_id="bank-a",
        rag_environment="preprod",
        rag_knowledge_base_id="bank-a-security-v1",
    )
    store = QdrantRagStore(settings)
    chunk = RagChunk(
        id=str(uuid4()),
        source="docs/a.md",
        title="A",
        text="maker checker approval",
        metadata={"document_id": "doc-1"},
    )

    store.upsert_chunks([chunk], [[0.1, 0.2]])
    results = store.search([0.1, 0.2], 1)

    assert settings.qdrant_path.is_dir()
    assert len(results) == 1
    assert results[0].text == "maker checker approval"
