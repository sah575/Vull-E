from vulle.config import Settings
from vulle.models import JiraIssue, RagChunk
from vulle.rag.service import (
    RagService,
    build_issue_queries,
    extract_security_facets,
    rerank_chunks,
    trim_context,
)


def test_build_issue_queries_extracts_security_facets() -> None:
    issue = JiraIssue(
        key="BANK-1",
        summary="Maker checker document approval",
        description=(
            "POST /customers/{customerId}/documents/{documentId}/approve "
            "uses customerId and documentId. Checker approves documents and "
            "PII masking plus audit logging are required."
        ),
    )
    queries = build_issue_queries(issue, [])
    joined = "\n".join(queries)

    assert len(queries) >= 5
    assert "customerId" in joined
    assert "documentId" in joined
    assert "checker" in joined.lower()
    assert "audit" in joined.lower()


def test_security_facets_only_include_detected_areas() -> None:
    facets = extract_security_facets(
        "POST /documents/{documentId}/approve lets checker upload a PDF "
        "and requires audit logging"
    )
    facet_types = {facet.type for facet in facets}

    assert {"authorization", "business_logic", "file_handling", "audit_logging"} <= facet_types
    assert "ssrf_integration" not in facet_types
    assert any("documentId" in facet.terms for facet in facets)


def test_issue_payload_masks_pii_before_retrieval() -> None:
    iban = "TR330006100519786457841326"
    issue = JiraIssue(
        key="BANK-PII",
        summary="Customer payment update",
        description=f"Customer IBAN is {iban}",
    )

    queries = build_issue_queries(issue, [], pii_mode="mask")

    assert iban not in "\n".join(queries)
    assert "[REDACTED:PII]" in queries[0]


def test_search_masks_pii_before_embedding() -> None:
    class FakeEmbeddings:
        embedded_query = ""

        def embed_query(self, query: str) -> list[float]:
            self.embedded_query = query
            return [0.0]

    class FakeStore:
        def search(self, vector: list[float], limit: int) -> list[RagChunk]:
            return []

    settings = Settings(_env_file=None, pii_redaction_mode="mask")
    service = object.__new__(RagService)
    service._settings = settings
    embeddings = FakeEmbeddings()
    service._embeddings = embeddings  # type: ignore[assignment]
    service._store = FakeStore()  # type: ignore[assignment]
    iban = "TR330006100519786457841326"

    service.search(f"Find policy for {iban}")

    assert iban not in embeddings.embedded_query
    assert "[REDACTED:PII]" in embeddings.embedded_query


def test_trim_context_keeps_context_under_limit() -> None:
    chunks = [
        RagChunk(id="1", source="a", title="A", text="a" * 600),
        RagChunk(id="2", source="b", title="B", text="b" * 600),
    ]

    selected = trim_context(chunks, 800)

    assert len(selected) == 1
    assert selected[0].source == "a"
    assert len(selected[0].text) == 600


def test_trim_context_skips_oversized_chunk_without_cutting() -> None:
    chunks = [
        RagChunk(id="1", source="a", title="A", text="a" * 900),
        RagChunk(id="2", source="b", title="B", text="complete"),
    ]

    selected = trim_context(chunks, 800)

    assert [chunk.id for chunk in selected] == ["2"]
    assert selected[0].text == "complete"


def test_trim_context_limits_chunks_per_source() -> None:
    chunks = [
        RagChunk(id="1", source="a", title="A", text="one"),
        RagChunk(id="2", source="a", title="A", text="two"),
        RagChunk(id="3", source="b", title="B", text="three"),
    ]

    selected = trim_context(chunks, 100, max_chunks_per_source=1)

    assert [chunk.id for chunk in selected] == ["1", "3"]


def test_rerank_chunks_uses_lexical_match_and_source_priority() -> None:
    chunks = [
        RagChunk(
            id="generic",
            source="owasp/generic.md",
            title="Generic",
            text="general security guidance",
            score=0.90,
            metadata={"source_type": "owasp", "source_priority": 0.60},
        ),
        RagChunk(
            id="internal",
            source="internal/role-matrix.md",
            title="Maker checker roles",
            text="maker checker branch approval",
            score=0.75,
            metadata={"source_type": "internal", "source_priority": 1.0},
        ),
    ]

    ranked = rerank_chunks(
        "maker checker branch approval",
        chunks,
        2,
        dense_weight=0.40,
        lexical_weight=0.35,
        source_weight=0.25,
    )

    assert ranked[0].id == "internal"
    assert ranked[0].metadata["retrieval"]["lexical_score"] == 1.0
