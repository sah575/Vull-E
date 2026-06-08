from vulle.models import JiraIssue
from vulle.rag.service import build_issue_queries, rerank_chunks, trim_context
from vulle.models import RagChunk


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


def test_trim_context_keeps_context_under_limit() -> None:
    chunks = [
        RagChunk(id="1", source="a", title="A", text="a" * 600),
        RagChunk(id="2", source="b", title="B", text="b" * 600),
    ]

    selected = trim_context(chunks, 800)

    assert len(selected) == 1
    assert selected[0].source == "a"


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
