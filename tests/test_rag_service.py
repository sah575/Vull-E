from vulle.models import JiraIssue
from vulle.rag.service import build_issue_queries, trim_context
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
