from vulle.models import RagChunk
from vulle.rag.evaluation import aggregate_results, evaluate_case


def test_evaluate_case_reports_ranking_and_source_types() -> None:
    chunks = [
        RagChunk(
            id="1",
            source="docs/knowledge/owasp/other.md",
            title="Other",
            text="other",
            metadata={"source_type": "owasp"},
        ),
        RagChunk(
            id="2",
            source="docs/knowledge/internal/role-matrix.md",
            title="Roles",
            text="roles",
            metadata={"source_type": "internal"},
        ),
    ]
    case = {
        "query": "maker checker",
        "expected_sources": ["internal/role-matrix.md"],
        "expected_source_types": ["internal"],
        "forbidden_sources": ["owasp/other.md"],
    }

    result = evaluate_case(case, chunks)
    summary = aggregate_results([result])

    assert result["recall_at_k"] == 1.0
    assert result["precision_at_k"] == 0.5
    assert result["mrr"] == 0.5
    assert result["source_type_coverage"] == 1.0
    assert result["false_positive_source_rate"] == 1.0
    assert summary["mean_mrr"] == 0.5
