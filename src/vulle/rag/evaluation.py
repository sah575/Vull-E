from typing import Any

from vulle.models import RagChunk


def evaluate_case(case: dict[str, Any], chunks: list[RagChunk]) -> dict[str, Any]:
    expected = case.get("expected_sources", case.get("must_retrieve", []))
    expected_types = set(case.get("expected_source_types", []))
    forbidden = case.get("forbidden_sources", [])
    sources = [chunk.source for chunk in chunks]
    source_types = {
        str(chunk.metadata.get("source_type"))
        for chunk in chunks
        if chunk.metadata.get("source_type")
    }

    hits = [item for item in expected if any(item in source for source in sources)]
    relevant_ranks = [
        rank
        for rank, source in enumerate(sources, start=1)
        if any(item in source for item in expected)
    ]
    relevant_results = len(relevant_ranks)
    forbidden_hits = [
        item for item in forbidden if any(item in source for source in sources)
    ]
    type_hits = sorted(expected_types.intersection(source_types))

    return {
        "query": case["query"],
        "expected_sources": expected,
        "hits": hits,
        "misses": [item for item in expected if item not in hits],
        "retrieved_sources": sources,
        "recall_at_k": len(hits) / len(expected) if expected else 1.0,
        "precision_at_k": relevant_results / len(sources) if sources else 0.0,
        "mrr": 1.0 / min(relevant_ranks) if relevant_ranks else 0.0,
        "expected_source_types": sorted(expected_types),
        "source_type_hits": type_hits,
        "source_type_coverage": (
            len(type_hits) / len(expected_types) if expected_types else 1.0
        ),
        "retrieved_source_types": sorted(source_types),
        "forbidden_source_hits": forbidden_hits,
        "false_positive_source_rate": (
            len(forbidden_hits) / len(forbidden) if forbidden else 0.0
        ),
    }


def aggregate_results(results: list[dict[str, Any]]) -> dict[str, float]:
    if not results:
        return {
            "mean_recall_at_k": 1.0,
            "mean_precision_at_k": 1.0,
            "mean_mrr": 1.0,
            "mean_source_type_coverage": 1.0,
            "mean_false_positive_source_rate": 0.0,
        }
    count = len(results)
    return {
        "mean_recall_at_k": sum(item["recall_at_k"] for item in results) / count,
        "mean_precision_at_k": sum(item["precision_at_k"] for item in results) / count,
        "mean_mrr": sum(item["mrr"] for item in results) / count,
        "mean_source_type_coverage": (
            sum(item["source_type_coverage"] for item in results) / count
        ),
        "mean_false_positive_source_rate": (
            sum(item["false_positive_source_rate"] for item in results) / count
        ),
    }
