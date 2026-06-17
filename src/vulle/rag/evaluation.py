from typing import Any

from vulle.models import RagChunk


def evaluate_case(case: dict[str, Any], chunks: list[RagChunk]) -> dict[str, Any]:
    expected = case.get("expected_sources", case.get("must_retrieve", []))
    expected_types = set(case.get("expected_source_types", []))
    forbidden = case.get("forbidden_sources", [])
    expected_domains = set(case.get("expected_security_domains", []))
    sources = [chunk.source for chunk in chunks]
    source_types = {
        str(chunk.metadata.get("source_type"))
        for chunk in chunks
        if chunk.metadata.get("source_type")
    }
    security_domains = _security_domains(chunks)

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
    domain_hits = sorted(expected_domains.intersection(security_domains))

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
        "expected_security_domains": sorted(expected_domains),
        "security_domain_hits": domain_hits,
        "security_domain_coverage": (
            len(domain_hits) / len(expected_domains) if expected_domains else 1.0
        ),
        "retrieved_security_domains": sorted(security_domains),
        "forbidden_source_hits": forbidden_hits,
        "false_positive_source_rate": (
            len(forbidden_hits) / len(forbidden) if forbidden else 0.0
        ),
        "internal_before_external_guidance": _internal_before_external_guidance(chunks),
    }


def aggregate_results(results: list[dict[str, Any]]) -> dict[str, float]:
    if not results:
        return {
            "mean_recall_at_k": 1.0,
            "mean_precision_at_k": 1.0,
            "mean_mrr": 1.0,
            "mean_source_type_coverage": 1.0,
            "mean_security_domain_coverage": 1.0,
            "mean_false_positive_source_rate": 0.0,
            "internal_before_external_guidance_rate": 1.0,
        }
    count = len(results)
    return {
        "mean_recall_at_k": sum(item["recall_at_k"] for item in results) / count,
        "mean_precision_at_k": sum(item["precision_at_k"] for item in results) / count,
        "mean_mrr": sum(item["mrr"] for item in results) / count,
        "mean_source_type_coverage": (
            sum(item["source_type_coverage"] for item in results) / count
        ),
        "mean_security_domain_coverage": (
            sum(item["security_domain_coverage"] for item in results) / count
        ),
        "mean_false_positive_source_rate": (
            sum(item["false_positive_source_rate"] for item in results) / count
        ),
        "internal_before_external_guidance_rate": (
            sum(
                1.0 if item["internal_before_external_guidance"] else 0.0
                for item in results
            )
            / count
        ),
    }


def _internal_before_external_guidance(chunks: list[RagChunk]) -> bool:
    first_internal = None
    first_external = None
    for index, chunk in enumerate(chunks):
        source_type = chunk.metadata.get("source_type")
        if source_type == "internal" and first_internal is None:
            first_internal = index
        if source_type == "external_pentest_methodology" and first_external is None:
            first_external = index
    if first_internal is None or first_external is None:
        return True
    return first_internal < first_external


def _security_domains(chunks: list[RagChunk]) -> set[str]:
    domains: set[str] = set()
    for chunk in chunks:
        primary = chunk.metadata.get("security_domain")
        if primary:
            domains.add(str(primary))
        secondary = chunk.metadata.get("security_domains")
        if isinstance(secondary, list):
            domains.update(str(item) for item in secondary)
    return domains
