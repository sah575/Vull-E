import json
import re
from pathlib import Path

from vulle.config import Settings
from vulle.models import ConfluencePage, JiraIssue, RagChunk, SecurityFacet
from vulle.rag.documents import (
    document_ids_for_path,
    hacktricks_document_ids_for_path,
    load_documents,
    load_hacktricks_documents,
    normalized_path,
)
from vulle.rag.embeddings import EmbeddingClient
from vulle.rag.qdrant_store import QdrantRagStore
from vulle.security import PiiRedactionMode, redact_data, redact_text

TOKEN_PATTERN = re.compile(r"[a-zA-Z0-9_./{}:-]+")
ENDPOINT_PATTERN = re.compile(
    r"\b(?:GET|POST|PUT|PATCH|DELETE)\s+/[^\s,\"')]+",
    re.I,
)
IDENTIFIER_PATTERN = re.compile(r"\b[a-zA-Z][a-zA-Z0-9_]*(?:Id|ID)\b")
FACET_TERMS = {
    "authorization": {
        "authorization", "permission", "role", "yetki", "maker", "checker",
        "approver", "branch", "tenant", "ownership", "impersonation", "admin",
        "idor", "bola", "bfla",
    },
    "authentication_session": {
        "authentication", "login", "logout", "session", "cookie", "token",
        "jwt", "oauth", "password", "mfa", "otp", "refresh token", "device",
    },
    "business_logic": {
        "workflow", "approve", "reject", "submit", "cancel", "reverse", "refund",
        "limit", "payment", "transfer", "replay", "duplicate", "idempotency",
        "maker checker", "state transition",
    },
    "file_handling": {
        "upload", "download", "file", "document", "pdf", "excel", "csv", "xml",
        "archive", "zip", "mime", "preview", "parser", "deserialize", "dosya",
    },
    "sensitive_data": {
        "pii", "kvkk", "gdpr", "mask", "iban", "card", "pan", "cvv", "email",
        "phone", "address", "nationalid", "customer data", "export",
    },
    "audit_logging": {
        "audit", "logging", "log", "correlationid", "actor", "timestamp",
        "denied attempt", "security event",
    },
    "ssrf_integration": {
        "ssrf", "webhook", "callback", "url", "integration", "third party",
        "metadata service", "private ip", "allowlist", "signature",
    },
    "injection": {
        "injection", "sql", "command", "template", "xss", "ldap", "xpath",
        "formula", "query", "filter expression",
    },
    "graphql_api": {
        "graphql", "mutation", "resolver", "schema", "introspection",
        "nested field", "field-level",
    },
    "race_replay": {
        "race", "concurrent", "parallel", "replay", "duplicate submission",
        "idempotency", "double spend",
    },
    "mass_assignment": {
        "mass assignment", "object property", "bind", "dto", "hidden field",
        "isadmin", "roleid", "status field",
    },
    "rate_limit_resource": {
        "rate limit", "throttle", "brute force", "resource exhaustion",
        "large payload", "pagination", "bulk", "otp abuse",
    },
    "misconfiguration": {
        "cors", "csrf", "debug", "swagger", "openapi", "actuator", "error",
        "stack trace", "security header", "cache",
    },
}


class RagService:
    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        self._embeddings = EmbeddingClient(settings)
        self._store = QdrantRagStore(settings)

    def index_path(self, path: Path, *, sync: bool = False) -> int:
        chunks = load_documents(path, pii_mode=self._settings.pii_redaction_mode)
        vectors = self._embeddings.embed_texts([chunk.text for chunk in chunks])
        if sync:
            self._store.sync_index_root(normalized_path(path), chunks, vectors)
        else:
            self._store.replace_documents(
                chunks,
                vectors,
                document_ids=document_ids_for_path(path),
            )
        return len(chunks)

    def index_hacktricks(self, path: Path, *, sync: bool = False) -> dict[str, object]:
        chunks, report = load_hacktricks_documents(
            path,
            pii_mode=self._settings.pii_redaction_mode,
            id_namespace=self._settings.rag_knowledge_base_id
            or f"{self._settings.qdrant_collection}:{self._settings.rag_environment}",
        )
        vectors = self._embeddings.embed_texts([chunk.text for chunk in chunks])
        if sync:
            self._store.sync_index_root(normalized_path(path), chunks, vectors)
        else:
            self._store.replace_documents(
                chunks,
                vectors,
                document_ids=hacktricks_document_ids_for_path(path),
            )
        return {
            "scanned_files": report.scanned_files,
            "accepted_files": report.accepted_files,
            "excluded_files": report.excluded_files,
            "chunk_count": report.chunk_count,
            "deduplicated_chunks": report.deduplicated_chunks,
            "domain_counts": report.domain_counts,
            "commit_sha": report.commit_sha,
            "warnings": report.warnings,
        }

    def search(self, query: str, limit: int | None = None) -> list[RagChunk]:
        redacted_query = (
            redact_text(
                query,
                pii_mode=self._settings.pii_redaction_mode,
            )
            or ""
        )
        result_limit = limit or self._settings.rag_top_k
        candidate_limit = result_limit * self._settings.rag_candidate_multiplier
        vector = self._embeddings.embed_query(redacted_query)
        candidates = self._store.search(vector, candidate_limit)
        return rerank_chunks(
            redacted_query,
            candidates,
            result_limit,
            dense_weight=self._settings.rag_dense_weight,
            lexical_weight=self._settings.rag_lexical_weight,
            source_weight=self._settings.rag_source_weight,
        )

    def retrieve_for_issue(
        self,
        issue: JiraIssue,
        confluence_pages: list[ConfluencePage],
    ) -> list[RagChunk]:
        queries = build_issue_queries(
            issue,
            confluence_pages,
            pii_mode=self._settings.pii_redaction_mode,
        )
        candidates: dict[str, RagChunk] = {}
        per_query_limit = max(self._settings.rag_top_k, 4)
        for query in queries:
            for chunk in self.search(query, per_query_limit):
                current = candidates.get(chunk.id)
                if current is None or _score(chunk) > _score(current):
                    candidates[chunk.id] = chunk
        chunks = sorted(candidates.values(), key=_score, reverse=True)
        return trim_context(
            chunks,
            self._settings.rag_max_context_chars,
            max_chunks_per_source=self._settings.rag_max_chunks_per_source,
        )


def build_issue_query(issue: JiraIssue, confluence_pages: list[ConfluencePage]) -> str:
    return build_issue_queries(issue, confluence_pages)[0]


def build_issue_queries(
    issue: JiraIssue,
    confluence_pages: list[ConfluencePage],
    *,
    pii_mode: PiiRedactionMode = "off",
) -> list[str]:
    text = _issue_text(issue, confluence_pages, pii_mode=pii_mode)
    payload = redact_data(
        {
            "summary": issue.summary,
            "description": issue.description,
            "acceptance_criteria": issue.acceptance_criteria,
            "labels": issue.labels,
            "components": issue.components,
            "comments": issue.comments,
            "confluence_titles": [page.title for page in confluence_pages],
            "confluence_excerpt": [page.body_text[:1200] for page in confluence_pages],
        },
        pii_mode=pii_mode,
    )
    facets = extract_security_facets(text)
    queries = [json.dumps(payload, ensure_ascii=False)]
    queries.extend(
        f"security facet {facet.type}: {' '.join(facet.terms)}"
        for facet in facets
    )
    return [query for query in queries if query.strip()]


def extract_security_facets(text: str) -> list[SecurityFacet]:
    lowered = text.lower()
    shared_terms = sorted(
        {
            *ENDPOINT_PATTERN.findall(text),
            *IDENTIFIER_PATTERN.findall(text),
        },
        key=str.lower,
    )
    facets: list[SecurityFacet] = []
    for facet_type, vocabulary in FACET_TERMS.items():
        matched = sorted(
            {
                term
                for term in vocabulary
                if re.search(
                    rf"(?<!\w){re.escape(term)}(?!\w)",
                    lowered,
                    re.IGNORECASE,
                )
            }
        )
        if matched:
            facets.append(
                SecurityFacet(
                    type=facet_type,
                    terms=[*matched, *shared_terms],
                )
            )
    if shared_terms and not facets:
        facets.append(SecurityFacet(type="api_surface", terms=shared_terms))
    return facets


def trim_context(
    chunks: list[RagChunk],
    max_chars: int,
    *,
    max_chunks_per_source: int = 3,
) -> list[RagChunk]:
    selected: list[RagChunk] = []
    total = 0
    source_counts: dict[str, int] = {}
    for chunk in chunks:
        if source_counts.get(chunk.source, 0) >= max_chunks_per_source:
            continue
        if total + len(chunk.text) > max_chars:
            continue
        selected.append(chunk)
        total += len(chunk.text)
        source_counts[chunk.source] = source_counts.get(chunk.source, 0) + 1
    return selected


def _issue_text(
    issue: JiraIssue,
    confluence_pages: list[ConfluencePage],
    *,
    pii_mode: PiiRedactionMode = "off",
) -> str:
    parts = [
        issue.summary,
        issue.description or "",
        issue.acceptance_criteria or "",
        " ".join(issue.labels),
        " ".join(issue.components),
        " ".join(issue.comments),
        " ".join(page.title for page in confluence_pages),
        " ".join(page.body_text[:2000] for page in confluence_pages),
    ]
    return redact_text("\n".join(parts), pii_mode=pii_mode) or ""


def _score(chunk: RagChunk) -> float:
    return chunk.score if chunk.score is not None else 0.0


def rerank_chunks(
    query: str,
    chunks: list[RagChunk],
    limit: int,
    *,
    dense_weight: float = 0.65,
    lexical_weight: float = 0.20,
    source_weight: float = 0.15,
) -> list[RagChunk]:
    if not chunks:
        return []
    total_weight = dense_weight + lexical_weight + source_weight
    if total_weight <= 0:
        raise ValueError("At least one RAG reranking weight must be greater than zero")

    query_terms = _terms(query)
    query_domains = _query_security_domains(query)
    ranked: list[RagChunk] = []
    for chunk in chunks:
        dense_score = max(min(_score(chunk), 1.0), 0.0)
        lexical_score = _lexical_score(query_terms, _terms(f"{chunk.title} {chunk.text}"))
        priority = _source_priority(chunk)
        domain_score = _domain_score(query_domains, chunk)
        final_score = (
            dense_weight * dense_score
            + lexical_weight * lexical_score
            + source_weight * priority
        ) / total_weight
        final_score = min(final_score + domain_score, 1.0)
        metadata = {
            **chunk.metadata,
            "retrieval": {
                "dense_score": dense_score,
                "lexical_score": lexical_score,
                "source_priority": priority,
                "domain_score": domain_score,
                "final_score": final_score,
                "query_terms": sorted(query_terms),
                "source_type": chunk.metadata.get("source_type"),
            },
        }
        ranked.append(chunk.model_copy(update={"score": final_score, "metadata": metadata}))
    return sorted(ranked, key=_score, reverse=True)[:limit]


def _terms(text: str) -> set[str]:
    return {
        match.group(0).lower()
        for match in TOKEN_PATTERN.finditer(text)
        if len(match.group(0)) > 1
    }


def _lexical_score(query_terms: set[str], document_terms: set[str]) -> float:
    if not query_terms:
        return 0.0
    return len(query_terms.intersection(document_terms)) / len(query_terms)


def _source_priority(chunk: RagChunk) -> float:
    configured = chunk.metadata.get("source_priority")
    if isinstance(configured, (int, float)):
        return max(min(float(configured), 1.0), 0.0)
    source_type = str(chunk.metadata.get("source_type") or "local")
    is_template = bool(chunk.metadata.get("is_template")) or ".template." in chunk.source
    if is_template:
        return 0.15
    return {
        "internal": 1.0,
        "local": 0.75,
        "mitre": 0.65,
        "owasp": 0.60,
        "portswigger": 0.55,
        "external_pentest_methodology": 0.50,
    }.get(source_type, 0.50)


def _query_security_domains(query: str) -> set[str]:
    facets = extract_security_facets(query)
    domains = {facet.type for facet in facets}
    lowered = query.lower()
    if "file upload" in lowered or "upload" in lowered:
        domains.add("file_upload")
    if "ssrf" in lowered or "webhook" in lowered:
        domains.add("ssrf")
    if "graphql" in lowered:
        domains.add("graphql")
    if "jwt" in lowered:
        domains.add("jwt")
    if "oauth" in lowered or "oidc" in lowered:
        domains.add("oauth")
    if "cors" in lowered:
        domains.add("cors")
    if "csrf" in lowered:
        domains.add("csrf")
    if "xss" in lowered:
        domains.add("xss")
    return domains


def _domain_score(query_domains: set[str], chunk: RagChunk) -> float:
    if not query_domains:
        return 0.0
    chunk_domains: set[str] = set()
    primary_domain = chunk.metadata.get("security_domain")
    if isinstance(primary_domain, str):
        chunk_domains.add(primary_domain)
    secondary_domains = chunk.metadata.get("security_domains")
    if isinstance(secondary_domains, list):
        chunk_domains.update(str(item) for item in secondary_domains)
    if not query_domains.intersection(chunk_domains):
        return 0.0
    source_type = str(chunk.metadata.get("source_type") or "")
    if source_type == "internal":
        return 0.04
    if source_type == "external_pentest_methodology":
        return 0.03
    return 0.02
