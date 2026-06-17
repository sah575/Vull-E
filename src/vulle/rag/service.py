import json
import re
from pathlib import Path
from typing import Any, Protocol

from vulle.config import Settings, rag_scope
from vulle.models import ConfluencePage, JiraIssue, RagChunk, RagIndexReport, SecurityFacet
from vulle.rag.documents import (
    DocumentLoadOptions,
    document_ids_for_path,
    hacktricks_document_ids_for_path,
    load_documents_with_report,
    load_hacktricks_documents,
    normalized_path,
)
from vulle.rag.embeddings import EmbeddingClient
from vulle.rag.hacktricks import HACKTRICKS_SOURCE_NAME, HACKTRICKS_SOURCE_TYPE
from vulle.rag.indexing import RetryPolicy, batch_count, batched, run_with_retry
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


class EmbeddingLike(Protocol):
    def embed_texts(self, texts: list[str]) -> list[list[float]]: ...

    def embed_query(self, text: str) -> list[float]: ...


class RagStoreLike(Protocol):
    def sync_index_root(
        self,
        index_root: str,
        chunks: list[RagChunk],
        vectors: list[list[float]],
        *,
        source_name: str | None = None,
        source_type: str | None = None,
    ) -> None: ...

    def delete_documents(
        self,
        document_ids: list[str],
        *,
        source_name: str | None = None,
        source_type: str | None = None,
    ) -> None: ...

    def upsert_chunks(self, chunks: list[RagChunk], vectors: list[list[float]]) -> None: ...

    def search(self, vector: list[float], limit: int) -> list[RagChunk]: ...


class RagService:
    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        self._embeddings: EmbeddingLike | None = None
        self._store: RagStoreLike | None = None

    def _embedding_client(self) -> EmbeddingLike:
        if getattr(self, "_embeddings", None) is None:
            self._embeddings = EmbeddingClient(self._settings)
        assert self._embeddings is not None
        return self._embeddings

    def _rag_store(self) -> RagStoreLike:
        if getattr(self, "_store", None) is None:
            self._store = QdrantRagStore(self._settings)
        assert self._store is not None
        return self._store

    def index_path(self, path: Path, *, sync: bool = False) -> int:
        return self.index_path_report(path, sync=sync).chunks_created

    def index_path_report(
        self,
        path: Path,
        *,
        sync: bool = False,
        dry_run: bool = False,
    ) -> RagIndexReport:
        options = self._load_options(source_name="local")
        result = load_documents_with_report(
            path,
            pii_mode=self._settings.pii_redaction_mode,
            options=options,
        )
        document_ids = document_ids_for_path(path, options)
        return self._index_chunks(
            path,
            result.chunks,
            result.report,
            sync=sync,
            dry_run=dry_run,
            document_ids=document_ids,
            source_name="local",
            source_type=None,
        )

    def index_hacktricks(self, path: Path, *, sync: bool = False) -> dict[str, object]:
        return self.index_hacktricks_report(path, sync=sync).model_dump()

    def index_hacktricks_report(
        self,
        path: Path,
        *,
        sync: bool = False,
        dry_run: bool = False,
    ) -> RagIndexReport:
        options = self._load_options(source_name=HACKTRICKS_SOURCE_NAME)
        chunks, report = load_hacktricks_documents(
            path,
            pii_mode=self._settings.pii_redaction_mode,
            id_namespace=self._settings.rag_knowledge_base_id
            or f"{self._settings.qdrant_collection}:{self._settings.rag_environment}",
            options=options,
        )
        index_report = RagIndexReport(
            files_scanned=report.scanned_files,
            files_accepted=report.accepted_files,
            files_skipped=report.excluded_files,
            chunks_created=report.chunk_count,
            duplicate_chunks=report.deduplicated_chunks,
            security_domain_distribution=report.domain_counts,
            commit_sha=report.commit_sha,
            warnings=[
                *report.warnings,
                "HackTricks license review is required before internal redistribution.",
            ],
        )
        for chunk in chunks:
            _increment(
                index_report.source_type_distribution,
                str(chunk.metadata.get("source_type") or "unknown"),
            )
        document_ids = hacktricks_document_ids_for_path(path, options)
        return self._index_chunks(
            path,
            chunks,
            index_report,
            sync=sync,
            dry_run=dry_run,
            document_ids=document_ids,
            source_name=HACKTRICKS_SOURCE_NAME,
            source_type=HACKTRICKS_SOURCE_TYPE,
        )

    def _load_options(self, *, source_name: str) -> DocumentLoadOptions:
        scope = rag_scope(self._settings)
        return DocumentLoadOptions(
            source_name=source_name,
            tenant_id=scope["tenant_id"],
            environment=scope["environment"],
            knowledge_base_id=scope["knowledge_base_id"],
            index_schema_version=self._settings.rag_index_schema_version,
            max_file_size_mb=self._settings.rag_max_file_size_mb,
            max_total_files=self._settings.rag_max_total_files,
            max_chunks_per_document=self._settings.rag_max_chunks_per_document,
            follow_symlinks=self._settings.rag_follow_symlinks,
        )

    def _index_chunks(
        self,
        path: Path,
        chunks: list[RagChunk],
        report: RagIndexReport,
        *,
        sync: bool,
        dry_run: bool,
        document_ids: list[str],
        source_name: str | None,
        source_type: str | None,
    ) -> RagIndexReport:
        report.dry_run = dry_run
        report.chunks_created = len(chunks)
        report.embedding_batches = batch_count(
            len(chunks),
            self._settings.embedding_batch_size,
        )
        report.qdrant_batches = _estimated_nested_batches(
            len(chunks),
            self._settings.embedding_batch_size,
            self._settings.qdrant_upsert_batch_size,
        )
        if dry_run:
            return report
        if sync and report.files_accepted == 0:
            report.warnings.append(
                "Sync delete skipped because no source files were accepted."
            )
            sync = False
        if sync:
            self._rag_store().sync_index_root(
                normalized_path(path),
                [],
                [],
                source_name=source_name,
                source_type=source_type,
            )
        elif document_ids:
            self._rag_store().delete_documents(
                document_ids,
                source_name=source_name,
                source_type=source_type,
            )

        retry_policy = RetryPolicy(
            attempts=self._settings.rag_index_retry_count,
            base_delay_seconds=self._settings.rag_index_retry_base_delay_seconds,
        )
        total_embedding_batches = report.embedding_batches
        report.qdrant_batches = 0
        for batch_number, chunk_batch in enumerate(
            batched(chunks, self._settings.embedding_batch_size),
            start=1,
        ):
            def embed_batch(batch: list[RagChunk] = chunk_batch) -> list[list[float]]:
                return self._embedding_client().embed_texts(
                    [chunk.text for chunk in batch]
                )

            try:
                vectors, retries = run_with_retry(
                    embed_batch,
                    operation_name="embedding",
                    batch_number=batch_number,
                    total_batches=total_embedding_batches,
                    policy=retry_policy,
                )
            except Exception as exc:
                report.chunks_failed += len(chunk_batch)
                report.errors.append(str(exc))
                raise
            report.retry_count += retries
            if len(vectors) != len(chunk_batch):
                report.chunks_failed += len(chunk_batch)
                raise ValueError(
                    "Embedding response count mismatch for batch "
                    f"{batch_number}/{total_embedding_batches}: "
                    f"expected={len(chunk_batch)}, actual={len(vectors)}"
                )
            self._upsert_vector_batches(
                chunk_batch,
                vectors,
                report,
                retry_policy,
                extra={
                    "embedding_batch_number": batch_number,
                    "embedding_total_batches": total_embedding_batches,
                },
            )
        return report

    def _upsert_vector_batches(
        self,
        chunks: list[RagChunk],
        vectors: list[list[float]],
        report: RagIndexReport,
        retry_policy: RetryPolicy,
        *,
        extra: dict[str, Any],
    ) -> None:
        total = batch_count(len(chunks), self._settings.qdrant_upsert_batch_size)
        for batch_number, index_batch in enumerate(
            batched(list(range(len(chunks))), self._settings.qdrant_upsert_batch_size),
            start=1,
        ):
            chunk_batch = [chunks[index] for index in index_batch]
            vector_batch = [vectors[index] for index in index_batch]

            def upsert_batch(
                cb: list[RagChunk] = chunk_batch,
                vb: list[list[float]] = vector_batch,
            ) -> None:
                self._rag_store().upsert_chunks(cb, vb)

            try:
                _, retries = run_with_retry(
                    upsert_batch,
                    operation_name="qdrant_upsert",
                    batch_number=batch_number,
                    total_batches=total,
                    policy=retry_policy,
                )
            except Exception as exc:
                report.chunks_failed += len(chunk_batch)
                report.errors.append(f"{exc}; context={extra}")
                raise
            report.retry_count += retries
            report.qdrant_batches += 1
            report.chunks_upserted += len(chunk_batch)

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
        vector = self._embedding_client().embed_query(redacted_query)
        candidates = self._rag_store().search(vector, candidate_limit)
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


def _increment(values: dict[str, int], key: str) -> None:
    values[key] = values.get(key, 0) + 1


def _estimated_nested_batches(
    item_count: int,
    outer_batch_size: int,
    inner_batch_size: int,
) -> int:
    total = 0
    for batch in batched(list(range(item_count)), outer_batch_size):
        total += batch_count(len(batch), inner_batch_size)
    return total
