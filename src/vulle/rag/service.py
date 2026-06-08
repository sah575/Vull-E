import json
import re
from pathlib import Path

from vulle.config import Settings
from vulle.models import ConfluencePage, JiraIssue, RagChunk
from vulle.rag.documents import load_documents
from vulle.rag.embeddings import EmbeddingClient
from vulle.rag.qdrant_store import QdrantRagStore
from vulle.security import redact_text


TOKEN_PATTERN = re.compile(r"[a-zA-Z0-9_./{}:-]+")


class RagService:
    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        self._embeddings = EmbeddingClient(settings)
        self._store = QdrantRagStore(settings)

    def index_path(self, path: Path) -> int:
        chunks = load_documents(path)
        vectors = self._embeddings.embed_texts([chunk.text for chunk in chunks])
        self._store.upsert_chunks(chunks, vectors)
        return len(chunks)

    def search(self, query: str, limit: int | None = None) -> list[RagChunk]:
        redacted_query = redact_text(query) or ""
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
        queries = build_issue_queries(issue, confluence_pages)
        candidates: dict[str, RagChunk] = {}
        per_query_limit = max(self._settings.rag_top_k, 4)
        for query in queries:
            for chunk in self.search(query, per_query_limit):
                current = candidates.get(chunk.id)
                if current is None or _score(chunk) > _score(current):
                    candidates[chunk.id] = chunk
        chunks = sorted(candidates.values(), key=_score, reverse=True)
        return trim_context(chunks, self._settings.rag_max_context_chars)


def build_issue_query(issue: JiraIssue, confluence_pages: list[ConfluencePage]) -> str:
    return build_issue_queries(issue, confluence_pages)[0]


def build_issue_queries(issue: JiraIssue, confluence_pages: list[ConfluencePage]) -> list[str]:
    text = _issue_text(issue, confluence_pages)
    endpoints = sorted(set(re.findall(r"\b(?:GET|POST|PUT|PATCH|DELETE)\s+/[^\s,\"')]+", text, re.I)))
    object_ids = sorted(set(re.findall(r"\b[a-zA-Z]*(?:customer|account|document|transaction|branch|user|case|card)[a-zA-Z]*Id\b", text, re.I)))
    roles = sorted(set(re.findall(r"\b(?:maker|checker|approver|reviewer|admin|branch|region|operator|viewer)\b", text, re.I)))
    actions = sorted(set(re.findall(r"\b(?:approve|reject|submit|cancel|upload|download|export|import|activate|reverse|refund|delete|update)\b", text, re.I)))
    data_terms = sorted(set(re.findall(r"\b(?:PII|KVKK|GDPR|mask(?:ed|ing)?|audit|log(?:ging)?|card|IBAN|phone|email|address|nationalId)\b", text, re.I)))

    payload = {
        "summary": issue.summary,
        "description": issue.description,
        "acceptance_criteria": issue.acceptance_criteria,
        "labels": issue.labels,
        "components": issue.components,
        "comments": issue.comments,
        "confluence_titles": [page.title for page in confluence_pages],
        "confluence_excerpt": [page.body_text[:1200] for page in confluence_pages],
    }
    queries = [
        json.dumps(payload, ensure_ascii=False),
        "endpoint object authorization IDOR BOLA " + " ".join([*endpoints, *object_ids]),
        "role scope access control maker checker branch authorization " + " ".join(roles),
        "state changing workflow business logic audit approval " + " ".join(actions),
        "data classification masking sensitive data logging " + " ".join(data_terms),
    ]
    return [query for query in queries if query.strip()]


def trim_context(chunks: list[RagChunk], max_chars: int) -> list[RagChunk]:
    selected: list[RagChunk] = []
    total = 0
    for chunk in chunks:
        if total + len(chunk.text) > max_chars:
            remaining = max_chars - total
            if remaining > 500:
                selected.append(chunk.model_copy(update={"text": chunk.text[:remaining]}))
            break
        selected.append(chunk)
        total += len(chunk.text)
    return selected


def _issue_text(issue: JiraIssue, confluence_pages: list[ConfluencePage]) -> str:
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
    return redact_text("\n".join(parts)) or ""


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
    ranked: list[RagChunk] = []
    for chunk in chunks:
        dense_score = max(min(_score(chunk), 1.0), 0.0)
        lexical_score = _lexical_score(query_terms, _terms(f"{chunk.title} {chunk.text}"))
        priority = _source_priority(chunk)
        final_score = (
            dense_weight * dense_score
            + lexical_weight * lexical_score
            + source_weight * priority
        ) / total_weight
        metadata = {
            **chunk.metadata,
            "retrieval": {
                "dense_score": dense_score,
                "lexical_score": lexical_score,
                "source_priority": priority,
                "final_score": final_score,
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
    }.get(source_type, 0.50)
