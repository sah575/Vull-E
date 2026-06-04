import json
from pathlib import Path

from vulle.config import Settings
from vulle.models import ConfluencePage, JiraIssue, RagChunk
from vulle.rag.documents import load_documents
from vulle.rag.embeddings import EmbeddingClient
from vulle.rag.qdrant_store import QdrantRagStore


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
        vector = self._embeddings.embed_query(query)
        return self._store.search(vector, limit or self._settings.rag_top_k)

    def retrieve_for_issue(
        self,
        issue: JiraIssue,
        confluence_pages: list[ConfluencePage],
    ) -> list[RagChunk]:
        query = build_issue_query(issue, confluence_pages)
        chunks = self.search(query, self._settings.rag_top_k)
        return trim_context(chunks, self._settings.rag_max_context_chars)


def build_issue_query(issue: JiraIssue, confluence_pages: list[ConfluencePage]) -> str:
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
    return json.dumps(payload, ensure_ascii=False)


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
