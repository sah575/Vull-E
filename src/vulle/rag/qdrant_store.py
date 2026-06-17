from typing import Any

from qdrant_client import QdrantClient
from qdrant_client.http import models as qmodels

from vulle.config import Settings, rag_scope
from vulle.errors import tls_verify
from vulle.models import RagChunk


class QdrantRagStore:
    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        self._scope = rag_scope(settings)
        self._payload_indexes_ready = False
        self._client = QdrantClient(
            url=settings.qdrant_url,
            api_key=settings.qdrant_api_key,
            timeout=30,
            verify=tls_verify(
                verify_ssl=settings.http_verify_ssl,
                ca_bundle=settings.http_ca_bundle,
            ),
        )

    def ensure_collection(self, *, ensure_payload_indexes: bool = False) -> None:
        collections = self._client.get_collections().collections
        exists = any(item.name == self._settings.qdrant_collection for item in collections)
        if not exists:
            self._client.create_collection(
                collection_name=self._settings.qdrant_collection,
                vectors_config=qmodels.VectorParams(
                    size=self._settings.embedding_dimensions,
                    distance=qmodels.Distance.COSINE,
                ),
            )
        if ensure_payload_indexes:
            self._ensure_payload_indexes()

    def upsert_chunks(self, chunks: list[RagChunk], vectors: list[list[float]]) -> None:
        if len(chunks) != len(vectors):
            raise ValueError("chunks and vectors must have the same length")
        if not chunks:
            return
        self.ensure_collection(ensure_payload_indexes=True)
        points = [
            qmodels.PointStruct(
                id=chunk.id,
                vector=vector,
                payload={
                    "source": chunk.source,
                    "title": chunk.title,
                    "text": chunk.text,
                    **chunk.metadata,
                    **self._scope,
                },
            )
            for chunk, vector in zip(chunks, vectors, strict=True)
        ]
        self._client.upsert(
            collection_name=self._settings.qdrant_collection,
            points=points,
        )

    def replace_documents(
        self,
        chunks: list[RagChunk],
        vectors: list[list[float]],
        *,
        document_ids: list[str] | None = None,
        source_name: str | None = None,
        source_type: str | None = None,
    ) -> None:
        document_ids = document_ids or sorted(
            {
                str(chunk.metadata["document_id"])
                for chunk in chunks
                if chunk.metadata.get("document_id")
            }
        )
        if document_ids:
            self.delete_documents(
                document_ids,
                source_name=source_name,
                source_type=source_type,
            )
        self.upsert_chunks(chunks, vectors)

    def sync_index_root(
        self,
        index_root: str,
        chunks: list[RagChunk],
        vectors: list[list[float]],
        *,
        source_name: str | None = None,
        source_type: str | None = None,
    ) -> None:
        self.ensure_collection(ensure_payload_indexes=True)
        self._client.delete(
            collection_name=self._settings.qdrant_collection,
            points_selector=self._filter(
                index_root=index_root,
                source_name=source_name,
                source_type=source_type,
            ),
            wait=True,
        )
        self.upsert_chunks(chunks, vectors)

    def delete_documents(
        self,
        document_ids: list[str],
        *,
        source_name: str | None = None,
        source_type: str | None = None,
    ) -> None:
        if not document_ids:
            return
        self.ensure_collection(ensure_payload_indexes=True)
        self._client.delete(
            collection_name=self._settings.qdrant_collection,
            points_selector=self._filter(
                document_ids=document_ids,
                source_name=source_name,
                source_type=source_type,
            ),
            wait=True,
        )

    def search(self, vector: list[float], limit: int) -> list[RagChunk]:
        self.ensure_collection()
        response = self._client.query_points(
            collection_name=self._settings.qdrant_collection,
            query=vector,
            query_filter=self._filter(),
            limit=limit,
            with_payload=True,
        )
        chunks: list[RagChunk] = []
        for result in response.points:
            payload = result.payload or {}
            chunks.append(
                RagChunk(
                    id=str(result.id),
                    source=str(payload.get("source") or ""),
                    title=str(payload.get("title") or ""),
                    text=str(payload.get("text") or ""),
                    score=float(result.score),
                    metadata={key: value for key, value in payload.items() if key != "text"},
                )
            )
        return chunks

    def _filter(
        self,
        *,
        document_ids: list[str] | None = None,
        index_root: str | None = None,
        source_name: str | None = None,
        source_type: str | None = None,
    ) -> qmodels.Filter:
        conditions: list[Any] = [
            qmodels.FieldCondition(
                key=key,
                match=qmodels.MatchValue(value=value),
            )
            for key, value in self._scope.items()
        ]
        if document_ids:
            conditions.append(
                qmodels.FieldCondition(
                    key="document_id",
                    match=qmodels.MatchAny(any=document_ids),
                )
            )
        if index_root:
            conditions.append(
                qmodels.FieldCondition(
                    key="index_root",
                    match=qmodels.MatchValue(value=index_root),
                )
            )
        if source_name:
            conditions.append(
                qmodels.FieldCondition(
                    key="source_name",
                    match=qmodels.MatchValue(value=source_name),
                )
            )
        if source_type:
            conditions.append(
                qmodels.FieldCondition(
                    key="source_type",
                    match=qmodels.MatchValue(value=source_type),
                )
            )
        return qmodels.Filter(must=conditions)

    def _ensure_payload_indexes(self) -> None:
        if self._payload_indexes_ready:
            return
        for field_name in (
            "tenant_id",
            "environment",
            "knowledge_base_id",
            "document_id",
            "index_root",
            "source_name",
            "source_type",
        ):
            self._client.create_payload_index(
                collection_name=self._settings.qdrant_collection,
                field_name=field_name,
                field_schema=qmodels.PayloadSchemaType.KEYWORD,
                wait=True,
            )
        self._payload_indexes_ready = True
