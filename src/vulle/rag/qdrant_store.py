from qdrant_client import QdrantClient
from qdrant_client.http import models as qmodels

from vulle.config import Settings
from vulle.models import RagChunk


class QdrantRagStore:
    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        self._client = QdrantClient(
            url=settings.qdrant_url,
            api_key=settings.qdrant_api_key,
            timeout=30,
        )

    def ensure_collection(self) -> None:
        collections = self._client.get_collections().collections
        exists = any(item.name == self._settings.qdrant_collection for item in collections)
        if exists:
            return
        self._client.create_collection(
            collection_name=self._settings.qdrant_collection,
            vectors_config=qmodels.VectorParams(
                size=self._settings.embedding_dimensions,
                distance=qmodels.Distance.COSINE,
            ),
        )

    def upsert_chunks(self, chunks: list[RagChunk], vectors: list[list[float]]) -> None:
        if len(chunks) != len(vectors):
            raise ValueError("chunks and vectors must have the same length")
        if not chunks:
            return
        self.ensure_collection()
        points = [
            qmodels.PointStruct(
                id=chunk.id,
                vector=vector,
                payload={
                    "source": chunk.source,
                    "title": chunk.title,
                    "text": chunk.text,
                    **chunk.metadata,
                },
            )
            for chunk, vector in zip(chunks, vectors)
        ]
        self._client.upsert(
            collection_name=self._settings.qdrant_collection,
            points=points,
        )

    def search(self, vector: list[float], limit: int) -> list[RagChunk]:
        self.ensure_collection()
        response = self._client.query_points(
            collection_name=self._settings.qdrant_collection,
            query=vector,
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
