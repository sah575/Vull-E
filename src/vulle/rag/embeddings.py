import httpx

from vulle.config import Settings


class EmbeddingClient:
    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        self._client = httpx.Client(
            base_url=settings.embedding_base_url.rstrip("/"),
            headers={"Authorization": f"Bearer {settings.embedding_api_key}"},
            timeout=120,
        )

    def embed_texts(self, texts: list[str]) -> list[list[float]]:
        if not texts:
            return []
        response = self._client.post(
            "/embeddings",
            json={"model": self._settings.embedding_model, "input": texts},
        )
        response.raise_for_status()
        data = response.json()["data"]
        return [item["embedding"] for item in data]

    def embed_query(self, text: str) -> list[float]:
        return self.embed_texts([text])[0]

