import httpx

from vulle.config import Settings
from vulle.errors import (
    ServiceCompatibilityError,
    ServiceResponseFormatError,
    raise_for_response,
    response_json,
    tls_verify,
    translate_http_error,
)


class EmbeddingClient:
    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        self._client = httpx.Client(
            base_url=settings.embedding_base_url.rstrip("/"),
            headers={"Authorization": f"Bearer {settings.embedding_api_key}"},
            timeout=120,
            verify=tls_verify(
                verify_ssl=settings.http_verify_ssl,
                ca_bundle=settings.http_ca_bundle,
            ),
        )

    def embed_texts(self, texts: list[str]) -> list[list[float]]:
        if not texts:
            return []
        endpoint = "/embeddings"
        try:
            response = self._client.post(
                endpoint,
                json={"model": self._settings.embedding_model, "input": texts},
            )
        except httpx.HTTPError as exc:
            raise translate_http_error(exc, service="Embedding", endpoint=endpoint) from exc
        raise_for_response(response, service="Embedding", endpoint=endpoint)
        payload = response_json(response, service="Embedding", endpoint=endpoint)
        try:
            vectors = [item["embedding"] for item in payload["data"]]  # type: ignore[index]
        except (KeyError, TypeError) as exc:
            raise ServiceResponseFormatError(
                "Embedding response is missing data[].embedding."
            ) from exc
        for vector in vectors:
            if len(vector) != self._settings.embedding_dimensions:
                raise ServiceCompatibilityError(
                    "Embedding dimension mismatch: "
                    f"configured={self._settings.embedding_dimensions}, actual={len(vector)}."
                )
        return vectors

    def embed_query(self, text: str) -> list[float]:
        return self.embed_texts([text])[0]
