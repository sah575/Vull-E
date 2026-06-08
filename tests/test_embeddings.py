import httpx
import pytest

from vulle.config import Settings
from vulle.errors import ServiceCompatibilityError
from vulle.rag.embeddings import EmbeddingClient


def _embedding_client(vector: list[float], dimensions: int) -> EmbeddingClient:
    transport = httpx.MockTransport(
        lambda request: httpx.Response(
            200,
            json={"data": [{"embedding": vector}]},
            request=request,
        )
    )
    client = object.__new__(EmbeddingClient)
    client._settings = Settings(_env_file=None, embedding_dimensions=dimensions)
    client._client = httpx.Client(
        base_url="http://embedding.local/v1",
        transport=transport,
    )
    return client


def test_embedding_dimension_mismatch_is_actionable() -> None:
    client = _embedding_client([0.1, 0.2], dimensions=3)

    with pytest.raises(ServiceCompatibilityError, match="dimension mismatch"):
        client.embed_query("health check")


def test_embedding_response_returns_configured_vector() -> None:
    client = _embedding_client([0.1, 0.2], dimensions=2)

    assert client.embed_query("health check") == [0.1, 0.2]
