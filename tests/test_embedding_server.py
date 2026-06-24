from typer.testing import CliRunner

from vulle.embedding_server import app


def test_embedding_server_help_is_available() -> None:
    result = CliRunner().invoke(app, ["--help"])

    assert result.exit_code == 0
    assert "sentence-transformers model" in result.output
    assert "/v1/embeddings" in result.output
