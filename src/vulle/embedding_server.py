from importlib import import_module
from pathlib import Path
from time import time
from typing import Annotated, Any

import typer

app = typer.Typer(help="Local OpenAI-compatible embedding server")
DEFAULT_MODEL_PATH = Path("models/BAAI/bge-m3")


@app.command("serve")
def serve(
    model_path: Annotated[
        Path,
        typer.Option(help="Local sentence-transformers model directory."),
    ] = DEFAULT_MODEL_PATH,
    model_name: Annotated[
        str,
        typer.Option(help="Model name accepted in /v1/embeddings requests."),
    ] = "BAAI/bge-m3",
    host: Annotated[str, typer.Option(help="Bind host.")] = "127.0.0.1",
    port: Annotated[int, typer.Option(help="Bind port.")] = 8010,
    device: Annotated[
        str,
        typer.Option(help="Model device, usually cpu on bank laptops."),
    ] = "cpu",
    batch_size: Annotated[int, typer.Option(min=1, help="Encoding batch size.")] = 4,
    normalize_embeddings: Annotated[
        bool,
        typer.Option(help="Normalize vectors for cosine search."),
    ] = True,
) -> None:
    """Serve a local sentence-transformers model through /v1/embeddings."""
    try:
        uvicorn = import_module("uvicorn")
        fastapi = import_module("fastapi")
        sentence_transformers = import_module("sentence_transformers")
        from pydantic import BaseModel, Field
    except ImportError as exc:
        raise typer.BadParameter(
            "Embedding server dependencies are missing. Install with "
            '`python -m pip install -e ".[embedding-server]"` or use the offline wheels.'
        ) from exc

    FastAPI = fastapi.FastAPI
    HTTPException = fastapi.HTTPException
    SentenceTransformer = sentence_transformers.SentenceTransformer

    if not model_path.is_dir():
        raise typer.BadParameter(f"Model directory does not exist: {model_path}")

    model = SentenceTransformer(str(model_path), device=device)
    api = FastAPI(title="Vull-E Local Embedding Server")

    class EmbeddingRequest(BaseModel):
        model: str
        input: str | list[str]

    class EmbeddingItem(BaseModel):
        object: str = "embedding"
        index: int
        embedding: list[float]

    class Usage(BaseModel):
        prompt_tokens: int = 0
        total_tokens: int = 0

    class EmbeddingResponse(BaseModel):
        object: str = "list"
        data: list[EmbeddingItem]
        model: str
        usage: Usage = Field(default_factory=Usage)

    @api.get("/health")
    def health() -> dict[str, Any]:
        return {
            "status": "ok",
            "model": model_name,
            "model_path": str(model_path),
            "device": device,
        }

    @api.get("/v1/models")
    def models() -> dict[str, Any]:
        return {
            "object": "list",
            "data": [{"id": model_name, "object": "model", "created": int(time())}],
        }

    @api.post("/v1/embeddings")
    def embeddings(request: EmbeddingRequest) -> EmbeddingResponse:
        if request.model != model_name:
            raise HTTPException(
                status_code=400,
                detail=f"Unsupported model '{request.model}'. Expected '{model_name}'.",
            )
        texts = [request.input] if isinstance(request.input, str) else request.input
        if not texts:
            raise HTTPException(status_code=400, detail="input must not be empty")
        vectors = model.encode(
            texts,
            batch_size=batch_size,
            normalize_embeddings=normalize_embeddings,
            show_progress_bar=False,
        )
        return EmbeddingResponse(
            data=[
                EmbeddingItem(index=index, embedding=vector.astype(float).tolist())
                for index, vector in enumerate(vectors)
            ],
            model=model_name,
            usage=Usage(
                prompt_tokens=sum(len(text.split()) for text in texts),
                total_tokens=sum(len(text.split()) for text in texts),
            ),
        )

    uvicorn.run(api, host=host, port=port)


if __name__ == "__main__":
    app()
