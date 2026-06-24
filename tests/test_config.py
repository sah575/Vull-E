from pathlib import Path

import pytest
from pydantic import ValidationError

from vulle.config import Settings, get_settings, rag_scope, resolve_profile_path


def test_named_profile_overrides_shared_env(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("LLM_MODEL", raising=False)
    monkeypatch.delenv("QDRANT_COLLECTION", raising=False)
    (tmp_path / ".env").write_text(
        "LLM_MODEL=shared-model\nQDRANT_COLLECTION=shared_collection\n",
        encoding="utf-8",
    )
    profile_dir = tmp_path / ".vulle/profiles"
    profile_dir.mkdir(parents=True)
    (profile_dir / "bank-a.env").write_text(
        "JIRA_BASE_URL=https://bank-a.example\n"
        "JIRA_EMAIL=security@example.com\n"
        "JIRA_API_TOKEN=test-token\n"
        "QDRANT_COLLECTION=bank_a_knowledge\n",
        encoding="utf-8",
    )
    get_settings.cache_clear()

    settings = get_settings("bank-a")

    assert settings.llm_model == "shared-model"
    assert settings.jira_base_url == "https://bank-a.example"
    assert settings.qdrant_collection == "bank_a_knowledge"
    get_settings.cache_clear()


def test_named_profile_can_contain_complete_runtime_config(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    profile_dir = tmp_path / ".vulle/profiles"
    profile_dir.mkdir(parents=True)
    (profile_dir / "bank-a.env").write_text(
        "JIRA_BASE_URL=https://bank-a.example/jira\n"
        "JIRA_EMAIL=security@example.com\n"
        "JIRA_API_TOKEN=test-token\n"
        "LLM_BASE_URL=http://llm.example/v1\n"
        "LLM_API_KEY=llm-token\n"
        "LLM_MODEL=bank-llm\n"
        "EMBEDDING_BASE_URL=http://embedding.example/v1\n"
        "EMBEDDING_API_KEY=embedding-token\n"
        "EMBEDDING_MODEL=bank-embedding\n"
        "EMBEDDING_DIMENSIONS=768\n"
        "EMBEDDING_TIMEOUT_SECONDS=900\n"
        "QDRANT_URL=http://qdrant.example:6333\n"
        "QDRANT_PATH=.vulle/qdrant_local\n"
        "QDRANT_COLLECTION=bank_a_knowledge\n",
        encoding="utf-8",
    )
    get_settings.cache_clear()

    settings = get_settings("bank-a")

    assert settings.llm_base_url == "http://llm.example/v1"
    assert settings.llm_api_key == "llm-token"
    assert settings.llm_model == "bank-llm"
    assert settings.embedding_base_url == "http://embedding.example/v1"
    assert settings.embedding_api_key == "embedding-token"
    assert settings.embedding_model == "bank-embedding"
    assert settings.embedding_dimensions == 768
    assert settings.embedding_timeout_seconds == 900
    assert settings.qdrant_url == "http://qdrant.example:6333"
    assert settings.qdrant_path == Path(".vulle/qdrant_local")
    assert settings.qdrant_collection == "bank_a_knowledge"
    get_settings.cache_clear()


def test_explicit_profile_path_is_supported() -> None:
    assert resolve_profile_path("configs/target.env") == Path("configs/target.env")


def test_explicit_rag_scope_overrides_profile_defaults() -> None:
    scope = rag_scope(
        get_settings().model_copy(
            update={
                "rag_tenant_id": "bank-a",
                "rag_environment": "staging",
                "rag_knowledge_base_id": "bank-a-security-v3",
            }
        )
    )

    assert scope == {
        "tenant_id": "bank-a",
        "environment": "staging",
        "knowledge_base_id": "bank-a-security-v3",
    }


def test_invalid_index_batch_settings_are_rejected() -> None:
    with pytest.raises(ValidationError):
        Settings(_env_file=None, embedding_batch_size=0)
    with pytest.raises(ValidationError):
        Settings(_env_file=None, qdrant_upsert_batch_size=0)
    with pytest.raises(ValidationError):
        Settings(_env_file=None, rag_max_file_size_mb=0)


def test_empty_ca_bundle_is_treated_as_unset(tmp_path: Path) -> None:
    env_file = tmp_path / "profile.env"
    env_file.write_text("HTTP_CA_BUNDLE=\n", encoding="utf-8")

    settings = Settings(_env_file=env_file)

    assert settings.http_ca_bundle is None
