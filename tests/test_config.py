from pathlib import Path

from vulle.config import get_settings, rag_scope, resolve_profile_path


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
