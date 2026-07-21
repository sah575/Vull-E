import os
from functools import lru_cache
from pathlib import Path
from typing import Literal

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

PROFILE_ENV_VAR = "VULLE_PROFILE"
DEFAULT_PROFILE_DIR = Path(".vulle/profiles")


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file_encoding="utf-8", extra="ignore")

    vulle_debug: bool = False
    vulle_audit_log: Path | None = None

    jira_base_url: str | None = None
    jira_email: str | None = None
    jira_api_token: str | None = None
    jira_auth_mode: Literal["basic", "bearer"] = "basic"
    jira_api_version: str = "3"
    jira_acceptance_criteria_field: str | None = None

    confluence_base_url: str | None = None
    confluence_email: str | None = None
    confluence_api_token: str | None = None
    confluence_auth_mode: Literal["basic", "bearer"] | None = None

    llm_base_url: str = "http://127.0.0.1:8000/v1"
    llm_api_key: str = "local-not-needed"
    llm_model: str = "gpt-oss-120b"
    llm_temperature: float = Field(default=0.1, ge=0.0, le=2.0)
    llm_json_repair_attempts: int = Field(default=1, ge=0, le=3)
    llm_http_retries: int = Field(default=2, ge=0, le=5)
    llm_timeout_seconds: int = Field(default=120, gt=0)
    llm_max_tokens: int = Field(default=4096, gt=0)
    llm_max_prompt_chars: int = Field(default=45000, gt=10000)
    llm_rag_context_chars: int = Field(default=12000, gt=1000)
    llm_confluence_chars_per_page: int = Field(default=6000, gt=1000)
    llm_reasoning_effort: Literal["low", "medium", "high"] | None = None
    pii_redaction_mode: Literal["off", "mask"] = "off"
    http_verify_ssl: bool = True
    http_ca_bundle: Path | None = None

    embedding_base_url: str = "http://127.0.0.1:8000/v1"
    embedding_api_key: str = "local-not-needed"
    embedding_model: str = "bge-m3"
    embedding_dimensions: int = Field(default=1024, gt=0)
    embedding_batch_size: int = Field(default=32, gt=0, le=4096)
    embedding_timeout_seconds: int = Field(default=600, gt=0)

    qdrant_url: str = "http://127.0.0.1:6333"
    qdrant_api_key: str | None = None
    qdrant_path: Path | None = None
    qdrant_collection: str = "vulle_knowledge"
    rag_tenant_id: str | None = None
    rag_environment: str = "preprod"
    rag_knowledge_base_id: str | None = None
    rag_top_k: int = Field(default=6, gt=0)
    rag_max_context_chars: int = Field(default=8000, gt=1000)
    rag_max_chunks_per_source: int = Field(default=3, gt=0)
    rag_candidate_multiplier: int = Field(default=4, ge=1, le=10)
    rag_dense_weight: float = Field(default=0.65, ge=0.0, le=1.0)
    rag_lexical_weight: float = Field(default=0.20, ge=0.0, le=1.0)
    rag_source_weight: float = Field(default=0.15, ge=0.0, le=1.0)
    qdrant_upsert_batch_size: int = Field(default=128, gt=0, le=10000)
    rag_index_retry_count: int = Field(default=3, ge=0, le=10)
    rag_index_retry_base_delay_seconds: float = Field(default=1.0, ge=0.0, le=60.0)
    rag_max_file_size_mb: int = Field(default=10, gt=0, le=1024)
    rag_max_total_files: int = Field(default=10000, gt=0, le=1000000)
    rag_max_chunks_per_document: int = Field(default=500, gt=0, le=100000)
    rag_follow_symlinks: bool = False
    rag_index_schema_version: int = Field(default=2, gt=0)

    llm_traffic_context_chars: int = Field(default=8000, gt=1000)

    adb_binary: str = "adb"
    adb_command_timeout_seconds: int = Field(default=30, gt=0)
    dynamic_crawler_kill_switch_path: Path = Path(".vulle/CRAWLER_STOP")
    dynamic_crawler_max_actions_default: int = Field(default=30, gt=0)
    dynamic_crawler_tap_settle_seconds: float = Field(default=1.5, gt=0.0)
    dynamic_session_dir: Path = Path(".vulle/dynamic-sessions")

    @field_validator("http_ca_bundle", mode="before")
    @classmethod
    def empty_ca_bundle_is_none(cls, value: object) -> object:
        if isinstance(value, str) and not value.strip():
            return None
        return value

    @field_validator("qdrant_path", mode="before")
    @classmethod
    def empty_qdrant_path_is_none(cls, value: object) -> object:
        if isinstance(value, str) and not value.strip():
            return None
        return value

    @field_validator("vulle_audit_log", mode="before")
    @classmethod
    def empty_audit_log_is_none(cls, value: object) -> object:
        if isinstance(value, str) and not value.strip():
            return None
        return value


@lru_cache
def get_settings(profile: str | None = None) -> Settings:
    selected_profile = profile or os.getenv(PROFILE_ENV_VAR)
    profile_path = resolve_profile_path(selected_profile)
    env_files: Path | tuple[Path, Path]
    if selected_profile and profile_path != Path(".env"):
        env_files = (Path(".env"), profile_path)
    else:
        env_files = Path(".env")
    return Settings(_env_file=env_files)  # type: ignore[call-arg]


def set_active_profile(profile: str | None) -> Path:
    profile_path = resolve_profile_path(profile)
    os.environ[PROFILE_ENV_VAR] = str(profile_path)
    get_settings.cache_clear()
    return profile_path


def active_profile_name() -> str:
    profile = os.getenv(PROFILE_ENV_VAR)
    if not profile:
        return "default"
    return resolve_profile_path(profile).stem


def rag_scope(settings: Settings) -> dict[str, str]:
    tenant_id = settings.rag_tenant_id or active_profile_name()
    knowledge_base_id = (
        settings.rag_knowledge_base_id
        or f"{tenant_id}:{settings.qdrant_collection}"
    )
    return {
        "tenant_id": tenant_id,
        "environment": settings.rag_environment,
        "knowledge_base_id": knowledge_base_id,
    }


def resolve_profile_path(profile: str | None) -> Path:
    if not profile:
        return Path(".env")

    candidate = Path(profile).expanduser()
    if candidate.is_absolute() or candidate.parent != Path(".") or candidate.suffix:
        return candidate
    if not profile.replace("-", "").replace("_", "").isalnum():
        raise ValueError("Profile names may contain only letters, numbers, '-' and '_'")
    return DEFAULT_PROFILE_DIR / f"{profile}.env"
