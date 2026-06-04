from functools import lru_cache

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8")

    jira_base_url: str | None = None
    jira_email: str | None = None
    jira_api_token: str | None = None

    confluence_base_url: str | None = None
    confluence_email: str | None = None
    confluence_api_token: str | None = None

    llm_base_url: str = "http://127.0.0.1:8000/v1"
    llm_api_key: str = "local-not-needed"
    llm_model: str = "gpt-oss-120b"
    llm_temperature: float = Field(default=0.1, ge=0.0, le=2.0)


@lru_cache
def get_settings() -> Settings:
    return Settings()
