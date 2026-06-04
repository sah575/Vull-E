import json
from typing import Any, TypeVar

import httpx
from pydantic import BaseModel

from vulle.config import Settings


T = TypeVar("T", bound=BaseModel)


class LLMClient:
    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        self._client = httpx.Client(
            base_url=settings.llm_base_url.rstrip("/"),
            headers={"Authorization": f"Bearer {settings.llm_api_key}"},
            timeout=120,
        )

    def complete_json(self, system: str, user: str, schema: type[T]) -> T:
        response = self._client.post(
            "/chat/completions",
            json={
                "model": self._settings.llm_model,
                "temperature": self._settings.llm_temperature,
                "messages": [
                    {"role": "system", "content": system},
                    {"role": "user", "content": user},
                ],
                "response_format": {"type": "json_object"},
            },
        )
        response.raise_for_status()
        content = response.json()["choices"][0]["message"]["content"]
        return self._parse_json_model(content, schema)

    @staticmethod
    def _parse_json_model(content: str, schema: type[T]) -> T:
        try:
            payload: dict[str, Any] = json.loads(content)
        except json.JSONDecodeError as exc:
            raise ValueError(f"LLM returned invalid JSON: {content[:500]}") from exc
        return schema.model_validate(payload)

