from pydantic import BaseModel

from vulle.config import Settings
from vulle.llm import LLMClient


class _Result(BaseModel):
    value: str


def test_complete_json_repairs_invalid_output() -> None:
    client = object.__new__(LLMClient)
    client._settings = Settings(llm_json_repair_attempts=1)
    responses = iter(["not json", '{"value": "repaired"}'])
    client._request = lambda *args, **kwargs: next(responses)

    result = client.complete_json("system", "user", _Result)

    assert result.value == "repaired"
