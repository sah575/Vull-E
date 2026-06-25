import json

import httpx
import pytest
from pydantic import BaseModel

from vulle.config import Settings
from vulle.errors import ServiceCompatibilityError
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


def test_response_format_rejection_is_actionable() -> None:
    transport = httpx.MockTransport(
        lambda request: httpx.Response(
            400,
            text="response_format is not supported",
            request=request,
        )
    )
    client = object.__new__(LLMClient)
    client._settings = Settings(_env_file=None)
    client._client = httpx.Client(
        base_url="http://llm.local/v1",
        transport=transport,
    )

    with pytest.raises(ServiceCompatibilityError, match="response_format"):
        client._request("system", "user")


def test_valid_llm_response_content_is_returned() -> None:
    seen_payload = {}
    debug_events = []

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal seen_payload
        seen_payload = json.loads(request.content)
        return httpx.Response(
            200,
            json={"choices": [{"message": {"content": '{"value":"ok"}'}}]},
            request=request,
        )

    transport = httpx.MockTransport(
        handler
    )
    client = object.__new__(LLMClient)
    client._settings = Settings(_env_file=None, llm_max_tokens=1234)
    client._debug_callback = debug_events.append
    client._client = httpx.Client(
        base_url="http://llm.local/v1",
        transport=transport,
    )

    assert client._request("system", "user") == '{"value":"ok"}'
    assert seen_payload["max_tokens"] == 1234
    assert debug_events[0]["event"] == "llm_request"
    assert debug_events[0]["total_prompt_chars"] == len("system") + len("user")
    assert debug_events[1]["event"] == "llm_response"
    assert debug_events[1]["http_status"] == 200
    assert "Authorization" not in json.dumps(debug_events)


def test_list_llm_response_content_is_joined() -> None:
    transport = httpx.MockTransport(
        lambda request: httpx.Response(
            200,
            json={
                "choices": [
                    {
                        "message": {
                            "content": [
                                {"type": "text", "text": '{"value":'},
                                {"type": "text", "text": '"ok"}'},
                            ]
                        }
                    }
                ]
            },
            request=request,
        )
    )
    client = object.__new__(LLMClient)
    client._settings = Settings(_env_file=None)
    client._client = httpx.Client(
        base_url="http://llm.local/v1",
        transport=transport,
    )

    assert client._request("system", "user") == '{"value":"ok"}'


def test_null_content_can_use_parsed_message_payload() -> None:
    transport = httpx.MockTransport(
        lambda request: httpx.Response(
            200,
            json={
                "choices": [
                    {
                        "message": {
                            "content": None,
                            "parsed": {"value": "ok"},
                        }
                    }
                ]
            },
            request=request,
        )
    )
    client = object.__new__(LLMClient)
    client._settings = Settings(_env_file=None)
    client._client = httpx.Client(
        base_url="http://llm.local/v1",
        transport=transport,
    )

    assert client._request("system", "user") == '{"value": "ok"}'


def test_null_content_can_use_tool_call_arguments() -> None:
    transport = httpx.MockTransport(
        lambda request: httpx.Response(
            200,
            json={
                "choices": [
                    {
                        "message": {
                            "content": None,
                            "tool_calls": [
                                {
                                    "function": {
                                        "arguments": '{"value":"ok"}',
                                    }
                                }
                            ],
                        }
                    }
                ]
            },
            request=request,
        )
    )
    client = object.__new__(LLMClient)
    client._settings = Settings(_env_file=None)
    client._client = httpx.Client(
        base_url="http://llm.local/v1",
        transport=transport,
    )

    assert client._request("system", "user") == '{"value":"ok"}'
