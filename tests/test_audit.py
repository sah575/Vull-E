import json

from vulle.audit import emit_audit_event


def test_audit_event_is_jsonl_and_redacted(tmp_path) -> None:
    path = tmp_path / "audit.jsonl"

    emit_audit_event(
        path,
        {
            "event": "llm_request",
            "authorization": "Bearer secret-token",
            "email": "user@example.com",
        },
        pii_mode="mask",
    )

    payload = json.loads(path.read_text(encoding="utf-8"))

    assert payload["event"] == "llm_request"
    assert payload["authorization"] == "[REDACTED]"
    assert payload["email"] == "[REDACTED:PII]"
    assert "timestamp" in payload
