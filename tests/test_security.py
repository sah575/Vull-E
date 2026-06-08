from vulle.security import REDACTED, redact_data, redact_text


def test_redact_text_removes_common_credentials() -> None:
    text = (
        "Authorization: Bearer abc.def.ghi "
        "password=super-secret api_key: key-123 "
        "Cookie: session=secret-value"
    )

    redacted = redact_text(text)

    assert redacted is not None
    assert redacted.count(REDACTED) == 4
    assert "super-secret" not in redacted
    assert "secret-value" not in redacted


def test_redact_data_preserves_structure() -> None:
    payload = {"comments": ["token=abc123"], "count": 2}

    assert redact_data(payload) == {
        "comments": [f"token={REDACTED}"],
        "count": 2,
    }
