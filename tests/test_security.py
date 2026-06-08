from vulle.security import REDACTED, REDACTED_PII, redact_data, redact_text


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


def test_redact_text_removes_multiline_private_key_and_connection_uri() -> None:
    text = (
        "-----BEGIN PRIVATE KEY-----\nsecret\n-----END PRIVATE KEY-----\n"
        "postgresql://admin:password@db.example/app"
    )

    redacted = redact_text(text)

    assert redacted is not None
    assert "PRIVATE KEY" not in redacted
    assert "admin:password" not in redacted
    assert redacted.count(REDACTED) == 2


def test_redact_text_removes_json_xml_and_url_secrets() -> None:
    text = (
        '{"client_secret": "abc123"} '
        "<token>xml-secret</token> "
        "https://example.test/callback?code=secret-code&state=public"
    )

    redacted = redact_text(text)

    assert redacted is not None
    assert "abc123" not in redacted
    assert "xml-secret" not in redacted
    assert "secret-code" not in redacted
    assert "state=public" in redacted


def test_pii_redaction_is_policy_controlled() -> None:
    text = "Contact user@example.com at +905551112233 with IBAN TR330006100519786457841326"

    assert redact_text(text, pii_mode="off") == text
    masked = redact_text(text, pii_mode="mask")

    assert masked is not None
    assert "user@example.com" not in masked
    assert "+905551112233" not in masked
    assert "TR330006100519786457841326" not in masked
    assert REDACTED_PII in masked
