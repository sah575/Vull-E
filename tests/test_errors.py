from pathlib import Path

import httpx
import pytest

from vulle.errors import (
    ServiceAuthenticationError,
    ServiceEndpointNotFoundError,
    ServicePermissionError,
    ServiceResponseFormatError,
    ServiceTimeoutError,
    ServiceTLSCertificateError,
    raise_for_response,
    response_json,
    tls_verify,
    translate_http_error,
)


def _response(status: int, content: str = "") -> httpx.Response:
    request = httpx.Request("GET", "https://service.example/api")
    return httpx.Response(status, text=content, request=request)


@pytest.mark.parametrize(
    ("status", "error_type"),
    [
        (401, ServiceAuthenticationError),
        (403, ServicePermissionError),
        (404, ServiceEndpointNotFoundError),
    ],
)
def test_http_statuses_have_actionable_errors(
    status: int,
    error_type: type[Exception],
) -> None:
    with pytest.raises(error_type):
        raise_for_response(
            _response(status, '{"message":"denied"}'),
            service="Jira",
            endpoint="/rest/api/3/myself",
        )


def test_timeout_and_tls_errors_are_distinguished() -> None:
    request = httpx.Request("GET", "https://service.example")
    timeout = httpx.ReadTimeout("slow", request=request)
    tls = httpx.ConnectError("certificate verify failed", request=request)

    assert isinstance(
        translate_http_error(timeout, service="LLM", endpoint="/chat/completions"),
        ServiceTimeoutError,
    )
    assert isinstance(
        translate_http_error(tls, service="LLM", endpoint="/chat/completions"),
        ServiceTLSCertificateError,
    )


def test_invalid_json_has_response_format_error() -> None:
    with pytest.raises(ServiceResponseFormatError):
        response_json(
            _response(200, "not-json"),
            service="Embedding",
            endpoint="/embeddings",
        )


def test_missing_ca_bundle_is_rejected(tmp_path: Path) -> None:
    with pytest.raises(ServiceTLSCertificateError):
        tls_verify(verify_ssl=True, ca_bundle=tmp_path / "missing.pem")
