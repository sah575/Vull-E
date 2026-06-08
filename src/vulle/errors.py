from __future__ import annotations

import ssl
from pathlib import Path

import httpx


class VulleError(RuntimeError):
    """Base class for actionable Vull-E runtime errors."""


class ServiceConnectionError(VulleError):
    pass


class ServiceTimeoutError(VulleError):
    pass


class ServiceTLSCertificateError(VulleError):
    pass


class ServiceAuthenticationError(VulleError):
    pass


class ServicePermissionError(VulleError):
    pass


class ServiceEndpointNotFoundError(VulleError):
    pass


class ServiceResponseFormatError(VulleError):
    pass


class ServiceCompatibilityError(VulleError):
    pass


class JiraCustomFieldNotFoundError(VulleError):
    pass


def tls_verify(*, verify_ssl: bool, ca_bundle: Path | None) -> bool | ssl.SSLContext:
    if not verify_ssl:
        return False
    if ca_bundle is None:
        return True
    if not ca_bundle.is_file():
        raise ServiceTLSCertificateError(f"CA bundle file does not exist: {ca_bundle}")
    return ssl.create_default_context(cafile=str(ca_bundle))


def raise_for_response(
    response: httpx.Response,
    *,
    service: str,
    endpoint: str,
) -> None:
    if response.is_success:
        return
    status = response.status_code
    detail = _response_detail(response)
    suffix = f" Detail: {detail}" if detail else ""
    if status == 401:
        raise ServiceAuthenticationError(
            f"{service} authentication failed for {endpoint} (HTTP 401).{suffix}"
        )
    if status == 403:
        raise ServicePermissionError(
            f"{service} credentials lack permission for {endpoint} (HTTP 403).{suffix}"
        )
    if status == 404:
        raise ServiceEndpointNotFoundError(
            f"{service} endpoint or resource was not found: {endpoint} (HTTP 404).{suffix}"
        )
    raise VulleError(f"{service} request failed for {endpoint} (HTTP {status}).{suffix}")


def translate_http_error(
    error: httpx.HTTPError,
    *,
    service: str,
    endpoint: str,
) -> VulleError:
    if isinstance(error, httpx.TimeoutException):
        return ServiceTimeoutError(f"{service} timed out while connecting to {endpoint}.")
    if _is_tls_error(error):
        return ServiceTLSCertificateError(
            f"{service} TLS certificate validation failed for {endpoint}. "
            "Configure HTTP_CA_BUNDLE for the bank CA, or investigate the certificate chain."
        )
    return ServiceConnectionError(
        f"{service} connection failed for {endpoint}: {error.__class__.__name__}: {error}"
    )


def response_json(
    response: httpx.Response,
    *,
    service: str,
    endpoint: str,
) -> object:
    try:
        return response.json()
    except ValueError as exc:
        raise ServiceResponseFormatError(
            f"{service} returned invalid JSON from {endpoint}."
        ) from exc


def _response_detail(response: httpx.Response) -> str:
    try:
        payload = response.json()
    except ValueError:
        return response.text.strip()[:300]
    if isinstance(payload, dict):
        value = payload.get("errorMessages") or payload.get("message") or payload.get("error")
        if isinstance(value, list):
            return "; ".join(str(item) for item in value)[:300]
        if value:
            return str(value)[:300]
    return ""


def _is_tls_error(error: BaseException) -> bool:
    current: BaseException | None = error
    while current is not None:
        text = str(current).lower()
        if isinstance(current, ssl.SSLError) or any(
            marker in text
            for marker in (
                "certificate verify failed",
                "certificate_verify_failed",
                "ssl:",
                "tls:",
            )
        ):
            return True
        current = current.__cause__ or current.__context__
    return False
