import json
from typing import Any, Literal

import httpx
from pydantic import BaseModel, Field
from qdrant_client import QdrantClient

from vulle.config import Settings, active_profile_name, rag_scope
from vulle.confluence_client import ConfluenceClient
from vulle.errors import (
    ServiceCompatibilityError,
    ServiceResponseFormatError,
    VulleError,
    raise_for_response,
    response_json,
    tls_verify,
    translate_http_error,
)
from vulle.jira_client import JiraClient


class DoctorCheck(BaseModel):
    name: str
    status: Literal["pass", "warn", "fail"]
    message: str
    details: dict[str, Any] = Field(default_factory=dict)


class DoctorReport(BaseModel):
    target_profile: str
    healthy: bool
    checks: list[DoctorCheck]


def run_doctor(settings: Settings, *, offline: bool = False) -> DoctorReport:
    checks = [
        _jira_configuration_check(settings),
        _confluence_configuration_check(settings),
        _rag_scope_check(settings),
        _rag_weight_check(settings),
    ]
    if offline:
        checks.append(
            DoctorCheck(
                name="network_checks",
                status="warn",
                message="Network checks were skipped.",
            )
        )
    else:
        checks.extend(
            [
                _jira_check(settings),
                _confluence_check(settings),
                _llm_check(settings),
                _embedding_check(settings),
                _qdrant_check(settings),
            ]
        )
    return DoctorReport(
        target_profile=active_profile_name(),
        healthy=not any(check.status == "fail" for check in checks),
        checks=checks,
    )


def _jira_configuration_check(settings: Settings) -> DoctorCheck:
    configured = [
        settings.jira_base_url,
        settings.jira_email,
        settings.jira_api_token,
    ]
    if all(configured):
        return DoctorCheck(
            name="jira_configuration",
            status="pass",
            message="Jira base URL and credentials are configured.",
        )
    if any(configured):
        return DoctorCheck(
            name="jira_configuration",
            status="fail",
            message="Jira configuration is incomplete.",
        )
    return DoctorCheck(
        name="jira_configuration",
        status="warn",
        message="Jira is not configured; analyze-file can still be used.",
    )


def _confluence_configuration_check(settings: Settings) -> DoctorCheck:
    explicit = [
        settings.confluence_base_url,
        settings.confluence_email,
        settings.confluence_api_token,
    ]
    jira_fallback = [
        settings.jira_base_url,
        settings.jira_email,
        settings.jira_api_token,
    ]
    status: Literal["pass", "warn", "fail"]
    if all(explicit):
        message = "Confluence URL and credentials are configured."
        status = "pass"
    elif not any(explicit) and all(jira_fallback):
        message = "Confluence will reuse the Jira URL and credentials."
        status = "pass"
    elif any(explicit):
        message = "Confluence configuration is incomplete."
        status = "fail"
    else:
        message = "Confluence is not configured."
        status = "warn"
    return DoctorCheck(name="confluence_configuration", status=status, message=message)


def _rag_weight_check(settings: Settings) -> DoctorCheck:
    total = (
        settings.rag_dense_weight
        + settings.rag_lexical_weight
        + settings.rag_source_weight
    )
    if total <= 0:
        return DoctorCheck(
            name="rag_weights",
            status="fail",
            message="At least one RAG reranking weight must be greater than zero.",
        )
    return DoctorCheck(
        name="rag_weights",
        status="pass",
        message="RAG reranking weights are valid.",
        details={"total": total},
    )


def _rag_scope_check(settings: Settings) -> DoctorCheck:
    return DoctorCheck(
        name="rag_scope",
        status="pass",
        message="RAG tenant scope is configured.",
        details=rag_scope(settings),
    )


def _jira_check(settings: Settings) -> DoctorCheck:
    if not all((settings.jira_base_url, settings.jira_email, settings.jira_api_token)):
        return DoctorCheck(
            name="jira",
            status="warn",
            message="Jira connectivity was not checked because configuration is incomplete.",
        )
    try:
        JiraClient(settings).check_connection()
    except VulleError as exc:
        return DoctorCheck(
            name="jira",
            status="fail",
            message=str(exc),
            details={
                "base_url": settings.jira_base_url,
                "api_version": settings.jira_api_version,
            },
        )
    return DoctorCheck(
        name="jira",
        status="pass",
        message="Jira authentication and API endpoint are reachable.",
        details={
            "base_url": settings.jira_base_url,
            "api_version": settings.jira_api_version,
        },
    )


def _confluence_check(settings: Settings) -> DoctorCheck:
    explicit = (
        settings.confluence_base_url,
        settings.confluence_email,
        settings.confluence_api_token,
    )
    fallback = (
        settings.jira_base_url,
        settings.jira_email,
        settings.jira_api_token,
    )
    if not all(explicit) and not (not any(explicit) and all(fallback)):
        return DoctorCheck(
            name="confluence",
            status="warn",
            message="Confluence connectivity was not checked because configuration is incomplete.",
        )
    try:
        ConfluenceClient(settings).check_connection()
    except VulleError as exc:
        return DoctorCheck(
            name="confluence",
            status="fail",
            message=str(exc),
            details={"base_url": settings.confluence_base_url},
        )
    return DoctorCheck(
        name="confluence",
        status="pass",
        message="Confluence authentication and API endpoint are reachable.",
        details={"base_url": settings.confluence_base_url or "derived from Jira"},
    )


def _llm_check(settings: Settings) -> DoctorCheck:
    try:
        endpoint = f"{settings.llm_base_url.rstrip('/')}/chat/completions"
        try:
            response = httpx.post(
                endpoint,
                headers={"Authorization": f"Bearer {settings.llm_api_key}"},
                json={
                    "model": settings.llm_model,
                    "temperature": 0,
                    "messages": [
                        {
                            "role": "system",
                            "content": "Return only valid JSON.",
                        },
                        {
                            "role": "user",
                            "content": 'Return exactly {"status":"ok"} as JSON.',
                        },
                    ],
                    "response_format": {"type": "json_object"},
                },
                timeout=20,
                verify=tls_verify(
                    verify_ssl=settings.http_verify_ssl,
                    ca_bundle=settings.http_ca_bundle,
                ),
            )
        except httpx.HTTPError as exc:
            raise translate_http_error(exc, service="LLM", endpoint=endpoint) from exc
        if response.status_code == 400 and "response_format" in response.text.lower():
            raise ServiceCompatibilityError(
                "LLM endpoint rejected response_format=json_object."
            )
        raise_for_response(response, service="LLM", endpoint=endpoint)
        response_payload = response_json(response, service="LLM", endpoint=endpoint)
        try:
            content = response_payload["choices"][0]["message"]["content"]  # type: ignore[index]
        except (KeyError, IndexError, TypeError) as exc:
            raise ServiceResponseFormatError(
                "LLM response is missing choices[0].message.content."
            ) from exc
        payload = json.loads(content)
        if payload.get("status") != "ok":
            raise ValueError("Model JSON did not contain status=ok")
    except (VulleError, ValueError, json.JSONDecodeError) as exc:
        return DoctorCheck(
            name="llm",
            status="fail",
            message=f"LLM compatibility check failed: {_error_summary(exc)}",
            details={"model": settings.llm_model, "base_url": settings.llm_base_url},
        )
    return DoctorCheck(
        name="llm",
        status="pass",
        message="LLM endpoint returned compatible JSON.",
        details={"model": settings.llm_model, "base_url": settings.llm_base_url},
    )


def _embedding_check(settings: Settings) -> DoctorCheck:
    try:
        endpoint = f"{settings.embedding_base_url.rstrip('/')}/embeddings"
        try:
            response = httpx.post(
                endpoint,
                headers={"Authorization": f"Bearer {settings.embedding_api_key}"},
                json={"model": settings.embedding_model, "input": ["Vull-E health check"]},
                timeout=20,
                verify=tls_verify(
                    verify_ssl=settings.http_verify_ssl,
                    ca_bundle=settings.http_ca_bundle,
                ),
            )
        except httpx.HTTPError as exc:
            raise translate_http_error(
                exc,
                service="Embedding",
                endpoint=endpoint,
            ) from exc
        raise_for_response(response, service="Embedding", endpoint=endpoint)
        payload = response_json(response, service="Embedding", endpoint=endpoint)
        try:
            vector = payload["data"][0]["embedding"]  # type: ignore[index]
        except (KeyError, IndexError, TypeError) as exc:
            raise ServiceResponseFormatError(
                "Embedding response is missing data[0].embedding."
            ) from exc
        actual_dimensions = len(vector)
        if actual_dimensions != settings.embedding_dimensions:
            return DoctorCheck(
                name="embedding",
                status="fail",
                message="Embedding dimensions do not match configuration.",
                details={
                    "model": settings.embedding_model,
                    "expected_dimensions": settings.embedding_dimensions,
                    "actual_dimensions": actual_dimensions,
                },
            )
    except (VulleError, TypeError, ValueError) as exc:
        return DoctorCheck(
            name="embedding",
            status="fail",
            message=f"Embedding compatibility check failed: {_error_summary(exc)}",
            details={
                "model": settings.embedding_model,
                "base_url": settings.embedding_base_url,
            },
        )
    return DoctorCheck(
        name="embedding",
        status="pass",
        message="Embedding endpoint returned the configured vector size.",
        details={
            "model": settings.embedding_model,
            "dimensions": settings.embedding_dimensions,
        },
    )


def _qdrant_check(settings: Settings) -> DoctorCheck:
    try:
        client = QdrantClient(
            url=settings.qdrant_url,
            api_key=settings.qdrant_api_key,
            timeout=10,
            verify=tls_verify(
                verify_ssl=settings.http_verify_ssl,
                ca_bundle=settings.http_ca_bundle,
            ),
        )
        names = {item.name for item in client.get_collections().collections}
        if settings.qdrant_collection not in names:
            return DoctorCheck(
                name="qdrant",
                status="warn",
                message="Qdrant is reachable, but the configured collection does not exist.",
                details={"collection": settings.qdrant_collection},
            )
        info = client.get_collection(settings.qdrant_collection)
        dimensions = _qdrant_vector_size(info)
        if dimensions is not None and dimensions != settings.embedding_dimensions:
            return DoctorCheck(
                name="qdrant",
                status="fail",
                message="Qdrant collection dimensions do not match embedding configuration.",
                details={
                    "collection": settings.qdrant_collection,
                    "expected_dimensions": settings.embedding_dimensions,
                    "actual_dimensions": dimensions,
                },
            )
    except Exception as exc:
        return DoctorCheck(
            name="qdrant",
            status="fail",
            message=f"Qdrant check failed: {_error_summary(exc)}",
            details={"url": settings.qdrant_url},
        )
    return DoctorCheck(
        name="qdrant",
        status="pass",
        message="Qdrant and the configured collection are compatible.",
        details={"collection": settings.qdrant_collection},
    )


def _qdrant_vector_size(info: Any) -> int | None:
    vectors = info.config.params.vectors
    size = getattr(vectors, "size", None)
    return int(size) if size is not None else None


def _error_summary(error: Exception) -> str:
    return f"{error.__class__.__name__}: {str(error)[:300]}"
