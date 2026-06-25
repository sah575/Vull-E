from typing import Any

import httpx

from vulle.config import Settings
from vulle.errors import (
    JiraCustomFieldNotFoundError,
    ServiceResponseFormatError,
    raise_for_response,
    response_json,
    tls_verify,
    translate_http_error,
)
from vulle.models import JiraIssue


class JiraClient:
    def __init__(self, settings: Settings) -> None:
        if not settings.jira_base_url or not settings.jira_api_token:
            raise ValueError("JIRA_BASE_URL and JIRA_API_TOKEN must be configured")
        auth: tuple[str, str] | None = None
        if settings.jira_auth_mode == "basic":
            email = settings.jira_email
            if not email:
                raise ValueError("JIRA_EMAIL must be configured for Basic authentication")
            auth = (email, settings.jira_api_token)
        headers = (
            {"Authorization": f"Bearer {settings.jira_api_token}"}
            if settings.jira_auth_mode == "bearer"
            else None
        )

        self._client = httpx.Client(
            base_url=settings.jira_base_url.rstrip("/"),
            auth=auth,
            headers=headers,
            timeout=30,
            verify=tls_verify(
                verify_ssl=settings.http_verify_ssl,
                ca_bundle=settings.http_ca_bundle,
            ),
        )
        self._api_version = settings.jira_api_version
        self._acceptance_criteria_field = settings.jira_acceptance_criteria_field

    def get_issue(self, issue_key: str) -> JiraIssue:
        # Keep a Jira context path (for example `/jira`) configured in the
        # base URL. A leading slash would resolve from the host root and drop
        # that path.
        endpoint = f"rest/api/{self._api_version}/issue/{issue_key}"
        fields = [
            "summary",
            "description",
            "issuetype",
            "status",
            "priority",
            "labels",
            "components",
            "comment",
        ]
        if self._acceptance_criteria_field:
            fields.append(self._acceptance_criteria_field)
        try:
            response = self._client.get(endpoint, params={"fields": ",".join(fields)})
        except httpx.HTTPError as exc:
            raise translate_http_error(exc, service="Jira", endpoint=endpoint) from exc
        raise_for_response(response, service="Jira", endpoint=endpoint)
        payload = response_json(response, service="Jira", endpoint=endpoint)
        if not isinstance(payload, dict):
            raise ServiceResponseFormatError("Jira issue response must be a JSON object.")
        return jira_payload_to_issue(
            payload,
            acceptance_criteria_field=self._acceptance_criteria_field,
        )

    def get_remote_links(self, issue_key: str) -> list[str]:
        endpoint = f"rest/api/{self._api_version}/issue/{issue_key}/remotelink"
        try:
            response = self._client.get(endpoint)
        except httpx.HTTPError as exc:
            raise translate_http_error(exc, service="Jira", endpoint=endpoint) from exc
        raise_for_response(response, service="Jira", endpoint=endpoint)
        payload = response_json(response, service="Jira", endpoint=endpoint)
        if not isinstance(payload, list):
            raise ServiceResponseFormatError("Jira remote link response must be a JSON array.")
        urls: list[str] = []
        for item in payload:
            if not isinstance(item, dict):
                continue
            url = _remote_link_url(item)
            if url:
                urls.append(url)
        return urls

    def check_connection(self) -> None:
        endpoint = f"rest/api/{self._api_version}/myself"
        try:
            response = self._client.get(endpoint)
        except httpx.HTTPError as exc:
            raise translate_http_error(exc, service="Jira", endpoint=endpoint) from exc
        raise_for_response(response, service="Jira", endpoint=endpoint)


def jira_payload_to_issue(
    payload: dict[str, Any],
    *,
    acceptance_criteria_field: str | None = None,
) -> JiraIssue:
    fields = payload.get("fields", {})
    if not isinstance(fields, dict):
        raise ServiceResponseFormatError("Jira issue response has no valid fields object.")
    if acceptance_criteria_field and acceptance_criteria_field not in fields:
        raise JiraCustomFieldNotFoundError(
            "Configured Jira acceptance criteria field was not returned: "
            f"{acceptance_criteria_field}. Verify JIRA_ACCEPTANCE_CRITERIA_FIELD."
        )
    comments = fields.get("comment", {}).get("comments", [])
    components = fields.get("components") or []

    comment_texts = [_adf_to_text(item.get("body")) for item in comments if item.get("body")]

    return JiraIssue(
        key=payload.get("key", "UNKNOWN"),
        summary=fields.get("summary") or "",
        description=_adf_to_text(fields.get("description")),
        issue_type=(fields.get("issuetype") or {}).get("name"),
        status=(fields.get("status") or {}).get("name"),
        priority=(fields.get("priority") or {}).get("name"),
        labels=fields.get("labels") or [],
        components=[item.get("name", "") for item in components if item.get("name")],
        comments=[text for text in comment_texts if text],
        acceptance_criteria=(
            _adf_to_text(fields.get(acceptance_criteria_field))
            if acceptance_criteria_field
            else _extract_acceptance_criteria(_adf_to_text(fields.get("description")))
        ),
        raw=payload,
    )


def _extract_acceptance_criteria(text: str | None) -> str | None:
    if not text:
        return None
    lower = text.lower()
    markers = ["acceptance criteria", "kabul kriterleri", "ac:"]
    for marker in markers:
        idx = lower.find(marker)
        if idx >= 0:
            return text[idx:].strip()
    return None


def _adf_to_text(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, str):
        return value
    if isinstance(value, dict):
        parts: list[str] = []
        _walk_adf(value, parts)
        return "\n".join(part for part in parts if part).strip() or None
    return str(value)


def _walk_adf(node: Any, parts: list[str]) -> None:
    if isinstance(node, dict):
        for href in _adf_link_hrefs(node):
            parts.append(href)
        if node.get("type") == "text" and node.get("text"):
            parts.append(node["text"])
        for child in node.get("content", []):
            _walk_adf(child, parts)
        if node.get("type") in {"paragraph", "heading", "listItem"}:
            parts.append("\n")
    elif isinstance(node, list):
        for child in node:
            _walk_adf(child, parts)


def _adf_link_hrefs(node: dict[str, Any]) -> list[str]:
    hrefs: list[str] = []
    attrs = node.get("attrs")
    if isinstance(attrs, dict):
        for key in ("href", "url"):
            value = attrs.get(key)
            if isinstance(value, str) and value.startswith(("http://", "https://")):
                hrefs.append(value)
    for mark in node.get("marks", []) or []:
        if not isinstance(mark, dict):
            continue
        mark_attrs = mark.get("attrs") or {}
        href = mark_attrs.get("href")
        if isinstance(href, str) and href.startswith(("http://", "https://")):
            hrefs.append(href)
    return hrefs


def _remote_link_url(item: dict[str, Any]) -> str | None:
    obj = item.get("object")
    if isinstance(obj, dict):
        url = obj.get("url")
        if isinstance(url, str):
            return url
    url = item.get("url")
    if isinstance(url, str):
        return url
    return None
