from typing import Any

import httpx

from vulle.config import Settings
from vulle.models import JiraIssue


class JiraClient:
    def __init__(self, settings: Settings) -> None:
        if not settings.jira_base_url or not settings.jira_email or not settings.jira_api_token:
            raise ValueError("JIRA_BASE_URL, JIRA_EMAIL and JIRA_API_TOKEN must be configured")

        self._client = httpx.Client(
            base_url=settings.jira_base_url.rstrip("/"),
            auth=(settings.jira_email, settings.jira_api_token),
            timeout=30,
        )

    def get_issue(self, issue_key: str) -> JiraIssue:
        response = self._client.get(
            f"/rest/api/3/issue/{issue_key}",
            params={
                "fields": "summary,description,issuetype,status,priority,labels,components,comment",
            },
        )
        response.raise_for_status()
        payload = response.json()
        return jira_payload_to_issue(payload)


def jira_payload_to_issue(payload: dict[str, Any]) -> JiraIssue:
    fields = payload.get("fields", {})
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
        acceptance_criteria=_extract_acceptance_criteria(_adf_to_text(fields.get("description"))),
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
        if node.get("type") == "text" and node.get("text"):
            parts.append(node["text"])
        for child in node.get("content", []):
            _walk_adf(child, parts)
        if node.get("type") in {"paragraph", "heading", "listItem"}:
            parts.append("\n")
    elif isinstance(node, list):
        for child in node:
            _walk_adf(child, parts)
