import re
from html.parser import HTMLParser
from typing import Any
from urllib.parse import parse_qs, urlparse

import httpx

from vulle.config import Settings
from vulle.errors import (
    ServiceResponseFormatError,
    raise_for_response,
    response_json,
    tls_verify,
    translate_http_error,
)
from vulle.models import ConfluencePage, JiraIssue


class ConfluenceClient:
    def __init__(self, settings: Settings) -> None:
        base_url = settings.confluence_base_url or _derive_confluence_base_url(
            settings.jira_base_url
        )
        email = settings.confluence_email or settings.jira_email
        token = settings.confluence_api_token or settings.jira_api_token
        auth_mode = settings.confluence_auth_mode or settings.jira_auth_mode

        if not base_url or not token:
            raise ValueError(
                "Confluence requires CONFLUENCE_BASE_URL plus credentials, "
                "or Jira settings that can be reused"
            )
        auth: tuple[str, str] | None = None
        if auth_mode == "basic":
            if not email:
                raise ValueError("CONFLUENCE_EMAIL is required for Basic authentication")
            auth = (email, token)
        headers = {"Authorization": f"Bearer {token}"} if auth_mode == "bearer" else None

        self._base_url = base_url.rstrip("/")
        self._client = httpx.Client(
            base_url=self._base_url,
            auth=auth,
            headers=headers,
            timeout=30,
            verify=tls_verify(
                verify_ssl=settings.http_verify_ssl,
                ca_bundle=settings.http_ca_bundle,
            ),
        )

    def get_page(self, page_id: str) -> ConfluencePage:
        payload = self._fetch_page_payload(page_id)
        body = (
            payload.get("body", {})
            .get("storage", {})
            .get("value")
            or payload.get("body", {})
            .get("view", {})
            .get("value")
            or ""
        )
        return ConfluencePage(
            id=str(payload.get("id", page_id)),
            title=payload.get("title") or f"Confluence page {page_id}",
            url=self._page_url(payload),
            space_key=_space_key(payload),
            body_text=html_to_text(body),
        )

    def get_pages_from_issue(self, issue: JiraIssue) -> list[ConfluencePage]:
        return self.get_pages_from_urls(extract_confluence_urls(issue))

    def get_pages_from_urls(self, urls: list[str]) -> list[ConfluencePage]:
        page_ids = []
        for url in urls:
            page_id = extract_page_id(url)
            if page_id and page_id not in page_ids:
                page_ids.append(page_id)

        pages: list[ConfluencePage] = []
        for page_id in page_ids:
            pages.append(self.get_page(page_id))
        return pages

    def _fetch_page_payload(self, page_id: str) -> dict[str, Any]:
        # A relative endpoint preserves `/wiki` or `/confluence` in the base URL.
        endpoint = f"rest/api/content/{page_id}"
        try:
            response = self._client.get(
                endpoint,
                params={"expand": "body.storage,body.view,space,_links"},
            )
        except httpx.HTTPError as exc:
            raise translate_http_error(
                exc,
                service="Confluence",
                endpoint=endpoint,
            ) from exc
        raise_for_response(response, service="Confluence", endpoint=endpoint)
        payload = response_json(response, service="Confluence", endpoint=endpoint)
        if not isinstance(payload, dict):
            raise ServiceResponseFormatError("Confluence response must be a JSON object.")
        return payload

    def check_connection(self) -> None:
        endpoint = "rest/api/space"
        try:
            response = self._client.get(endpoint, params={"limit": 1})
        except httpx.HTTPError as exc:
            raise translate_http_error(
                exc,
                service="Confluence",
                endpoint=endpoint,
            ) from exc
        raise_for_response(response, service="Confluence", endpoint=endpoint)

    def _page_url(self, payload: dict[str, Any]) -> str | None:
        links = payload.get("_links") or {}
        webui = links.get("webui")
        base = links.get("base") or self._base_url
        if webui:
            return f"{base.rstrip('/')}/{webui.lstrip('/')}"
        return None


def extract_confluence_urls(issue: JiraIssue) -> list[str]:
    text_parts = [
        issue.description or "",
        issue.acceptance_criteria or "",
        *issue.comments,
    ]
    text = "\n".join(text_parts)
    candidates = re.findall(r"https?://[^\s<>\]\)\"']+", text)
    return filter_confluence_urls(candidates)


def filter_confluence_urls(urls: list[str]) -> list[str]:
    seen: set[str] = set()
    results: list[str] = []
    for candidate in urls:
        url = candidate.rstrip(".,;")
        if not ("confluence" in url.lower() or "/wiki/" in url):
            continue
        if url not in seen:
            seen.add(url)
            results.append(url)
    return results


def extract_page_id(url: str) -> str | None:
    parsed = urlparse(url)
    query = parse_qs(parsed.query)
    if query.get("pageId"):
        return query["pageId"][0]

    patterns = [
        r"/pages/(\d+)",
        r"/content/(\d+)",
        r"/pageId/(\d+)",
    ]
    for pattern in patterns:
        match = re.search(pattern, parsed.path)
        if match:
            return match.group(1)
    return None


def html_to_text(html: str) -> str:
    parser = _TextExtractor()
    parser.feed(html)
    return parser.text()


def _derive_confluence_base_url(jira_base_url: str | None) -> str | None:
    if not jira_base_url:
        return None
    parsed = urlparse(jira_base_url)
    if "atlassian.net" in parsed.netloc:
        return f"{parsed.scheme}://{parsed.netloc}/wiki"
    return jira_base_url


def _space_key(payload: dict[str, Any]) -> str | None:
    space = payload.get("space") or {}
    return space.get("key")


class _TextExtractor(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self._parts: list[str] = []

    def handle_data(self, data: str) -> None:
        cleaned = data.strip()
        if cleaned:
            self._parts.append(cleaned)

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag in {"p", "br", "li", "tr", "h1", "h2", "h3", "h4"}:
            self._parts.append("\n")

    def text(self) -> str:
        raw = " ".join(self._parts)
        lines = [line.strip() for line in raw.splitlines()]
        return "\n".join(line for line in lines if line)
