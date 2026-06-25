import httpx

from vulle.config import Settings
from vulle.confluence_client import ConfluenceClient, extract_page_id, filter_confluence_urls


def test_extract_page_id_from_spaces_url() -> None:
    assert (
        extract_page_id("https://example.atlassian.net/wiki/spaces/SEC/pages/123456789/Page")
        == "123456789"
    )


def test_extract_page_id_from_viewpage_query() -> None:
    assert (
        extract_page_id("https://example.atlassian.net/wiki/pages/viewpage.action?pageId=987654321")
        == "987654321"
    )


def test_filter_confluence_urls_deduplicates_and_ignores_other_links() -> None:
    assert filter_confluence_urls(
        [
            "https://atlas.example/confluence/pages/12345,",
            "https://atlas.example/confluence/pages/12345",
            "https://example.invalid/page",
        ]
    ) == ["https://atlas.example/confluence/pages/12345"]


def test_confluence_page_payload_is_parsed() -> None:
    seen_path = ""

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal seen_path
        seen_path = request.url.path
        return httpx.Response(
            200,
            json={
                "id": "123",
                "title": "Security Design",
                "space": {"key": "SEC"},
                "body": {"storage": {"value": "<p>Branch ownership is required.</p>"}},
                "_links": {"base": "https://confluence.example", "webui": "/pages/123"},
            },
            request=request,
        )

    client = object.__new__(ConfluenceClient)
    client._base_url = "https://confluence.example/confluence"
    client._client = httpx.Client(
        base_url=client._base_url,
        transport=httpx.MockTransport(handler),
    )

    page = client.get_page("123")

    assert page.title == "Security Design"
    assert page.space_key == "SEC"
    assert page.body_text == "Branch ownership is required."
    assert seen_path == "/confluence/rest/api/content/123"


def test_bearer_authentication_does_not_require_email() -> None:
    client = ConfluenceClient(
        Settings(
            _env_file=None,
            jira_auth_mode="bearer",
            confluence_base_url="https://confluence.example/confluence",
            confluence_api_token="data-center-pat",
            confluence_auth_mode="bearer",
        )
    )

    assert client._client.headers["Authorization"] == "Bearer data-center-pat"
    client._client.close()


def test_check_connection_preserves_confluence_context_path() -> None:
    seen_path = ""

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal seen_path
        seen_path = request.url.path
        return httpx.Response(200, json={"results": []}, request=request)

    client = object.__new__(ConfluenceClient)
    client._base_url = "https://confluence.example/confluence"
    client._client = httpx.Client(
        base_url=client._base_url,
        transport=httpx.MockTransport(handler),
    )

    client.check_connection()

    assert seen_path == "/confluence/rest/api/space"
