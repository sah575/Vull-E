import httpx

from vulle.confluence_client import ConfluenceClient, extract_page_id


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


def test_confluence_page_payload_is_parsed() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
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
    client._base_url = "https://confluence.example"
    client._client = httpx.Client(
        base_url=client._base_url,
        transport=httpx.MockTransport(handler),
    )

    page = client.get_page("123")

    assert page.title == "Security Design"
    assert page.space_key == "SEC"
    assert page.body_text == "Branch ownership is required."
