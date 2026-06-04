from vulle.confluence_client import extract_page_id


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
