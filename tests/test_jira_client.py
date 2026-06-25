import httpx
import pytest

from vulle.config import Settings
from vulle.errors import JiraCustomFieldNotFoundError
from vulle.jira_client import JiraClient, jira_payload_to_issue


def test_configured_acceptance_criteria_field_is_used() -> None:
    issue = jira_payload_to_issue(
        {
            "key": "BANK-10",
            "fields": {
                "summary": "Approval change",
                "description": "General description",
                "customfield_12345": "Only checker users may approve",
            },
        },
        acceptance_criteria_field="customfield_12345",
    )

    assert issue.acceptance_criteria == "Only checker users may approve"


def test_missing_acceptance_criteria_field_is_actionable() -> None:
    with pytest.raises(JiraCustomFieldNotFoundError, match="JIRA_ACCEPTANCE_CRITERIA_FIELD"):
        jira_payload_to_issue(
            {
                "key": "BANK-11",
                "fields": {
                    "summary": "Approval change",
                    "description": "General description",
                },
            },
            acceptance_criteria_field="customfield_99999",
        )


def test_get_issue_requests_configured_api_and_custom_field() -> None:
    seen_url = ""
    seen_fields = ""

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal seen_url, seen_fields
        seen_url = request.url.path
        seen_fields = request.url.params["fields"]
        return httpx.Response(
            200,
            json={
                "key": "BANK-12",
                "fields": {
                    "summary": "Approval change",
                    "description": None,
                    "customfield_12345": "Checker approval is required",
                },
            },
            request=request,
        )

    client = object.__new__(JiraClient)
    client._api_version = "2"
    client._acceptance_criteria_field = "customfield_12345"
    client._client = httpx.Client(
        base_url="https://jira.example/jira",
        transport=httpx.MockTransport(handler),
    )

    issue = client.get_issue("BANK-12")

    assert seen_url == "/jira/rest/api/2/issue/BANK-12"
    assert "customfield_12345" in seen_fields
    assert issue.acceptance_criteria == "Checker approval is required"


def test_adf_link_href_is_preserved_in_issue_text() -> None:
    issue = jira_payload_to_issue(
        {
            "key": "BANK-13",
            "fields": {
                "summary": "Confluence linked",
                "description": {
                    "type": "doc",
                    "content": [
                        {
                            "type": "paragraph",
                            "content": [
                                {
                                    "type": "text",
                                    "text": "Design document",
                                    "marks": [
                                        {
                                            "type": "link",
                                            "attrs": {
                                                "href": "https://atlas.example/confluence/pages/12345"
                                            },
                                        }
                                    ],
                                }
                            ],
                        }
                    ],
                },
            },
        }
    )

    assert "https://atlas.example/confluence/pages/12345" in (issue.description or "")


def test_get_remote_links_returns_object_urls() -> None:
    seen_url = ""

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal seen_url
        seen_url = request.url.path
        return httpx.Response(
            200,
            json=[
                {"object": {"url": "https://atlas.example/confluence/pages/12345"}},
                {"object": {"url": "https://example.invalid/other"}},
            ],
            request=request,
        )

    client = object.__new__(JiraClient)
    client._api_version = "2"
    client._client = httpx.Client(
        base_url="https://jira.example/jira",
        transport=httpx.MockTransport(handler),
    )

    urls = client.get_remote_links("BANK-13")

    assert seen_url == "/jira/rest/api/2/issue/BANK-13/remotelink"
    assert urls == [
        "https://atlas.example/confluence/pages/12345",
        "https://example.invalid/other",
    ]


def test_check_connection_preserves_jira_context_path() -> None:
    seen_url = ""

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal seen_url
        seen_url = request.url.path
        return httpx.Response(200, json={"name": "security.user"}, request=request)

    client = object.__new__(JiraClient)
    client._api_version = "2"
    client._client = httpx.Client(
        base_url="https://jira.example/jira",
        transport=httpx.MockTransport(handler),
    )

    client.check_connection()

    assert seen_url == "/jira/rest/api/2/myself"


def test_bearer_authentication_does_not_require_email() -> None:
    client = JiraClient(
        Settings(
            _env_file=None,
            jira_base_url="https://jira.example/jira",
            jira_api_token="data-center-pat",
            jira_auth_mode="bearer",
        )
    )

    assert client._client.headers["Authorization"] == "Bearer data-center-pat"
    client._client.close()
