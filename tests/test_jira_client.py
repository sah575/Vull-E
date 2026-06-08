import httpx
import pytest

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
        base_url="https://jira.example",
        transport=httpx.MockTransport(handler),
    )

    issue = client.get_issue("BANK-12")

    assert seen_url == "/rest/api/2/issue/BANK-12"
    assert "customfield_12345" in seen_fields
    assert issue.acceptance_criteria == "Checker approval is required"
