import httpx

from vulle.config import Settings
from vulle.doctor import (
    _confluence_check,
    _embedding_check,
    _jira_check,
    run_doctor,
)
from vulle.errors import ServiceAuthenticationError


def test_doctor_offline_validates_configuration_without_network() -> None:
    report = run_doctor(
        Settings(
            jira_base_url="https://jira.example",
            jira_email="security@example.com",
            jira_api_token="token",
        ),
        offline=True,
    )

    assert report.healthy
    assert any(check.name == "network_checks" for check in report.checks)


def test_embedding_dimension_mismatch_fails(monkeypatch) -> None:
    monkeypatch.setattr(
        "vulle.doctor.httpx.post",
        lambda *args, **kwargs: httpx.Response(
            200,
            json={"data": [{"embedding": [0.1, 0.2]}]},
            request=httpx.Request("POST", "http://embedding.local/v1/embeddings"),
        ),
    )

    check = _embedding_check(Settings(embedding_dimensions=3))

    assert check.status == "fail"
    assert check.details["actual_dimensions"] == 2


def test_jira_doctor_reports_authentication_failure(monkeypatch) -> None:
    def fail(self) -> None:
        raise ServiceAuthenticationError("Jira authentication failed")

    monkeypatch.setattr("vulle.doctor.JiraClient.check_connection", fail)
    check = _jira_check(
        Settings(
            jira_base_url="https://jira.example",
            jira_email="security@example.com",
            jira_api_token="invalid",
        )
    )

    assert check.status == "fail"
    assert "authentication failed" in check.message


def test_confluence_doctor_passes_when_connection_succeeds(monkeypatch) -> None:
    monkeypatch.setattr(
        "vulle.doctor.ConfluenceClient.check_connection",
        lambda self: None,
    )
    check = _confluence_check(
        Settings(
            confluence_base_url="https://confluence.example",
            confluence_email="security@example.com",
            confluence_api_token="token",
        )
    )

    assert check.status == "pass"
