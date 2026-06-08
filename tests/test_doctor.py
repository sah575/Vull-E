from vulle.config import Settings
from vulle.doctor import _embedding_check, run_doctor


class _Response:
    def raise_for_status(self) -> None:
        return None

    def json(self) -> dict:
        return {"data": [{"embedding": [0.1, 0.2]}]}


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
    monkeypatch.setattr("vulle.doctor.httpx.post", lambda *args, **kwargs: _Response())

    check = _embedding_check(Settings(embedding_dimensions=3))

    assert check.status == "fail"
    assert check.details["actual_dimensions"] == 2
