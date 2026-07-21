import json
from pathlib import Path
from typing import Any

import pytest

from vulle.agents.jira_analysis import _evidence_segments, _quote_is_valid
from vulle.config import Settings
from vulle.dynamic.analyzers.http_traffic_rules import evaluate_http_traffic_rules
from vulle.dynamic.crawler import (
    center_of,
    is_denylisted,
    parse_clickable_elements,
    run_crawl_session,
)
from vulle.dynamic.flow_ingestion import _flow_from_mitmproxy_object
from vulle.dynamic.models import ClickableElement, CrawlSessionConfig
from vulle.errors import AdbCommandError
from vulle.models import HttpFlow, HttpHeader

_NONE_ALG_JWT = (
    "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0"
    ".eyJzdWIiOiIxMjM0NTY3ODkwIn0"
    ".signaturepart1234567890"
)
_HS256_JWT = (
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
    ".eyJzdWIiOiIxMjM0NTY3ODkwIn0"
    ".signaturepart1234567890"
)


def _flow(**overrides: Any) -> HttpFlow:
    defaults: dict[str, Any] = {
        "id": "flow-1",
        "method": "GET",
        "url": "https://api.bank.test/accounts/123",
        "host": "api.bank.test",
        "scheme": "https",
        "status_code": 200,
    }
    defaults.update(overrides)
    return HttpFlow(**defaults)


# --- flow_rendering ---


def test_render_flow_pretty_prints_json_body() -> None:
    from vulle.dynamic.flow_rendering import render_flow_as_evidence_text

    flow = _flow(response_body='{"amount": 100000, "currency": "TRY"}')
    rendered = render_flow_as_evidence_text(flow)

    assert '"amount": 100000' in rendered
    assert "{\n" in rendered  # pretty-printed (indented), not minified


def test_render_flow_truncates_after_pretty_printing() -> None:
    from vulle.dynamic.flow_rendering import render_flow_as_evidence_text

    big_body = json.dumps({"items": list(range(2000))})
    flow = _flow(response_body=big_body)
    rendered = render_flow_as_evidence_text(flow)

    assert rendered.rstrip().endswith("[truncated]")
    assert '"items": [' in rendered  # confirms pretty-print ran before truncation


def test_render_flow_quote_round_trips_through_jira_evidence_validation() -> None:
    from vulle.dynamic.flow_rendering import render_flow_as_evidence_text

    flow = _flow()
    rendered = render_flow_as_evidence_text(flow)
    quote = "GET https://api.bank.test/accounts/123 (host api.bank.test, scheme https)"

    assert _quote_is_valid(quote, rendered)
    assert any("api.bank.test" in segment for segment in _evidence_segments(rendered))


# --- flow_ingestion (pure mapping function, no mitmproxy import required) ---


class _FakeMitmHeaders:
    def __init__(self, items: list[tuple[str, str]]) -> None:
        self._items = items

    def items(self, multi: bool = False) -> list[tuple[str, str]]:
        return self._items


class _FakeMitmRequest:
    def __init__(self, **kwargs: Any) -> None:
        self.method = kwargs["method"]
        self.pretty_url = kwargs["pretty_url"]
        self.host = kwargs["host"]
        self.scheme = kwargs["scheme"]
        self.headers = _FakeMitmHeaders(kwargs.get("headers", []))
        self.content = kwargs.get("content")
        self.timestamp_start = kwargs.get("timestamp_start", 1000.0)


class _FakeMitmResponse:
    def __init__(self, **kwargs: Any) -> None:
        self.status_code = kwargs["status_code"]
        self.headers = _FakeMitmHeaders(kwargs.get("headers", []))
        self.content = kwargs.get("content")


class _FakeMitmFlow:
    def __init__(self, *, flow_id: str, request: Any, response: Any | None) -> None:
        self.id = flow_id
        self.request = request
        self.response = response


def test_flow_from_mitmproxy_object_maps_fields_and_preserves_duplicate_headers() -> None:
    request = _FakeMitmRequest(
        method="GET",
        pretty_url="https://api.bank.test/accounts/123?token=abc",
        host="api.bank.test",
        scheme="https",
        headers=[("Authorization", "Bearer secret")],
        content=b"",
    )
    response = _FakeMitmResponse(
        status_code=200,
        headers=[("Set-Cookie", "a=1"), ("Set-Cookie", "b=2")],
        content=b'{"ok": true}',
    )
    flow = _FakeMitmFlow(flow_id="abc-123", request=request, response=response)

    http_flow = _flow_from_mitmproxy_object(flow)

    assert http_flow.id == "abc-123"
    assert http_flow.method == "GET"
    assert http_flow.status_code == 200
    assert [h.value for h in http_flow.response_headers if h.name == "Set-Cookie"] == ["a=1", "b=2"]
    assert http_flow.response_body == '{"ok": true}'


def test_flow_from_mitmproxy_object_handles_missing_response() -> None:
    request = _FakeMitmRequest(
        method="GET",
        pretty_url="https://api.bank.test/health",
        host="api.bank.test",
        scheme="https",
        content=None,
    )
    flow = _FakeMitmFlow(flow_id="no-response", request=request, response=None)

    http_flow = _flow_from_mitmproxy_object(flow)

    assert http_flow.status_code is None
    assert http_flow.response_body is None
    assert http_flow.response_headers == []


def test_flow_from_mitmproxy_object_omits_binary_body() -> None:
    request = _FakeMitmRequest(
        method="GET",
        pretty_url="https://api.bank.test/logo.png",
        host="api.bank.test",
        scheme="https",
        content=None,
    )
    response = _FakeMitmResponse(
        status_code=200,
        headers=[("Content-Type", "image/png")],
        content=b"\x89PNG\r\n\x1a\n",
    )
    flow = _FakeMitmFlow(flow_id="binary", request=request, response=response)

    http_flow = _flow_from_mitmproxy_object(flow)

    assert http_flow.response_body is not None
    assert "omitted" in http_flow.response_body


# --- flow_ingestion (real mitmproxy .mitm round trip, skipped if not installed) ---


def test_load_http_flows_reads_a_real_mitm_file(tmp_path: Path) -> None:
    mitmproxy = pytest.importorskip("mitmproxy")
    from mitmproxy import io as mitm_io
    from mitmproxy.connection import Client, Server
    from mitmproxy.http import HTTPFlow, Request, Response

    request = Request.make(
        "GET",
        "https://api.bank.test/accounts/123",
        headers={"Host": "api.bank.test"},
    )
    response = Response.make(
        200,
        b'{"amount": 100000}',
        headers={"Content-Type": "application/json"},
    )
    client = Client(peername=("127.0.0.1", 1), sockname=("127.0.0.1", 2), timestamp_start=0.0)
    server = Server(address=("api.bank.test", 443))
    raw_flow = HTTPFlow(client, server)
    raw_flow.request = request
    raw_flow.response = response

    flow_path = tmp_path / "sample.mitm"
    with flow_path.open("wb") as handle:
        mitm_io.FlowWriter(handle).add(raw_flow)

    from vulle.dynamic.flow_ingestion import load_http_flows

    flows = load_http_flows(flow_path)

    assert len(flows) == 1
    assert flows[0].method == "GET"
    assert flows[0].status_code == 200
    assert mitmproxy.__name__ == "mitmproxy"


# --- http_traffic_rules ---


def test_cleartext_request_is_flagged() -> None:
    flow = _flow(scheme="http", url="http://api.bank.test/accounts/123")
    findings = evaluate_http_traffic_rules([flow])
    assert any(f.rule_id == "android.dynamic.cleartext_request" for f in findings)


def test_missing_hsts_flagged_only_when_absent() -> None:
    without_hsts = _flow()
    assert any(
        f.rule_id == "android.dynamic.missing_hsts"
        for f in evaluate_http_traffic_rules([without_hsts])
    )

    with_hsts = _flow(
        response_headers=[HttpHeader(name="Strict-Transport-Security", value="max-age=1")]
    )
    assert not any(
        f.rule_id == "android.dynamic.missing_hsts"
        for f in evaluate_http_traffic_rules([with_hsts])
    )


def test_missing_csp_only_flagged_for_html_responses() -> None:
    html_flow = _flow(
        response_headers=[HttpHeader(name="Content-Type", value="text/html; charset=utf-8")]
    )
    assert any(
        f.rule_id == "android.dynamic.missing_csp"
        for f in evaluate_http_traffic_rules([html_flow])
    )

    json_flow = _flow(response_headers=[HttpHeader(name="Content-Type", value="application/json")])
    assert not any(
        f.rule_id == "android.dynamic.missing_csp"
        for f in evaluate_http_traffic_rules([json_flow])
    )


def test_secret_in_traffic_detected() -> None:
    flow = _flow(response_body="leaked key AKIAABCDEFGHIJKLMNOP in response")
    assert any(
        f.rule_id == "android.dynamic.secret_in_traffic"
        for f in evaluate_http_traffic_rules([flow])
    )


def test_jwt_alg_none_is_flagged() -> None:
    flow = _flow(
        request_headers=[HttpHeader(name="Authorization", value=f"Bearer {_NONE_ALG_JWT}")]
    )
    assert any(
        f.rule_id == "android.dynamic.jwt_alg_none" for f in evaluate_http_traffic_rules([flow])
    )


def test_jwt_with_real_algorithm_is_not_flagged() -> None:
    flow = _flow(
        request_headers=[HttpHeader(name="Authorization", value=f"Bearer {_HS256_JWT}")]
    )
    assert not any(
        f.rule_id == "android.dynamic.jwt_alg_none" for f in evaluate_http_traffic_rules([flow])
    )


def test_cookie_missing_flags_detected() -> None:
    flow = _flow(response_headers=[HttpHeader(name="Set-Cookie", value="session=abc; Path=/")])
    findings = [
        f
        for f in evaluate_http_traffic_rules([flow])
        if f.rule_id == "android.dynamic.cookie_missing_flags"
    ]
    assert len(findings) == 1
    assert "Secure" in findings[0].title
    assert "HttpOnly" in findings[0].title


def test_cookie_with_all_flags_is_not_flagged() -> None:
    flow = _flow(
        response_headers=[
            HttpHeader(
                name="Set-Cookie",
                value="session=abc; Path=/; Secure; HttpOnly; SameSite=Strict",
            )
        ]
    )
    assert not any(
        f.rule_id == "android.dynamic.cookie_missing_flags"
        for f in evaluate_http_traffic_rules([flow])
    )


# --- crawler: pure helpers ---


def test_parse_clickable_elements_only_returns_clickable_nodes() -> None:
    xml_text = """<hierarchy>
        <node clickable="false" text="Header" resource-id="" class="TextView"
              bounds="[0,0][10,10]" />
        <node clickable="true" text="Login" resource-id="app:id/login" class="Button"
              bounds="[100,200][300,260]" />
    </hierarchy>"""

    elements = parse_clickable_elements(xml_text)

    assert len(elements) == 1
    assert elements[0].text == "Login"
    assert elements[0].bounds == "[100,200][300,260]"


def test_parse_clickable_elements_handles_malformed_xml() -> None:
    assert parse_clickable_elements("<not-valid-xml") == []


def test_is_denylisted_matches_case_insensitively() -> None:
    element = ClickableElement(
        text="Onayla",
        content_desc="",
        resource_id="app:id/confirm_btn",
        class_name="Button",
        bounds="[0,0][10,10]",
    )
    assert is_denylisted(element, ["confirm", "onayla"])


def test_is_denylisted_fails_closed_on_unreadable_element() -> None:
    element = ClickableElement(
        text="", content_desc="", resource_id="", class_name="Button", bounds="[0,0][10,10]"
    )
    assert is_denylisted(element, ["confirm"])


def test_center_of_computes_bounds_midpoint() -> None:
    assert center_of("[100,200][300,400]") == (200, 300)
    assert center_of("not-bounds") is None


# --- crawler: run_crawl_session with an injected fake adb client ---


class _FakeAdbClient:
    """Duck-typed stand-in for AdbClient, scripted per-call like FakeClassAnalysis."""

    def __init__(self, dump_sequence: list[str]) -> None:
        self._dump_sequence = dump_sequence
        self.launch_calls: list[str] = []
        self.tap_calls: list[tuple[int, int]] = []
        self.screenshot_calls: list[Path] = []
        self._dump_index = 0

    def launch_app(self, package: str) -> None:
        self.launch_calls.append(package)

    def dump_ui(self) -> str:
        xml = self._dump_sequence[min(self._dump_index, len(self._dump_sequence) - 1)]
        self._dump_index += 1
        return xml

    def tap(self, x: int, y: int) -> None:
        self.tap_calls.append((x, y))

    def screenshot(self, dest: Path) -> bytes:
        self.screenshot_calls.append(dest)
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(b"fake-png")
        return b"fake-png"


class _ErroringAdbClient(_FakeAdbClient):
    def dump_ui(self) -> str:
        raise AdbCommandError("device offline")


def _safe_button(name: str, x1: int, y1: int, x2: int, y2: int) -> str:
    return (
        f'<node clickable="true" text="{name}" resource-id="app:id/{name.lower()}" '
        f'class="Button" bounds="[{x1},{y1}][{x2},{y2}]" />'
    )


def _dangerous_button(name: str) -> str:
    return (
        f'<node clickable="true" text="{name}" resource-id="app:id/{name.lower()}" '
        'class="Button" bounds="[0,0][10,10]" />'
    )


def _settings(tmp_path: Path, *, kill_switch: Path | None = None) -> Settings:
    return Settings(
        _env_file=None,
        vulle_audit_log=tmp_path / "audit.jsonl",
    )


def test_crawl_session_stops_when_max_actions_reached(tmp_path: Path) -> None:
    xml = f"<hierarchy>{_safe_button('Details', 0, 0, 100, 100)}</hierarchy>"
    adb = _FakeAdbClient(dump_sequence=[xml])
    config = CrawlSessionConfig(
        package="com.bank.test",
        max_actions=3,
        kill_switch_path=tmp_path / "STOP",
        denylist_keywords=["confirm"],
        tap_settle_seconds=0.0,
        session_dir=tmp_path / "session",
    )

    report = run_crawl_session(config, adb, _settings(tmp_path))

    assert report.stop_reason == "max_actions_reached"
    assert report.actions_taken == 3
    assert adb.launch_calls == ["com.bank.test"]


def test_crawl_session_stops_on_kill_switch(tmp_path: Path) -> None:
    kill_switch = tmp_path / "STOP"
    kill_switch.write_text("stop")
    adb = _FakeAdbClient(dump_sequence=["<hierarchy></hierarchy>"])
    config = CrawlSessionConfig(
        package="com.bank.test",
        max_actions=30,
        kill_switch_path=kill_switch,
        denylist_keywords=[],
        tap_settle_seconds=0.0,
        session_dir=tmp_path / "session",
    )

    report = run_crawl_session(config, adb, _settings(tmp_path))

    assert report.stop_reason == "kill_switch"
    # kill-switch is checked before the loop's first dump/tap - only launch_app happened.
    assert adb.tap_calls == []


def test_crawl_session_stops_when_no_safe_candidates(tmp_path: Path) -> None:
    xml = f"<hierarchy>{_dangerous_button('Onayla')}</hierarchy>"
    adb = _FakeAdbClient(dump_sequence=[xml])
    config = CrawlSessionConfig(
        package="com.bank.test",
        max_actions=30,
        kill_switch_path=tmp_path / "STOP",
        denylist_keywords=["onayla"],
        tap_settle_seconds=0.0,
        session_dir=tmp_path / "session",
    )

    report = run_crawl_session(config, adb, _settings(tmp_path))

    assert report.stop_reason == "no_safe_candidates"
    assert report.denylist_blocked_count == 1
    assert adb.tap_calls == []


def test_crawl_session_taps_center_of_safe_element(tmp_path: Path) -> None:
    xml = (
        "<hierarchy>"
        + _safe_button("Details", 100, 200, 300, 400)
        + _dangerous_button("Onayla")
        + "</hierarchy>"
    )
    adb = _FakeAdbClient(dump_sequence=[xml])
    config = CrawlSessionConfig(
        package="com.bank.test",
        # Bounded so the session stops right after the single tap+screenshot: with a
        # static screen the crawler would otherwise keep re-tapping the same element.
        max_actions=4,
        kill_switch_path=tmp_path / "STOP",
        denylist_keywords=["onayla"],
        tap_settle_seconds=0.0,
        session_dir=tmp_path / "session",
    )

    report = run_crawl_session(config, adb, _settings(tmp_path))

    assert adb.tap_calls == [(200, 300)]
    assert report.denylist_blocked_count == 1
    assert len(report.screenshots) == 1


def test_crawl_session_reports_adb_error_without_raising(tmp_path: Path) -> None:
    adb = _ErroringAdbClient(dump_sequence=[])
    config = CrawlSessionConfig(
        package="com.bank.test",
        max_actions=10,
        kill_switch_path=tmp_path / "STOP",
        denylist_keywords=[],
        tap_settle_seconds=0.0,
        session_dir=tmp_path / "session",
    )

    report = run_crawl_session(config, adb, _settings(tmp_path))

    assert report.stop_reason == "adb_error"


def test_crawl_session_writes_audit_log_entries(tmp_path: Path) -> None:
    xml = f"<hierarchy>{_safe_button('Details', 0, 0, 100, 100)}</hierarchy>"
    adb = _FakeAdbClient(dump_sequence=[xml])
    config = CrawlSessionConfig(
        package="com.bank.test",
        max_actions=2,
        kill_switch_path=tmp_path / "STOP",
        denylist_keywords=[],
        tap_settle_seconds=0.0,
        session_dir=tmp_path / "session",
    )

    settings = _settings(tmp_path)
    run_crawl_session(config, adb, settings)

    lines = settings.vulle_audit_log.read_text(encoding="utf-8").strip().splitlines()
    events = [json.loads(line)["action"] for line in lines]
    assert "crawl.session_start" in events
    assert "crawl.session_end" in events
