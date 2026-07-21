import json
from typing import Any

from vulle.models import HttpFlow

_MAX_BODY_CHARS_IN_EVIDENCE = 4000


def render_flow_as_evidence_text(flow: HttpFlow) -> str:
    """Render a captured HTTP flow into quotable, evidence-citable text.

    The layout (blank-line-separated paragraphs, one header per line) is
    deliberately shaped to match how ``jira_analysis._evidence_segments``
    splits source text into quotable segments - do not collapse this into a
    single-line/minified representation.
    """
    request_lines = [f"{flow.method} {flow.url} (host {flow.host}, scheme {flow.scheme})"]
    request_lines.extend(f"{header.name}: {header.value}" for header in flow.request_headers)

    status_line = (
        f"HTTP status {flow.status_code}" if flow.status_code is not None else "HTTP status unknown"
    )
    response_lines = [status_line]
    response_lines.extend(f"{header.name}: {header.value}" for header in flow.response_headers)

    paragraphs = ["\n".join(request_lines), "\n".join(response_lines)]
    if flow.request_body:
        paragraphs.append(f"Request body:\n{_render_body(flow.request_body)}")
    if flow.response_body:
        paragraphs.append(f"Response body:\n{_render_body(flow.response_body)}")
    return "\n\n".join(paragraphs)


def _render_body(body: str) -> str:
    rendered = _pretty_print_if_json(body)
    return _truncate(rendered, _MAX_BODY_CHARS_IN_EVIDENCE)


def _pretty_print_if_json(body: str) -> str:
    try:
        parsed = json.loads(body)
    except (json.JSONDecodeError, ValueError):
        return body
    return json.dumps(parsed, indent=2, ensure_ascii=False)


def _truncate(value: str, max_chars: int) -> str:
    if len(value) <= max_chars:
        return value
    return f"{value[:max_chars].rstrip()}\n[truncated]"


def compact_traffic_for_prompt(flows: list[HttpFlow], *, max_chars: int) -> list[dict[str, Any]]:
    """Greedy per-item truncate-and-break budget, mirroring
    ``jira_analysis._compact_rag_context`` for RAG chunks."""
    compact: list[dict[str, Any]] = []
    remaining = max_chars
    for flow in flows:
        if remaining <= 0:
            break
        item = _compact_flow(flow, text_chars=min(remaining, 1200))
        encoded = json.dumps(item, ensure_ascii=False, separators=(",", ":"))
        if len(encoded) > remaining and compact:
            break
        if len(encoded) > remaining:
            item = _compact_flow(flow, text_chars=max(200, remaining - 300))
            encoded = json.dumps(item, ensure_ascii=False, separators=(",", ":"))
        compact.append(item)
        remaining -= len(encoded)
    return compact


def _compact_flow(flow: HttpFlow, *, text_chars: int) -> dict[str, Any]:
    return {
        "id": flow.id,
        "method": flow.method,
        "url": flow.url,
        "status_code": flow.status_code,
        "text": _truncate(render_flow_as_evidence_text(flow), text_chars),
    }
