from pathlib import Path
from typing import Any

from vulle.dynamic.limits import MAX_FLOW_FILE_BYTES, MAX_FLOWS_INGESTED
from vulle.errors import VulleError
from vulle.models import HttpFlow, HttpHeader

_BINARY_CONTENT_TYPE_PREFIXES = ("image/", "video/", "audio/", "font/", "application/octet-stream")


def load_http_flows(path: Path) -> list[HttpFlow]:
    """Parse a mitmweb-exported ``.mitm`` flow file into HttpFlow records."""
    from mitmproxy import io as mitm_io
    from mitmproxy.http import HTTPFlow

    if not path.is_file():
        raise VulleError(f"Flow file does not exist: {path}")
    file_size = path.stat().st_size
    if file_size > MAX_FLOW_FILE_BYTES:
        raise VulleError(
            f"Flow file size {file_size} bytes exceeds the maximum of "
            f"{MAX_FLOW_FILE_BYTES} bytes: {path}"
        )

    flows: list[HttpFlow] = []
    with path.open("rb") as handle:
        reader = mitm_io.FlowReader(handle)
        try:
            for raw_flow in reader.stream():
                if not isinstance(raw_flow, HTTPFlow):
                    continue
                flows.append(_flow_from_mitmproxy_object(raw_flow))
                if len(flows) >= MAX_FLOWS_INGESTED:
                    break
        except ValueError as exc:
            raise VulleError(f"Failed to parse flow file {path}: {exc}") from exc
    return flows


def _flow_from_mitmproxy_object(raw_flow: Any) -> HttpFlow:
    request = raw_flow.request
    response = raw_flow.response

    request_headers = _headers_from_raw(request.headers)
    response_headers = _headers_from_raw(response.headers) if response is not None else []

    return HttpFlow(
        id=str(raw_flow.id),
        method=request.method,
        url=request.pretty_url,
        host=request.host,
        scheme=request.scheme,
        status_code=response.status_code if response is not None else None,
        request_headers=request_headers,
        request_body=_decode_body(request.content, request_headers),
        response_headers=response_headers,
        response_body=(
            _decode_body(response.content, response_headers) if response is not None else None
        ),
        timestamp=request.timestamp_start,
        source="manual_capture",
    )


def _headers_from_raw(headers: Any) -> list[HttpHeader]:
    return [HttpHeader(name=name, value=value) for name, value in headers.items(multi=True)]


def _decode_body(content: bytes | None, headers: list[HttpHeader]) -> str | None:
    if not content:
        return None
    content_type = next(
        (header.value for header in headers if header.name.lower() == "content-type"),
        "",
    ).lower()
    if content_type.startswith(_BINARY_CONTENT_TYPE_PREFIXES):
        return f"[omitted: binary content-type {content_type}, {len(content)} bytes]"
    try:
        return content.decode("utf-8")
    except UnicodeDecodeError:
        return f"[omitted: undecodable binary content, {len(content)} bytes]"
