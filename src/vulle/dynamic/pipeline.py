from pathlib import Path

from vulle.dynamic.analyzers.http_traffic_rules import evaluate_http_traffic_rules
from vulle.dynamic.models import TrafficAnalysisReport
from vulle.errors import VulleError


def analyze_traffic_file(path: Path) -> TrafficAnalysisReport:
    """Run deterministic checks over a captured mitmproxy ``.mitm`` flow file."""
    from vulle.dynamic.flow_ingestion import load_http_flows

    analysis_limitations: list[str] = []
    try:
        flows = load_http_flows(path)
    except VulleError as exc:
        return TrafficAnalysisReport(
            flow_count=0,
            findings=[],
            analysis_limitations=[f"Failed to load flow file: {exc}"],
        )

    try:
        findings = evaluate_http_traffic_rules(flows)
    except Exception as exc:  # noqa: BLE001 - degrade to a limitation, never crash the CLI
        findings = []
        analysis_limitations.append(
            f"Failed to run deterministic traffic rules: {exc.__class__.__name__}: {exc}"
        )

    return TrafficAnalysisReport(
        flow_count=len(flows),
        findings=findings,
        analysis_limitations=analysis_limitations,
    )
