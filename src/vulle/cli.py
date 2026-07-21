import json
import os
from pathlib import Path
from typing import Any

import httpx
import typer
from rich.console import Console

from vulle.agents.jira_analysis import analyze_jira_issue
from vulle.banner import render_banner
from vulle.config import Settings, get_settings, set_active_profile
from vulle.confluence_client import (
    ConfluenceClient,
    extract_confluence_urls,
    filter_confluence_urls,
)
from vulle.doctor import run_doctor
from vulle.errors import VulleError
from vulle.jira_client import JiraClient, jira_payload_to_issue
from vulle.models import ConfluencePage, JiraIssue
from vulle.rag.evaluation import aggregate_results, evaluate_case
from vulle.rag.importers import (
    ImportReport,
    import_mitre_capec,
    import_mitre_cwe,
    import_owasp_api,
    import_owasp_mastg,
    import_owasp_masvs,
    import_owasp_wstg,
    import_payloads,
)
from vulle.rag.service import RagService

app = typer.Typer(help="Vull-E security analysis CLI")
console = Console()
CONFLUENCE_URL_OPTION = typer.Option(
    None,
    "--confluence-url",
    "-c",
    help="Confluence page URL to include when Jira does not expose the link.",
)
ASK_CONFLUENCE_URL_OPTION = typer.Option(
    True,
    "--ask-confluence-url/--no-ask-confluence-url",
    help="Prompt for a Confluence URL when none is discovered automatically.",
)
DEBUG_OPTION = typer.Option(
    False,
    "--debug",
    help="Print non-secret diagnostic metrics for Jira analysis and LLM calls.",
)
AUDIT_LOG_OPTION = typer.Option(
    None,
    "--audit-log",
    help="Write non-secret structured JSONL audit events to this file.",
)
FLOW_FILE_OPTION = typer.Option(
    None,
    "--flow-file",
    help="mitmweb-exported .mitm HTTP flow capture to use as additional evidence.",
)
SESSION_DIR_OPTION = typer.Option(None, help="Per-session screenshot/UI dump directory.")
_DEFAULT_CRAWLER_DENYLIST = [
    "onayla", "onay", "confirm", "confirmed", "transfer", "gönder", "gonder", "send",
    "sil", "delete", "sildim", "submit", "kaydet", "save", "ödeme", "odeme", "pay",
    "payment", "kabul et", "accept", "evet", "yes", "tamam", "ok", "devam", "proceed",
]


@app.callback()
def main(
    profile: str | None = typer.Option(
        None,
        help="Target profile name or explicit env file path.",
    ),
) -> None:
    """Select `.vulle/profiles/<name>.env` or an explicit env file path."""
    if profile:
        try:
            profile_path = set_active_profile(profile)
        except ValueError as exc:
            raise typer.BadParameter(str(exc), param_hint="--profile") from exc
        if not profile_path.is_file():
            raise typer.BadParameter(
                f"Profile file does not exist: {profile_path}",
                param_hint="--profile",
            )


@app.command("analyze-jira")
def analyze_jira(
    issue_key: str,
    output: Path | None = None,
    confluence_url: list[str] | None = CONFLUENCE_URL_OPTION,
    ask_confluence_url: bool = ASK_CONFLUENCE_URL_OPTION,
    debug: bool = DEBUG_OPTION,
    audit_log: Path | None = AUDIT_LOG_OPTION,
    flow_file: Path | None = FLOW_FILE_OPTION,
) -> None:
    """Fetch a Jira issue and analyze it with the local LLM."""
    render_banner(console)
    if debug:
        os.environ["VULLE_DEBUG"] = "true"
        get_settings.cache_clear()
    if audit_log:
        os.environ["VULLE_AUDIT_LOG"] = str(audit_log)
        get_settings.cache_clear()
    settings = get_settings()
    jira_client = JiraClient(settings)
    issue = jira_client.get_issue(issue_key)
    confluence_pages = _load_confluence_pages(
        issue,
        settings,
        jira_client=jira_client,
        manual_urls=confluence_url or [],
        ask_for_url=ask_confluence_url,
    )
    http_flows = _load_http_flows(flow_file)
    analysis = analyze_jira_issue(issue, confluence_pages, http_flows=http_flows)
    _emit_json(analysis.model_dump(), output)


@app.command("analyze-file")
def analyze_file(path: Path, output: Path | None = None) -> None:
    """Analyze a Jira-like JSON file without connecting to Jira."""
    render_banner(console)
    payload = json.loads(path.read_text(encoding="utf-8"))
    issue = _issue_from_file_payload(payload)
    confluence_pages = payload.get("confluence_pages", [])
    analysis = analyze_jira_issue(issue, confluence_pages)
    _emit_json(analysis.model_dump(), output)


@app.command("analyze-apk")
def analyze_apk(path: Path, output: Path | None = None) -> None:
    """Statically analyze an Android APK without contacting any backend."""
    render_banner(console)
    from vulle.apk.pipeline import analyze_apk_static

    report = analyze_apk_static(path)
    _emit_json(report.model_dump(), output)


@app.command("analyze-traffic")
def analyze_traffic(path: Path, output: Path | None = None) -> None:
    """Run deterministic checks over a captured .mitm HTTP flow file (no LLM, no Jira)."""
    render_banner(console)
    from vulle.dynamic.pipeline import analyze_traffic_file

    report = analyze_traffic_file(path)
    _emit_json(report.model_dump(), output)


@app.command("dynamic-crawl")
def dynamic_crawl(
    package: str,
    max_actions: int = typer.Option(30, help="Hard cap on total adb actions this session."),
    device: str | None = typer.Option(None, "--device", "-s", help="adb device serial."),
    session_dir: Path | None = SESSION_DIR_OPTION,
    output: Path | None = None,
) -> None:
    """Guardrailed automatic UI crawl of a rooted Android emulator via adb.

    Requires explicit confirmation before it taps anything; there is no --yes
    bypass, and every adb action is written to the audit log.
    """
    render_banner(console)
    from vulle.dynamic.adb import AdbClient
    from vulle.dynamic.crawler import run_crawl_session
    from vulle.dynamic.models import CrawlSessionConfig

    settings = get_settings()
    resolved_session_dir = session_dir or (settings.dynamic_session_dir / package)
    config = CrawlSessionConfig(
        package=package,
        max_actions=max_actions,
        device_serial=device,
        kill_switch_path=settings.dynamic_crawler_kill_switch_path,
        denylist_keywords=_DEFAULT_CRAWLER_DENYLIST,
        tap_settle_seconds=settings.dynamic_crawler_tap_settle_seconds,
        session_dir=resolved_session_dir,
    )
    console.print(
        f"[yellow]About to actively tap through '{package}' on device "
        f"{device or 'default'} for up to {max_actions} adb actions. "
        f"Kill switch: create {config.kill_switch_path} to stop early.[/yellow]"
    )
    typer.confirm("Continue?", abort=True)
    report = run_crawl_session(config, AdbClient(settings, device_serial=device), settings)
    _emit_json(report.model_dump(), output)


@app.command("rag-index")
def rag_index(
    path: Path,
    sync: bool = typer.Option(
        False,
        help="Replace the complete index root and remove stale/deleted documents.",
    ),
    dry_run: bool = typer.Option(
        False,
        help="Preview indexing without embedding, upsert, or delete operations.",
    ),
    output: Path | None = None,
) -> None:
    """Index markdown, text, or JSON knowledge documents into Qdrant."""
    settings = get_settings()
    report = RagService(settings, progress_callback=_print_progress).index_path_report(
        path,
        sync=sync,
        dry_run=dry_run,
    )
    _print_index_summary(report.model_dump())
    if output:
        _emit_json(report.model_dump(), output)


@app.command("rag-index-hacktricks")
def rag_index_hacktricks(
    path: Path,
    sync: bool = typer.Option(
        False,
        help="Replace the complete HackTricks index root and remove stale/deleted documents.",
    ),
    dry_run: bool = typer.Option(
        False,
        help="Preview indexing without embedding, upsert, or delete operations.",
    ),
    output: Path | None = None,
) -> None:
    """Index selected AppSec/Web/API HackTricks markdown documents into Qdrant."""
    settings = get_settings()
    if not path.exists() or not path.is_dir():
        raise typer.BadParameter(
            f"HackTricks path does not exist or is not a directory: {path}",
            param_hint="PATH",
        )
    report = RagService(settings, progress_callback=_print_progress).index_hacktricks_report(
        path,
        sync=sync,
        dry_run=dry_run,
    )
    console.print(
        "[yellow]HackTricks is external testing guidance, not bank policy or "
        "vulnerability evidence. Review current license terms before internal "
        "redistribution.[/yellow]"
    )
    if output:
        _print_index_summary(report.model_dump())
        _emit_json(report.model_dump(), output)
    else:
        _emit_json(report.model_dump())


@app.command("rag-import-owasp-wstg")
def rag_import_owasp_wstg(
    source: Path,
    output_root: Path = Path("docs/knowledge/generated"),
    output: Path | None = None,
) -> None:
    """Normalize selected OWASP WSTG markdown into generated RAG knowledge."""
    _emit_import_report(import_owasp_wstg(source, output_root), output)


@app.command("rag-import-owasp-api")
def rag_import_owasp_api(
    source: Path,
    output_root: Path = Path("docs/knowledge/generated"),
    output: Path | None = None,
) -> None:
    """Normalize OWASP API Security markdown into generated RAG knowledge."""
    _emit_import_report(import_owasp_api(source, output_root), output)


@app.command("rag-import-owasp-masvs")
def rag_import_owasp_masvs(
    source: Path,
    output_root: Path = Path("docs/knowledge/generated"),
    output: Path | None = None,
) -> None:
    """Normalize OWASP MASVS mobile security standard markdown."""
    _emit_import_report(import_owasp_masvs(source, output_root), output)


@app.command("rag-import-owasp-mastg")
def rag_import_owasp_mastg(
    source: Path,
    output_root: Path = Path("docs/knowledge/generated"),
    output: Path | None = None,
) -> None:
    """Normalize selected OWASP MASTG mobile testing markdown."""
    _emit_import_report(import_owasp_mastg(source, output_root), output)


@app.command("rag-import-payloads")
def rag_import_payloads(
    source: Path,
    output_root: Path = Path("docs/knowledge/generated"),
    output: Path | None = None,
) -> None:
    """Normalize selected PayloadsAllTheThings AppSec/API markdown."""
    _emit_import_report(import_payloads(source, output_root), output)


@app.command("rag-import-mitre-cwe")
def rag_import_mitre_cwe(
    source: Path,
    output_root: Path = Path("docs/knowledge/generated"),
    output: Path | None = None,
) -> None:
    """Normalize selected MITRE CWE CSV/XML records into generated markdown."""
    _emit_import_report(import_mitre_cwe(source, output_root), output)


@app.command("rag-import-mitre-capec")
def rag_import_mitre_capec(
    source: Path,
    output_root: Path = Path("docs/knowledge/generated"),
    output: Path | None = None,
) -> None:
    """Normalize selected MITRE CAPEC CSV/XML records into generated markdown."""
    _emit_import_report(import_mitre_capec(source, output_root), output)


@app.command("rag-search")
def rag_search(query: str, limit: int | None = None) -> None:
    """Search the Qdrant-backed knowledge base."""
    settings = get_settings()
    chunks = RagService(settings).search(query, limit)
    _emit_json([chunk.model_dump() for chunk in chunks])


@app.command("rag-eval")
def rag_eval(
    path: Path,
    limit: int | None = None,
    output: Path | None = None,
) -> None:
    """Evaluate whether expected knowledge sources are retrieved for sample queries."""
    settings = get_settings()
    service = RagService(settings)
    cases = json.loads(path.read_text(encoding="utf-8"))
    results = []
    for case in cases:
        chunks = service.search(case["query"], limit or settings.rag_top_k)
        results.append(evaluate_case(case, chunks))
    report = {
        "cases": results,
        "summary": aggregate_results(results),
    }
    _emit_json(report, output)


@app.command("banner")
def show_banner() -> None:
    """Print the Vull-E banner."""
    render_banner(console)


@app.command("doctor")
def doctor(
    offline: bool = typer.Option(
        False,
        help="Validate configuration without contacting external services.",
    ),
    output: Path | None = None,
) -> None:
    """Check target configuration and local service compatibility."""
    report = run_doctor(get_settings(), offline=offline)
    _emit_json(report.model_dump(), output)
    if not report.healthy:
        raise typer.Exit(code=1)


def _load_http_flows(flow_file: Path | None) -> list[Any]:
    if flow_file is None:
        return []
    from vulle.dynamic.flow_ingestion import load_http_flows

    flows = load_http_flows(flow_file)
    console.print(f"[cyan]Loaded {len(flows)} captured HTTP flow(s) from {flow_file}.[/cyan]")
    return flows


def _issue_from_file_payload(payload: dict[str, Any]) -> JiraIssue:
    if "fields" in payload:
        return jira_payload_to_issue(payload)
    return JiraIssue.model_validate(payload)


def _load_confluence_pages(
    issue: JiraIssue,
    settings: Settings,
    *,
    jira_client: JiraClient | None = None,
    manual_urls: list[str] | None = None,
    ask_for_url: bool = False,
) -> list[ConfluencePage]:
    urls = extract_confluence_urls(issue)
    if jira_client is not None:
        try:
            urls.extend(jira_client.get_remote_links(issue.key))
        except (httpx.HTTPError, VulleError) as exc:
            console.print(f"[yellow]Jira remote links could not be loaded: {exc}[/yellow]")
    if manual_urls:
        urls.extend(manual_urls)
    urls = filter_confluence_urls(urls)
    if not urls and ask_for_url:
        console.print("[yellow]No Confluence link was discovered from Jira.[/yellow]")
        try:
            manual_url = typer.prompt(
                "Confluence URL gir (boş bırak geç)",
                default="",
                show_default=False,
            ).strip()
        except (EOFError, KeyboardInterrupt):
            manual_url = ""
        if manual_url:
            urls = filter_confluence_urls([manual_url])
    if not urls:
        console.print("[yellow]No Confluence page will be included in this analysis.[/yellow]")
        return []
    try:
        pages = ConfluenceClient(settings).get_pages_from_urls(urls)
    except ValueError:
        console.print(
            "[yellow]Confluence link found, but Confluence credentials "
            "are not configured.[/yellow]"
        )
        return []
    except (httpx.HTTPError, VulleError) as exc:
        console.print(f"[yellow]Confluence pages could not be loaded: {exc}[/yellow]")
        return []
    if pages:
        console.print(f"[cyan]Loaded {len(pages)} Confluence page(s) from Jira links.[/cyan]")
    else:
        console.print(
            "[yellow]Confluence URLs were found, "
            "but no loadable page ID was detected.[/yellow]"
        )
    return pages


def _emit_json(payload: Any, output: Path | None = None) -> None:
    rendered = json.dumps(payload, ensure_ascii=False, indent=2)
    if output is None:
        console.print_json(rendered)
        return
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(f"{rendered}\n", encoding="utf-8")
    console.print(f"[green]Wrote output to {output}.[/green]")


def _emit_import_report(report: ImportReport, output: Path | None = None) -> None:
    payload = report.model_dump()
    console.print(f"Source: {payload['source_kind']}")
    console.print(f"Files scanned: {payload['files_scanned']}")
    console.print(f"Files written: {payload['files_written']}")
    console.print(f"Files skipped: {payload['files_skipped']}")
    console.print(f"Records scanned: {payload['records_scanned']}")
    console.print(f"Records written: {payload['records_written']}")
    console.print(f"Output path: {payload['output_path']}")
    if output:
        _emit_json(payload, output)


def _print_progress(event: dict[str, Any]) -> None:
    message = event.get("message")
    if message:
        console.print(f"[cyan]{message}[/cyan]")


def _print_index_summary(report: dict[str, Any]) -> None:
    console.print(f"Files scanned: {report.get('files_scanned', 0)}")
    console.print(f"Files accepted: {report.get('files_accepted', 0)}")
    console.print(f"Files skipped: {report.get('files_skipped', 0)}")
    console.print(f"Files failed: {report.get('files_failed', 0)}")
    console.print(f"Chunks created: {report.get('chunks_created', 0)}")
    console.print(f"Chunks upserted: {report.get('chunks_upserted', 0)}")
    console.print(f"Embedding batches: {report.get('embedding_batches', 0)}")
    console.print(f"Qdrant batches: {report.get('qdrant_batches', 0)}")
    console.print(f"Retries: {report.get('retry_count', 0)}")
    console.print(f"Warnings: {len(report.get('warnings', []))}")
    if report.get("commit_sha"):
        console.print(f"Commit SHA: {report['commit_sha']}")
    console.print(f"Dry run: {'yes' if report.get('dry_run') else 'no'}")


if __name__ == "__main__":
    app()
