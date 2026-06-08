import json
from pathlib import Path
from typing import Any

import httpx
import typer
from rich.console import Console

from vulle.agents.jira_analysis import analyze_jira_issue
from vulle.banner import render_banner
from vulle.config import Settings, get_settings, set_active_profile
from vulle.confluence_client import ConfluenceClient, extract_confluence_urls
from vulle.doctor import run_doctor
from vulle.errors import VulleError
from vulle.jira_client import JiraClient, jira_payload_to_issue
from vulle.models import ConfluencePage, JiraIssue
from vulle.rag.evaluation import aggregate_results, evaluate_case
from vulle.rag.service import RagService

app = typer.Typer(help="Vull-E security analysis CLI")
console = Console()


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
def analyze_jira(issue_key: str, output: Path | None = None) -> None:
    """Fetch a Jira issue and analyze it with the local LLM."""
    render_banner(console)
    settings = get_settings()
    issue = JiraClient(settings).get_issue(issue_key)
    confluence_pages = _load_confluence_pages(issue, settings)
    analysis = analyze_jira_issue(issue, confluence_pages)
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


@app.command("rag-index")
def rag_index(
    path: Path,
    sync: bool = typer.Option(
        False,
        help="Replace the complete index root and remove stale/deleted documents.",
    ),
) -> None:
    """Index markdown, text, or JSON knowledge documents into Qdrant."""
    settings = get_settings()
    count = RagService(settings).index_path(path, sync=sync)
    console.print(f"[green]Indexed {count} chunk(s) into {settings.qdrant_collection}.[/green]")


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


def _issue_from_file_payload(payload: dict[str, Any]) -> JiraIssue:
    if "fields" in payload:
        return jira_payload_to_issue(payload)
    return JiraIssue.model_validate(payload)


def _load_confluence_pages(
    issue: JiraIssue,
    settings: Settings,
) -> list[ConfluencePage]:
    urls = extract_confluence_urls(issue)
    if not urls:
        return []
    try:
        pages = ConfluenceClient(settings).get_pages_from_issue(issue)
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
    return pages


def _emit_json(payload: Any, output: Path | None = None) -> None:
    rendered = json.dumps(payload, ensure_ascii=False, indent=2)
    if output is None:
        console.print_json(rendered)
        return
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(f"{rendered}\n", encoding="utf-8")
    console.print(f"[green]Wrote output to {output}.[/green]")


if __name__ == "__main__":
    app()
