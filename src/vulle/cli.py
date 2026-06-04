import json
from pathlib import Path

import httpx
import typer
from dotenv import load_dotenv
from rich.console import Console

from vulle.agents.jira_analysis import analyze_jira_issue
from vulle.banner import BANNER
from vulle.confluence_client import ConfluenceClient, extract_confluence_urls
from vulle.config import get_settings
from vulle.jira_client import JiraClient, jira_payload_to_issue
from vulle.models import JiraIssue
from vulle.rag.service import RagService


app = typer.Typer(help="Vull-E security analysis CLI")
console = Console()


@app.callback()
def main() -> None:
    load_dotenv()


@app.command("analyze-jira")
def analyze_jira(issue_key: str) -> None:
    """Fetch a Jira issue and analyze it with the local LLM."""
    console.print(f"[bold cyan]{BANNER}[/bold cyan]")
    settings = get_settings()
    issue = JiraClient(settings).get_issue(issue_key)
    confluence_pages = _load_confluence_pages(issue, settings)
    analysis = analyze_jira_issue(issue, confluence_pages)
    console.print_json(analysis.model_dump_json(indent=2))


@app.command("analyze-file")
def analyze_file(path: Path) -> None:
    """Analyze a Jira-like JSON file without connecting to Jira."""
    console.print(f"[bold cyan]{BANNER}[/bold cyan]")
    payload = json.loads(path.read_text(encoding="utf-8"))
    issue = _issue_from_file_payload(payload)
    confluence_pages = payload.get("confluence_pages", [])
    analysis = analyze_jira_issue(issue, confluence_pages)
    console.print_json(analysis.model_dump_json(indent=2))


@app.command("rag-index")
def rag_index(path: Path) -> None:
    """Index markdown, text, or JSON knowledge documents into Qdrant."""
    settings = get_settings()
    count = RagService(settings).index_path(path)
    console.print(f"[green]Indexed {count} chunk(s) into {settings.qdrant_collection}.[/green]")


@app.command("rag-search")
def rag_search(query: str, limit: int | None = None) -> None:
    """Search the Qdrant-backed knowledge base."""
    settings = get_settings()
    chunks = RagService(settings).search(query, limit)
    console.print_json(json.dumps([chunk.model_dump() for chunk in chunks], ensure_ascii=False, indent=2))


@app.command("rag-eval")
def rag_eval(path: Path, limit: int | None = None) -> None:
    """Evaluate whether expected knowledge sources are retrieved for sample queries."""
    settings = get_settings()
    service = RagService(settings)
    cases = json.loads(path.read_text(encoding="utf-8"))
    results = []
    total_expected = 0
    total_hits = 0
    for case in cases:
        query = case["query"]
        expected = case.get("must_retrieve", [])
        chunks = service.search(query, limit or settings.rag_top_k)
        sources = [chunk.source for chunk in chunks]
        hits = [
            item
            for item in expected
            if any(item in source for source in sources)
        ]
        total_expected += len(expected)
        total_hits += len(hits)
        results.append(
            {
                "query": query,
                "expected": expected,
                "hits": hits,
                "misses": [item for item in expected if item not in hits],
                "retrieved_sources": sources,
                "hit_rate": len(hits) / len(expected) if expected else 1.0,
            }
        )
    output = {
        "cases": results,
        "overall_hit_rate": total_hits / total_expected if total_expected else 1.0,
    }
    console.print_json(json.dumps(output, ensure_ascii=False, indent=2))


@app.command("banner")
def show_banner() -> None:
    """Print the Vull-E banner."""
    console.print(f"[bold cyan]{BANNER}[/bold cyan]")


def _issue_from_file_payload(payload: dict) -> JiraIssue:
    if "fields" in payload:
        return jira_payload_to_issue(payload)
    return JiraIssue.model_validate(payload)


def _load_confluence_pages(issue: JiraIssue, settings) -> list:
    urls = extract_confluence_urls(issue)
    if not urls:
        return []
    try:
        pages = ConfluenceClient(settings).get_pages_from_issue(issue)
    except ValueError:
        console.print("[yellow]Confluence link found, but Confluence credentials are not configured.[/yellow]")
        return []
    except httpx.HTTPError as exc:
        console.print(f"[yellow]Confluence pages could not be loaded: {exc}[/yellow]")
        return []
    if pages:
        console.print(f"[cyan]Loaded {len(pages)} Confluence page(s) from Jira links.[/cyan]")
    return pages


if __name__ == "__main__":
    app()
