import json
from typing import Any

from langgraph.graph import END, StateGraph

from vulle.config import get_settings
from vulle.llm import LLMClient
from vulle.models import ConfluencePage, GraphState, JiraIssue, JiraSecurityAnalysis


SYSTEM_PROMPT = """You are a senior application security analyst.
Analyze pre-deployment Jira issues and produce practical, testable security
review output. Focus on authorization, IDOR, role confusion, authentication,
input validation, file handling, business logic, sensitive data exposure, audit
logging, and abuse cases.

Return only valid JSON that matches the requested schema. Do not include
exploit payloads for destructive actions. Keep test ideas safe for an authorized
pre-production banking environment.
"""


def build_jira_analysis_graph() -> Any:
    graph = StateGraph(GraphState)
    graph.add_node("normalize_issue", normalize_issue)
    graph.add_node("extract_security_signals", extract_security_signals)
    graph.add_node("analyze_issue", analyze_issue)
    graph.set_entry_point("normalize_issue")
    graph.add_edge("normalize_issue", "extract_security_signals")
    graph.add_edge("extract_security_signals", "analyze_issue")
    graph.add_edge("analyze_issue", END)
    return graph.compile()


def analyze_jira_issue(
    issue: JiraIssue,
    confluence_pages: list[ConfluencePage] | None = None,
) -> JiraSecurityAnalysis:
    graph = build_jira_analysis_graph()
    final_state = graph.invoke(GraphState(issue=issue, confluence_pages=confluence_pages or []))
    analysis = final_state["analysis"] if isinstance(final_state, dict) else final_state.analysis
    if analysis is None:
        raise RuntimeError("Jira analysis graph finished without analysis")
    return analysis


def normalize_issue(state: GraphState) -> dict[str, Any]:
    issue = state.issue
    normalized = {
        "key": issue.key,
        "summary": issue.summary,
        "description": issue.description,
        "acceptance_criteria": issue.acceptance_criteria,
        "issue_type": issue.issue_type,
        "status": issue.status,
        "priority": issue.priority,
        "labels": issue.labels,
        "components": issue.components,
        "comments": issue.comments,
        "confluence_pages": [
            {
                "id": page.id,
                "title": page.title,
                "url": page.url,
                "space_key": page.space_key,
                "body_text": page.body_text,
            }
            for page in state.confluence_pages
        ],
    }
    return {"normalized_issue": normalized}


def extract_security_signals(state: GraphState) -> dict[str, Any]:
    text = json.dumps(state.normalized_issue, ensure_ascii=False).lower()
    signal_keywords = {
        "idor": ["id", "object", "account", "customer", "user id", "iban", "hesap", "müşteri"],
        "authorization": ["role", "permission", "yetki", "maker", "checker", "admin", "approval"],
        "authentication": ["login", "session", "token", "otp", "mfa", "password"],
        "file_upload": ["upload", "file", "document", "excel", "pdf", "dosya"],
        "sensitive_data": ["pii", "personal", "kvkk", "mask", "card", "email", "phone"],
        "business_logic": ["limit", "transfer", "payment", "fee", "approve", "reject", "workflow"],
        "external_integration": ["webhook", "callback", "api", "integration", "third party"],
    }
    signals = {
        name: [keyword for keyword in keywords if keyword in text]
        for name, keywords in signal_keywords.items()
    }
    return {"security_signals": {k: v for k, v in signals.items() if v}}


def analyze_issue(state: GraphState) -> dict[str, Any]:
    settings = get_settings()
    llm = LLMClient(settings)
    schema = JiraSecurityAnalysis.model_json_schema()
    user_prompt = f"""Analyze this Jira issue for pre-deployment security testing.

Jira issue:
{json.dumps(state.normalized_issue, ensure_ascii=False, indent=2)}

Detected keyword signals:
{json.dumps(state.security_signals, ensure_ascii=False, indent=2)}

Required JSON schema:
{json.dumps(schema, ensure_ascii=False, indent=2)}
"""
    analysis = llm.complete_json(SYSTEM_PROMPT, user_prompt, JiraSecurityAnalysis)
    return {"analysis": analysis}
