from typing import Any, Literal

from pydantic import BaseModel, Field


class JiraIssue(BaseModel):
    key: str
    summary: str
    description: str | None = None
    issue_type: str | None = None
    status: str | None = None
    priority: str | None = None
    labels: list[str] = Field(default_factory=list)
    components: list[str] = Field(default_factory=list)
    comments: list[str] = Field(default_factory=list)
    acceptance_criteria: str | None = None
    raw: dict[str, Any] = Field(default_factory=dict)


class ConfluencePage(BaseModel):
    id: str
    title: str
    url: str | None = None
    space_key: str | None = None
    body_text: str


class RagChunk(BaseModel):
    id: str
    source: str
    title: str
    text: str
    score: float | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class RiskHypothesis(BaseModel):
    title: str
    vulnerability_class: str
    rationale: str
    likely_entry_points: list[str] = Field(default_factory=list)
    affected_roles: list[str] = Field(default_factory=list)
    confidence: Literal["low", "medium", "high"]
    severity_hint: Literal["info", "low", "medium", "high", "critical"]


class TestIdea(BaseModel):
    title: str
    objective: str
    preconditions: list[str] = Field(default_factory=list)
    steps: list[str] = Field(default_factory=list)
    expected_secure_behavior: str
    evidence_to_collect: list[str] = Field(default_factory=list)
    safety_notes: list[str] = Field(default_factory=list)


class JiraSecurityAnalysis(BaseModel):
    issue_key: str
    change_summary: str
    business_flows: list[str] = Field(default_factory=list)
    assets_or_entry_points: list[str] = Field(default_factory=list)
    trust_boundaries: list[str] = Field(default_factory=list)
    risk_hypotheses: list[RiskHypothesis] = Field(default_factory=list)
    test_ideas: list[TestIdea] = Field(default_factory=list)
    missing_information: list[str] = Field(default_factory=list)
    recommended_next_steps: list[str] = Field(default_factory=list)


class GraphState(BaseModel):
    issue: JiraIssue
    confluence_pages: list[ConfluencePage] = Field(default_factory=list)
    rag_context: list[RagChunk] = Field(default_factory=list)
    normalized_issue: dict[str, Any] = Field(default_factory=dict)
    security_signals: dict[str, Any] = Field(default_factory=dict)
    analysis: JiraSecurityAnalysis | None = None
