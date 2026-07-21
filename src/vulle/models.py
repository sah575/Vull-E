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


class RagSource(BaseModel):
    source: str
    title: str
    score: float | None = None
    chunk_id: str | None = None


class RagIndexReport(BaseModel):
    files_scanned: int = 0
    files_accepted: int = 0
    files_skipped: int = 0
    files_failed: int = 0
    chunks_created: int = 0
    chunks_upserted: int = 0
    chunks_failed: int = 0
    chunks_deleted: int = 0
    chunks_truncated: int = 0
    duplicate_chunks: int = 0
    embedding_batches: int = 0
    qdrant_batches: int = 0
    retry_count: int = 0
    source_type_distribution: dict[str, int] = Field(default_factory=dict)
    security_domain_distribution: dict[str, int] = Field(default_factory=dict)
    commit_sha: str | None = None
    warnings: list[str] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)
    dry_run: bool = False


class SecurityFacet(BaseModel):
    type: str
    terms: list[str] = Field(default_factory=list)


class HttpHeader(BaseModel):
    name: str
    value: str


class HttpFlow(BaseModel):
    id: str
    method: str
    url: str
    host: str
    scheme: Literal["http", "https"]
    status_code: int | None = None
    request_headers: list[HttpHeader] = Field(default_factory=list)
    request_body: str | None = None
    response_headers: list[HttpHeader] = Field(default_factory=list)
    response_body: str | None = None
    timestamp: float | None = None
    source: Literal["manual_capture", "crawler_capture"] = "manual_capture"


EvidenceType = Literal[
    "system_fact",
    "business_requirement",
    "security_policy",
    "security_guidance",
    "past_finding",
    "assumption",
]


class EvidenceReference(BaseModel):
    source_id: str
    evidence_quote: str
    evidence_type: EvidenceType
    relevance: str


class AnalysisMetadata(BaseModel):
    app_version: str
    prompt_version: str
    target_profile: str
    llm_model: str
    embedding_model: str
    qdrant_collection: str
    tenant_id: str
    environment: str
    knowledge_base_id: str
    confluence_pages_loaded: int = 0
    http_flows_loaded: int = 0


class RiskHypothesis(BaseModel):
    title: str
    vulnerability_class: str
    rationale: str
    likely_entry_points: list[str] = Field(default_factory=list)
    affected_roles: list[str] = Field(default_factory=list)
    confidence: Literal["low", "medium", "high"]
    confidence_reason: str
    severity_hint: Literal["info", "low", "medium", "high", "critical"]
    supporting_evidence: list[EvidenceReference]
    assumptions: list[str] = Field(default_factory=list)


class TestIdea(BaseModel):
    title: str
    objective: str
    preconditions: list[str] = Field(default_factory=list)
    steps: list[str] = Field(default_factory=list)
    expected_secure_behavior: str
    evidence_to_collect: list[str] = Field(default_factory=list)
    safety_notes: list[str] = Field(default_factory=list)
    supporting_evidence: list[EvidenceReference]
    assumptions: list[str] = Field(default_factory=list)


class JiraSecurityAnalysis(BaseModel):
    issue_key: str
    analysis_metadata: AnalysisMetadata | None = None
    rag_status: Literal["not_configured", "ok", "empty", "failed"] = "not_configured"
    rag_error: str | None = None
    rag_sources: list[RagSource] = Field(default_factory=list)
    citation_warnings: list[str] = Field(default_factory=list)
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
    http_flows: list[HttpFlow] = Field(default_factory=list)
    rag_context: list[RagChunk] = Field(default_factory=list)
    rag_status: Literal["not_configured", "ok", "empty", "failed"] = "not_configured"
    rag_error: str | None = None
    normalized_issue: dict[str, Any] = Field(default_factory=dict)
    security_signals: dict[str, Any] = Field(default_factory=dict)
    evidence_brief: dict[str, Any] = Field(default_factory=dict)
    risk_hypotheses: list[RiskHypothesis] = Field(default_factory=list)
    test_ideas: list[TestIdea] = Field(default_factory=list)
    analysis: JiraSecurityAnalysis | None = None
