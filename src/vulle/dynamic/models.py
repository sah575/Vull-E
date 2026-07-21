from pathlib import Path
from typing import Literal

from pydantic import BaseModel, Field

DynamicFindingStatus = Literal[
    "confirmed_observation",
    "risk_hypothesis",
    "informational",
    "analysis_limitation",
]


class DynamicEvidence(BaseModel):
    artifact_type: Literal["http_flow", "screenshot", "ui_hierarchy", "logcat", "adb_shell"]
    artifact_path: str
    location: str
    quote: str


class DynamicFinding(BaseModel):
    id: str
    rule_id: str
    title: str
    category: str
    severity: Literal["info", "low", "medium", "high", "critical"]
    status: DynamicFindingStatus
    evidence: list[DynamicEvidence] = Field(default_factory=list)
    impact: str
    recommended_validation: list[str] = Field(default_factory=list)
    remediation: str


class ClickableElement(BaseModel):
    text: str
    content_desc: str
    resource_id: str
    class_name: str
    bounds: str


class CrawlSessionConfig(BaseModel):
    package: str
    max_actions: int
    device_serial: str | None = None
    kill_switch_path: Path
    denylist_keywords: list[str]
    tap_settle_seconds: float
    session_dir: Path


class CrawlSessionReport(BaseModel):
    session_id: str
    package: str
    started_at: str
    ended_at: str
    actions_taken: int
    stop_reason: Literal[
        "max_actions_reached",
        "kill_switch",
        "no_safe_candidates",
        "adb_error",
    ]
    screenshots: list[str] = Field(default_factory=list)
    denylist_blocked_count: int = 0


class TrafficAnalysisReport(BaseModel):
    flow_count: int
    findings: list[DynamicFinding] = Field(default_factory=list)
    analysis_limitations: list[str] = Field(default_factory=list)
