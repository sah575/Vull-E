from vulle.agents.jira_analysis import _validate_evidence_references
from vulle.models import (
    EvidenceReference,
    JiraSecurityAnalysis,
    RiskHypothesis,
    TestIdea as AnalysisTestIdea,
)


def test_invalid_evidence_source_ids_are_removed() -> None:
    valid = EvidenceReference(
        source_id="jira:BANK-1:summary",
        evidence_quote="Maker checker change",
        relevance="Names the privileged workflow",
    )
    invalid = EvidenceReference(
        source_id="jira:BANK-1:summary",
        evidence_quote="Invented",
        relevance="Quote is not in the cited source",
    )
    analysis = JiraSecurityAnalysis(
        issue_key="BANK-1",
        change_summary="Change",
        risk_hypotheses=[
            RiskHypothesis(
                title="Risk",
                vulnerability_class="Authorization",
                rationale="Role boundary",
                confidence="medium",
                confidence_reason="The Jira summary names a role boundary",
                severity_hint="high",
                supporting_evidence=[valid, invalid],
            )
        ],
        test_ideas=[
            AnalysisTestIdea(
                title="Test",
                objective="Verify role boundary",
                expected_secure_behavior="Denied",
                supporting_evidence=[invalid],
            )
        ],
    )

    validated = _validate_evidence_references(
        analysis,
        {"jira:BANK-1:summary": "Maker checker change"},
    )

    assert validated.risk_hypotheses[0].supporting_evidence == [valid]
    assert validated.test_ideas[0].supporting_evidence == []
    assert validated.citation_warnings == ["Test idea has no valid citation: Test"]
