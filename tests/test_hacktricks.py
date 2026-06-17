from pathlib import Path

from typer.testing import CliRunner

from vulle.agents.jira_analysis import _evidence_context, _validate_evidence_references
from vulle.cli import app
from vulle.config import Settings
from vulle.models import (
    EvidenceReference,
    GraphState,
    JiraIssue,
    JiraSecurityAnalysis,
    RagChunk,
    RiskHypothesis,
)
from vulle.rag.documents import load_hacktricks_documents
from vulle.rag.hacktricks import (
    HACKTRICKS_SOURCE_TYPE,
    classify_security_domain,
    classify_security_domains,
    git_commit_sha,
    hacktricks_chunk_id,
    select_hacktricks_documents,
)
from vulle.rag.service import RagService, rerank_chunks

FIXTURES = Path("tests/fixtures/hacktricks")


def test_hacktricks_selector_allows_appsec_and_excludes_linux_privesc() -> None:
    documents, report = select_hacktricks_documents(FIXTURES)
    paths = {document.relative_path for document in documents}

    assert "pentesting-web/file-upload.md" in paths
    assert "pentesting-web/ssrf.md" in paths
    assert "linux/linux-privesc.md" not in paths
    assert report.scanned_files == 5
    assert report.accepted_files == 4
    assert report.excluded_files == 1


def test_hacktricks_chunk_metadata_preserves_heading_path_and_code_block() -> None:
    chunks, report = load_hacktricks_documents(FIXTURES, id_namespace="kb-a")
    upload_chunks = [
        chunk for chunk in chunks if chunk.metadata["security_domain"] == "file_upload"
    ]

    assert upload_chunks
    assert report.domain_counts["file_upload"] >= 1
    assert all(chunk.metadata["source_type"] == HACKTRICKS_SOURCE_TYPE for chunk in chunks)
    assert all(chunk.metadata["source_name"] == "hacktricks" for chunk in chunks)
    assert all(chunk.metadata["evidence_type"] == "security_guidance" for chunk in chunks)
    assert all(chunk.metadata["authority_level"] == "guidance" for chunk in chunks)
    assert all(chunk.metadata["is_internal"] is False for chunk in chunks)
    assert all(chunk.metadata["license_review_required"] is True for chunk in chunks)
    assert all(chunk.metadata["source_priority"] == 0.50 for chunk in chunks)
    assert any(
        chunk.metadata["heading_path"] == ["File Upload", "Bypass file extension checks"]
        for chunk in upload_chunks
    )
    assert any("```http" in chunk.text and "```" in chunk.text for chunk in upload_chunks)
    assert all("Title:" in chunk.text and "Content:" in chunk.text for chunk in chunks)


def test_hacktricks_domain_classification_is_deterministic() -> None:
    assert (
        classify_security_domain(
            "pentesting-web/graphql.md",
            "GraphQL",
            "Mutation authorization resolver object level checks",
        )
        == "graphql"
    )
    assert (
        classify_security_domain(
            "pentesting-web/jwt.md",
            "JWT",
            "JSON Web Token signature algorithm issuer audience",
        )
        == "jwt"
    )
    assert {
        "graphql",
        "access_control",
    } <= set(
        classify_security_domains(
            "pentesting-web/graphql.md",
            "GraphQL",
            "Mutation authorization resolver object level checks",
        )
    )


def test_hacktricks_chunk_ids_are_stable_and_namespace_aware() -> None:
    first = hacktricks_chunk_id(
        source_name="hacktricks",
        relative_path="pentesting-web/ssrf.md",
        heading_path=["SSRF", "URL allowlist"],
        content="same content",
        knowledge_base_id="kb-a",
    )
    second = hacktricks_chunk_id(
        source_name="hacktricks",
        relative_path="pentesting-web/ssrf.md",
        heading_path=["SSRF", "URL allowlist"],
        content="same content",
        knowledge_base_id="kb-a",
    )
    other_kb = hacktricks_chunk_id(
        source_name="hacktricks",
        relative_path="pentesting-web/ssrf.md",
        heading_path=["SSRF", "URL allowlist"],
        content="same content",
        knowledge_base_id="kb-b",
    )

    assert first == second
    assert first != other_kb
    assert len(first) == 36


def test_hacktricks_loader_deduplicates_identical_chunks(tmp_path: Path) -> None:
    root = tmp_path / "hacktricks"
    root.mkdir()
    content = (
        "# SSRF\n\nWebhook callback validation for server side request forgery testing.\n\n"
        "## URL allowlist\n\n"
        "SSRF tests should include localhost and private IP destination checks."
    )
    (root / "ssrf-a.md").write_text(content, encoding="utf-8")
    (root / "ssrf-b.md").write_text(content, encoding="utf-8")

    chunks, report = load_hacktricks_documents(root, id_namespace="kb-a")

    assert chunks
    assert report.deduplicated_chunks >= 1


def test_git_commit_sha_falls_back_for_non_git_directory(tmp_path: Path) -> None:
    assert git_commit_sha(tmp_path) == "unknown"


def test_git_commit_sha_reads_repository_version(tmp_path: Path, monkeypatch) -> None:
    sha = "a" * 40
    git_dir = tmp_path / ".git"
    ref_dir = git_dir / "refs" / "heads"
    ref_dir.mkdir(parents=True)
    (git_dir / "HEAD").write_text("ref: refs/heads/main\n", encoding="utf-8")
    (ref_dir / "main").write_text(f"{sha}\n", encoding="utf-8")

    assert git_commit_sha(tmp_path) == sha


def test_index_hacktricks_uses_replace_or_sync_without_real_services() -> None:
    class FakeEmbeddings:
        def embed_texts(self, texts: list[str]) -> list[list[float]]:
            return [[0.0] for _ in texts]

    class FakeStore:
        def __init__(self) -> None:
            self.deleted = False
            self.synced = False
            self.upserted = False

        def delete_documents(self, document_ids, *, source_name=None, source_type=None) -> None:
            self.deleted = bool(document_ids and source_name and source_type)

        def sync_index_root(
            self,
            index_root,
            chunks,
            vectors,
            *,
            source_name=None,
            source_type=None,
        ) -> None:
            self.synced = bool(index_root and source_name and source_type)

        def upsert_chunks(self, chunks, vectors) -> None:
            self.upserted = bool(chunks and vectors)

    service = object.__new__(RagService)
    service._settings = Settings(
        _env_file=None,
        rag_knowledge_base_id="kb-a",
    )
    service._embeddings = FakeEmbeddings()
    store = FakeStore()
    service._store = store

    replace_report = service.index_hacktricks(FIXTURES, sync=False)
    sync_report = service.index_hacktricks(FIXTURES, sync=True)

    assert store.deleted
    assert store.upserted
    assert store.synced
    assert replace_report["files_accepted"] == 4
    assert sync_report["chunks_created"]


def test_internal_policy_reranks_before_hacktricks_guidance() -> None:
    chunks = [
        RagChunk(
            id="hacktricks",
            source="hacktricks:pentesting-web/file-upload.md",
            title="File Upload",
            text="file upload extension validation negative tests",
            score=0.94,
            metadata={
                "source_type": "external_pentest_methodology",
                "source_priority": 0.50,
                "security_domain": "file_upload",
            },
        ),
        RagChunk(
            id="internal",
            source="docs/knowledge/internal/file-upload-policy.md",
            title="Internal File Upload Policy",
            text="file upload extension validation policy",
            score=0.82,
            metadata={
                "source_type": "internal",
                "source_priority": 1.0,
                "security_domain": "file_upload",
            },
        ),
    ]

    ranked = rerank_chunks(
        "file upload extension validation",
        chunks,
        2,
        dense_weight=0.35,
        lexical_weight=0.25,
        source_weight=0.40,
    )

    assert ranked[0].id == "internal"
    assert ranked[1].metadata["retrieval"]["domain_score"] == 0.03


def test_hacktricks_evidence_is_security_guidance_and_not_high_confidence() -> None:
    chunk = RagChunk(
        id="ht-1",
        source="hacktricks:pentesting-web/file-upload.md",
        title="File Upload",
        text="File upload flows should validate file type and authorization",
        metadata={
            "source_type": "external_pentest_methodology",
            "evidence_type": "security_guidance",
        },
    )
    analysis = JiraSecurityAnalysis(
        issue_key="BANK-HT",
        change_summary="Change",
        risk_hypotheses=[
            RiskHypothesis(
                title="Potential unsafe upload",
                vulnerability_class="File upload",
                rationale="External guidance suggests upload checks",
                confidence="high",
                confidence_reason="Model selected high",
                severity_hint="high",
                supporting_evidence=[
                    EvidenceReference(
                        source_id="rag:ht-1",
                        evidence_quote=(
                            "File upload flows should validate file type and authorization"
                        ),
                        evidence_type="system_fact",
                        relevance="Testing guidance",
                    )
                ],
            )
        ],
    )
    context = _evidence_context(
        GraphState(
            issue=JiraIssue(key="BANK-HT", summary="Upload"),
            rag_context=[chunk],
        )
    )

    validated = _validate_evidence_references(analysis, context)

    risk = validated.risk_hypotheses[0]
    assert risk.supporting_evidence[0].evidence_type == "security_guidance"
    assert risk.confidence == "low"


def test_rag_index_hacktricks_cli_reports_bad_path() -> None:
    runner = CliRunner()
    result = runner.invoke(app, ["rag-index-hacktricks", "tests/fixtures/missing"])

    assert result.exit_code != 0
    assert "Invalid value" in result.output
