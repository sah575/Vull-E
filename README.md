# Vull-E

Vull-E is an agentic security-analysis prototype for pre-deployment review.

```text
V   V  U   U  L      L       EEEEE
V   V  U   U  L      L       E
V   V  U   U  L      L       EEEE
 V V   U   U  L      L       E
  V     UUU   LLLLL  LLLLL   EEEEE

PRE-DEPLOYMENT SECURITY INTELLIGENCE
JIRA + CONFLUENCE > RAG > RISK HYPOTHESES > TEST PLANS
LOCAL-FIRST | EVIDENCE-BOUND | HUMAN-REVIEWED
```

The first milestone analyzes Jira issues with a local OpenAI-compatible model
such as `gpt-oss-120b` and produces a structured security review: assets,
business flows, likely vulnerability classes, test ideas, and follow-up
questions.

Jira, Confluence, and RAG content is treated as untrusted input. Common secret
patterns are redacted before retrieval and LLM analysis, document instructions
are explicitly ignored, and risk/test citations are checked against an allowed
source catalog.

## Current Scope

- Pull a Jira issue by key.
- Pull linked Confluence pages from the Jira description or comments.
- Extract summary, description, acceptance criteria, comments, and metadata.
- Analyze the change with a local LLM.
- Return structured JSON suitable for later automation.

Future modules can add recon, Burp MCP, access-control testing, evidence
collection, and Jira report publishing.

## Setup

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -c constraints.txt setuptools wheel
python -m pip install --no-build-isolation -c constraints.txt -e ".[dev]"
cp .env.example .env
```

`constraints.txt` pins the dependency versions validated for this repository.
Create it in the development environment, commit it, and use the same file on
the target device. Update it only as an intentional dependency upgrade.

Edit `.env`:

```bash
JIRA_BASE_URL=https://jira.example.com
JIRA_EMAIL=your.email@example.com
JIRA_API_TOKEN=your-token

CONFLUENCE_BASE_URL=https://jira.example.com/wiki
CONFLUENCE_EMAIL=your.email@example.com
CONFLUENCE_API_TOKEN=your-token

LLM_BASE_URL=http://127.0.0.1:8000/v1
LLM_API_KEY=local-not-needed
LLM_MODEL=gpt-oss-120b

EMBEDDING_BASE_URL=http://127.0.0.1:8000/v1
EMBEDDING_API_KEY=local-not-needed
EMBEDDING_MODEL=bge-m3
EMBEDDING_DIMENSIONS=1024

QDRANT_URL=http://127.0.0.1:6333
QDRANT_COLLECTION=vulle_knowledge

RAG_CANDIDATE_MULTIPLIER=4
RAG_DENSE_WEIGHT=0.65
RAG_LEXICAL_WEIGHT=0.20
RAG_SOURCE_WEIGHT=0.15
```

The LLM server must expose an OpenAI-compatible `/chat/completions` API.
The embedding server must expose an OpenAI-compatible `/embeddings` API.

Start local Qdrant:

```bash
docker compose up -d qdrant
```

## Multiple Targets

Keep shared local AI, embedding, and Qdrant settings in the root `.env`. Store
Jira and Confluence credentials per target under the git-ignored
`.vulle/profiles/` directory:

```bash
mkdir -p .vulle/profiles
cp examples/profiles/bank-a.env.example .vulle/profiles/bank-a.env
```

Use the profile before the command name:

```bash
vulle --profile bank-a analyze-jira BANK-123
vulle --profile bank-b analyze-jira PAY-456
vulle --profile bank-a rag-index docs/knowledge
```

A named profile resolves to `.vulle/profiles/<name>.env`. An explicit path is
also supported:

```bash
vulle --profile /secure/configs/bank-a.env doctor
```

Profile values override the shared `.env`. A target may override
`QDRANT_COLLECTION` to isolate its internal knowledge. Do not commit profile
files because they contain credentials.

## Doctor

Run a complete compatibility check after moving Vull-E or changing models:

```bash
vulle --profile bank-a doctor
```

The command checks:

- Jira and Confluence configuration completeness
- LLM `/chat/completions` connectivity and JSON output compatibility
- embedding `/embeddings` connectivity and configured vector dimensions
- Qdrant connectivity, collection existence, and vector dimensions
- RAG reranking configuration

Configuration can be checked before the services are available:

```bash
vulle --profile bank-a doctor --offline
```

`pass` means the component is compatible, `warn` means an optional component or
collection is absent, and `fail` causes a non-zero exit code. Doctor never prints
configured credentials.

## Run

Show the banner:

```bash
vulle banner
```

Analyze a live Jira issue:

```bash
vulle analyze-jira BANK-123
```

Analyze from a local sample file:

```bash
vulle analyze-file examples/jira_issue.sample.json
vulle analyze-file examples/jira_issue.sample.json --output .vulle/reports/report.json
```

Index local RAG knowledge into Qdrant:

```bash
vulle rag-index docs/knowledge
```

Re-run `rag-index` after upgrading an existing installation so Qdrant receives
the source-priority, template, and control-area metadata used by reranking.

The starter knowledge base includes OWASP-inspired notes under
`docs/knowledge/owasp/` plus small local examples for access control, IDOR, and
audit logging. These are retrieval-friendly security analysis notes, not full
copies of the OWASP projects. They are structured around Jira signals, expected
controls, test ideas, evidence, and Vull-E retrieval keywords.

The knowledge base also includes MITRE CWE and CAPEC notes under
`docs/knowledge/mitre/`. CWE is used for weakness classification and reporting
language. CAPEC is used for attack-pattern-oriented test planning.

PortSwigger-style methodology notes are under `docs/knowledge/portswigger/`.
They are practical testing workflows inspired by Web Security Academy topics,
written for Vull-E retrieval. They do not copy lab solutions.

The knowledge base also includes `docs/knowledge/rag-source-priority.md`, which
defines how Vull-E should treat retrieved context. OWASP notes are useful for
hypotheses and test strategy, but internal documents and direct evidence should
take priority when confidence is assigned.

For real use, fill the sanitized internal templates under
`docs/knowledge/internal/`:

```text
docs/knowledge/internal/role-matrix.template.md
docs/knowledge/internal/endpoint-inventory.template.md
docs/knowledge/internal/business-flows.template.md
docs/knowledge/internal/data-masking-standard.template.md
docs/knowledge/internal/audit-logging-standard.template.md
docs/knowledge/internal/past-findings.template.md
```

Keep the committed `.template.md` files as sanitized examples. Copy real
target-specific documents into the git-ignored
`docs/knowledge/internal/private/` directory and index that directory together
with the public knowledge base. Never commit internal architecture, role,
endpoint, finding, customer, or credential data.

Search the knowledge base:

```bash
vulle rag-search "maker checker document approval"
```

Evaluate whether expected sources are retrieved for sample queries:

```bash
vulle rag-eval tests/rag_eval_cases.json
vulle rag-eval tests/rag_eval_cases.json --output .vulle/reports/rag-eval.json
```

Evaluation reports Recall@K, Precision@K, MRR, expected source-type coverage,
and forbidden-source hit rate. Cases may use `expected_sources` (or the legacy
`must_retrieve` field), `expected_source_types`, and `forbidden_sources`.

Output is written to stdout as JSON.

## Architecture

```text
CLI
  -> Jira + Confluence connectors / file loader
  -> secret redaction and untrusted-input boundaries
  -> LangGraph workflow
      -> normalize issue
      -> retrieve Qdrant RAG context
      -> extract security signals
      -> threat model
      -> test plan
      -> final structured report
```

The analysis output includes `rag_status`, `rag_error`, and `rag_sources` so a
reviewer can tell whether the report used RAG context or fell back to Jira and
Confluence only.

Reports also include `analysis_metadata` with the Vull-E version, prompt
version, target profile, model names, and Qdrant collection used for
reproducibility.

Retrieval starts with a larger dense candidate pool and reranks it using dense
similarity, lexical overlap, and source priority. Filled internal documents are
preferred; `.template` files receive a low trust score and must not be treated
as bank policy. This is a compatibility-friendly hybrid reranker, not a full
sparse-vector/BM25 index.

Each risk hypothesis and test idea must include `supporting_evidence` using an
allowed Jira, Confluence, or RAG source ID plus an exact `evidence_quote`.
Unknown IDs and quotes not present in the cited source are removed; missing
coverage is exposed through `citation_warnings`. Invalid model JSON is retried
once with a schema-constrained repair prompt by default.

The graph state is intentionally generic so later agents can append recon
results, Burp MCP evidence, and validation outcomes without rewriting the Jira
analysis layer.

## Safety Notes

This repository is currently analysis-only. It does not scan, exploit, replay
requests, or interact with target applications.

When active testing is added, keep these controls mandatory:

- explicit scope allowlist
- destructive-action blocking
- rate limits
- immutable audit logs
- secrets redaction
- human approval for state-changing tests
