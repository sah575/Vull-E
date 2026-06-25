# Vull-E

Vull-E is an agentic security-analysis prototype for pre-deployment review.

```text
██╗   ██╗██╗   ██╗██╗     ██╗          ███████╗
██║   ██║██║   ██║██║     ██║          ██╔════╝
██║   ██║██║   ██║██║     ██║  █████╗  █████╗
╚██╗ ██╔╝██║   ██║██║     ██║  ╚════╝  ██╔══╝
 ╚████╔╝ ╚██████╔╝███████╗███████╗     ███████╗
  ╚═══╝   ╚═════╝ ╚══════╝╚══════╝     ╚══════╝

PRE-DEPLOYMENT SECURITY INTELLIGENCE
LOCAL-FIRST APPSEC RAG | JIRA + CONFLUENCE | EVIDENCE-BOUND
[ JIRA+CONF ] => [ RAG ] => [ RISKS ] => [ TESTS ]
AUTHORIZED TESTING | GUIDANCE-AWARE | HUMAN-REVIEWED
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

For one local target, edit `.env`:

```bash
JIRA_BASE_URL=https://jira.example.com
JIRA_EMAIL=your.email@example.com
JIRA_API_TOKEN=your-token
JIRA_AUTH_MODE=basic
JIRA_API_VERSION=3
JIRA_ACCEPTANCE_CRITERIA_FIELD=

CONFLUENCE_BASE_URL=https://jira.example.com/wiki
CONFLUENCE_EMAIL=your.email@example.com
CONFLUENCE_API_TOKEN=your-token
CONFLUENCE_AUTH_MODE=basic

HTTP_VERIFY_SSL=true
HTTP_CA_BUNDLE=
VULLE_DEBUG=false

LLM_BASE_URL=http://127.0.0.1:8000/v1
LLM_API_KEY=local-not-needed
LLM_MODEL=gpt-oss-120b
LLM_TIMEOUT_SECONDS=120
LLM_MAX_TOKENS=4096
LLM_MAX_PROMPT_CHARS=45000
LLM_RAG_CONTEXT_CHARS=12000
LLM_CONFLUENCE_CHARS_PER_PAGE=6000
PII_REDACTION_MODE=off

EMBEDDING_BASE_URL=http://127.0.0.1:8000/v1
EMBEDDING_API_KEY=local-not-needed
EMBEDDING_MODEL=bge-m3
EMBEDDING_DIMENSIONS=1024
EMBEDDING_BATCH_SIZE=32

QDRANT_URL=http://127.0.0.1:6333
QDRANT_API_KEY=
QDRANT_PATH=
QDRANT_COLLECTION=vulle_knowledge
RAG_TENANT_ID=
RAG_ENVIRONMENT=preprod
RAG_KNOWLEDGE_BASE_ID=
RAG_TOP_K=6
RAG_MAX_CONTEXT_CHARS=8000
RAG_MAX_CHUNKS_PER_SOURCE=3

RAG_CANDIDATE_MULTIPLIER=4
RAG_DENSE_WEIGHT=0.65
RAG_LEXICAL_WEIGHT=0.20
RAG_SOURCE_WEIGHT=0.15
QDRANT_UPSERT_BATCH_SIZE=128
RAG_INDEX_RETRY_COUNT=3
RAG_INDEX_RETRY_BASE_DELAY_SECONDS=1
RAG_MAX_FILE_SIZE_MB=10
RAG_MAX_TOTAL_FILES=10000
RAG_MAX_CHUNKS_PER_DOCUMENT=500
RAG_FOLLOW_SYMLINKS=false
RAG_INDEX_SCHEMA_VERSION=2
```

The LLM server must expose an OpenAI-compatible `/chat/completions` API.
The embedding server must expose an OpenAI-compatible `/embeddings` API.

For an offline/local embedding server, place the model under
`models/BAAI/bge-m3` and run:

```bash
python -m pip install -e ".[embedding-server]"
python -m vulle.embedding_server --model-path models/BAAI/bge-m3 \
  --model-name BAAI/bge-m3 --host 127.0.0.1 --port 8010 \
  --device cpu --batch-size 4
```

Then set the active profile:

```env
EMBEDDING_BASE_URL=http://127.0.0.1:8010/v1
EMBEDDING_API_KEY=local-not-needed
EMBEDDING_MODEL=BAAI/bge-m3
EMBEDDING_DIMENSIONS=1024
EMBEDDING_BATCH_SIZE=4
EMBEDDING_TIMEOUT_SECONDS=600
```

Start local Qdrant with Docker:

```bash
docker compose up -d qdrant
```

If Docker is not available, use embedded Python Qdrant storage instead:

```env
QDRANT_PATH=.vulle/qdrant_local
```

When `QDRANT_PATH` is set, Vull-E uses local on-disk Qdrant storage inside the
Python process and ignores `QDRANT_URL`.

## Multiple Targets

For bank or multi-target use, prefer one complete profile file per target.
That avoids splitting Jira, Confluence, LLM, embedding, Qdrant, and TLS values
across several `.env` files. Store profiles under the git-ignored
`.vulle/profiles/` directory:

```bash
mkdir -p .vulle/profiles
cp examples/profiles/bank-a.env.example .vulle/profiles/bank-a.env
```

Put the target's full runtime configuration in that profile:

```env
JIRA_BASE_URL=https://atlas.example.local/jira
JIRA_EMAIL=your.email@example.com
JIRA_API_TOKEN=replace-me
JIRA_AUTH_MODE=bearer
JIRA_API_VERSION=2
JIRA_ACCEPTANCE_CRITERIA_FIELD=

CONFLUENCE_BASE_URL=https://atlas.example.local/confluence
CONFLUENCE_EMAIL=your.email@example.com
CONFLUENCE_API_TOKEN=
CONFLUENCE_AUTH_MODE=bearer

HTTP_VERIFY_SSL=true
HTTP_CA_BUNDLE=/secure/path/bank-ca-chain.pem

LLM_BASE_URL=http://llm.example.local:8000/v1
LLM_API_KEY=replace-me
LLM_MODEL=approved-local-model
LLM_TIMEOUT_SECONDS=120
LLM_MAX_TOKENS=4096
LLM_MAX_PROMPT_CHARS=45000

EMBEDDING_BASE_URL=http://embedding.example.local:8000/v1
EMBEDDING_API_KEY=replace-me
EMBEDDING_MODEL=approved-embedding-model
EMBEDDING_DIMENSIONS=1024

QDRANT_URL=http://127.0.0.1:6333
QDRANT_API_KEY=
QDRANT_PATH=.vulle/qdrant_local
QDRANT_COLLECTION=vulle_bank_a_knowledge

RAG_TENANT_ID=bank-a
RAG_ENVIRONMENT=preprod
RAG_KNOWLEDGE_BASE_ID=bank-a-security-v1
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

Profile values override the root `.env`. The root `.env` is optional when the
selected profile contains all required values. Do not commit profile files
because they contain credentials and internal URLs.

`JIRA_AUTH_MODE`, `JIRA_API_VERSION`, and `JIRA_ACCEPTANCE_CRITERIA_FIELD` are
profile-specific. Use `JIRA_AUTH_MODE=basic` for email/API-token authentication
or `JIRA_AUTH_MODE=bearer` for a Jira Data Center personal access token.
Leave the field empty to extract an Acceptance Criteria/Kabul Kriterleri
section from the description. Set it to the real Jira field ID, such as
`customfield_12345`, after validating the bank Jira response.

Keep `HTTP_VERIFY_SSL=true`. When the institution uses a private CA or TLS
inspection proxy, set `HTTP_CA_BUNDLE` to the approved PEM chain. Disabling
verification should only be a temporary diagnostic step.

Set `PII_REDACTION_MODE=mask` in profiles where common email, phone, Turkish
national ID, IBAN, and card-like values must be masked before embedding and LLM
analysis. Secrets and credentials are always redacted; `off` only disables the
optional PII layer.

Each profile should define a stable RAG scope:

```env
RAG_TENANT_ID=bank-a
RAG_ENVIRONMENT=preprod
RAG_KNOWLEDGE_BASE_ID=bank-a-security-v1
```

Every Qdrant search and delete operation is filtered by all three values.
Collection separation remains useful, but it is not the only isolation control.

## RAG Source Imports

External Tier-1/Tier-2 sources should be imported into normalized markdown
before indexing. Keep raw upstream repositories outside committed project
knowledge, for example under `external_sources/`:

```bash
git clone https://github.com/OWASP/wstg.git external_sources/owasp-wstg
git clone https://github.com/OWASP/API-Security.git external_sources/owasp-api-security
git clone https://github.com/swisskyrepo/PayloadsAllTheThings.git external_sources/payloadsallthethings
```

Generate normalized RAG documents:

```bash
vulle rag-import-owasp-wstg external_sources/owasp-wstg
vulle rag-import-owasp-api external_sources/owasp-api-security
vulle rag-import-payloads external_sources/payloadsallthethings
vulle rag-import-mitre-cwe external_sources/mitre/cwe.csv
vulle rag-import-mitre-capec external_sources/mitre/capec.xml
```

The import commands write to `docs/knowledge/generated/<source>/`. After import,
index the generated and curated knowledge:

```bash
vulle --profile bank-a rag-index docs/knowledge --sync
```

The import pipeline is selective: it keeps AppSec/API-relevant material and
skips broad low-value or unrelated content. MITRE CWE/CAPEC CSV/XML files are
converted into focused markdown records before indexing.

## Doctor

Run a complete compatibility check after moving Vull-E or changing models:

```bash
vulle --profile bank-a doctor
```

The command checks:

- Jira and Confluence configuration completeness
- Jira authentication, API version, and endpoint reachability
- Confluence authentication and endpoint reachability
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

Vull-E tries to load Confluence links from Jira description, comments, ADF link
attributes, and Jira remote links. If no Confluence link is discovered, the CLI
prompts for a URL. You can also pass one explicitly:

```bash
vulle analyze-jira BANK-123 --confluence-url "https://atlas.example.local/confluence/pages/12345"
vulle analyze-jira BANK-123 --no-ask-confluence-url
vulle analyze-jira BANK-123 --debug
```

`--debug` prints non-secret diagnostics such as prompt character counts, RAG
chunk count, Confluence character counts, HTTP status, and response shape. It
does not print API keys or bearer tokens. The same mode can be enabled with
`VULLE_DEBUG=true`.

Analyze from a local sample file:

```bash
vulle analyze-file examples/jira_issue.sample.json
vulle analyze-file examples/jira_issue.sample.json --output .vulle/reports/report.json
```

Index local RAG knowledge into Qdrant:

```bash
vulle rag-index docs/knowledge --sync
```

Normal indexing replaces old chunks for documents currently present. `--sync`
also removes chunks for files deleted from that index root. Use `--sync` after
upgrading so Qdrant receives scope, document version, source-priority, template,
and control-area metadata.

Collections indexed by an older Vull-E version do not contain tenant scope
metadata. Use a new collection name or recreate the old collection once during
migration, then run `rag-index --sync`. Legacy unscoped points are intentionally
invisible to scoped searches.

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

Preview an index without contacting embedding or Qdrant services:

```bash
vulle rag-index docs/knowledge --dry-run
vulle rag-index-hacktricks /path/to/hacktricks --dry-run --output .vulle/reports/hacktricks-index.json
```

Large index runs use bounded embedding and Qdrant batches:

```env
EMBEDDING_BATCH_SIZE=32
QDRANT_UPSERT_BATCH_SIZE=128
RAG_INDEX_RETRY_COUNT=3
RAG_INDEX_RETRY_BASE_DELAY_SECONDS=1
RAG_MAX_FILE_SIZE_MB=10
RAG_MAX_TOTAL_FILES=10000
RAG_MAX_CHUNKS_PER_DOCUMENT=500
RAG_FOLLOW_SYMLINKS=false
RAG_INDEX_SCHEMA_VERSION=2
```

These defaults are starting points. Tune them in the bank environment according
to the embedding server, GPU capacity, network behavior, and Qdrant capacity.
Indexing skips symlinks by default, rejects files that resolve outside the
index root, skips oversized or non-UTF-8 files with warnings, excludes common
build/cache/asset directories, and refuses destructive sync deletes when no
source files were accepted. Deterministic document and chunk IDs include the
tenant, environment, knowledge base, root-relative path, heading path, content
hash, and index schema version. Because `RAG_INDEX_SCHEMA_VERSION=2` changes ID
identity, recreate older collections or run a controlled `--sync` after
validating a dry run.

## HackTricks RAG Source

Vull-E can index a controlled subset of a locally cloned HackTricks repository
as external AppSec/Web/API testing guidance:

```bash
vulle rag-index-hacktricks /path/to/hacktricks --sync
```

The command does not clone HackTricks from the internet. It only reads the local
directory you provide. Selection is controlled by
`config/hacktricks_sources.yml`, which contains allow and exclude path patterns,
security-domain mappings, language, minimum content length, and source priority.
The default profile focuses on Web/API topics such as authentication,
authorization, IDOR/BOLA, file upload, SSRF, injection, JWT, OAuth/OIDC,
GraphQL, WebSocket, race/replay, rate limiting, request smuggling,
deserialization, open redirect, CORS, CSRF, XSS, path traversal, and HTTP
parameter pollution. It excludes binary exploitation, reverse engineering,
Active Directory, OS privilege escalation, forensics, wireless, CTF, cloud, and
Kubernetes content.

HackTricks chunks are marked as:

```json
{
  "source_type": "external_pentest_methodology",
  "source_name": "hacktricks",
  "evidence_type": "security_guidance",
  "authority_level": "guidance",
  "license_review_required": true
}
```

When the source directory is a Git repository, the current commit SHA is stored
as `version`; otherwise `unknown` is used with a warning. Internal documents,
Jira, and Confluence remain higher-priority evidence. HackTricks is useful for
test objectives, negative tests, attack scenarios, and edge cases, but it is not
bank policy, a business requirement, a system fact, or proof that a
vulnerability exists. Review the current HackTricks license before internal use
or redistribution.

Evaluate retrieval behavior with the existing evaluator after indexing the
desired sources:

```bash
vulle rag-eval tests/rag_eval_cases.json
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

Issue retrieval queries are decomposed into detected security facets instead of
running the same fixed queries for every change. Current facets include access
control, authentication/session, business logic, file handling, sensitive
data, audit logging, integrations/SSRF, injection, GraphQL, race/replay, mass
assignment, rate limiting, and common misconfiguration signals. Endpoint and
identifier names are carried into matching facet queries.

Knowledge documents are chunked according to their format. Markdown heading
paths are preserved, code blocks remain atomic, long tables repeat their header
across row-aware chunks, and JSON chunks carry a key path. This prevents a
control, table row, or structured object from being split by a generic
word-only chunker.

Context selection keeps complete chunks and enforces a per-source quota. It
does not truncate a retrieved chunk in the middle of a sentence or control.

Each risk hypothesis and test idea must include `supporting_evidence` using an
allowed Jira, Confluence, or RAG source ID plus an exact `evidence_quote`.
Unknown IDs and quotes not present in the cited source are removed; missing
coverage is exposed through `citation_warnings`. Invalid model JSON is retried
once with a schema-constrained repair prompt by default.

Evidence is classified as a system fact, business requirement, security policy,
security guidance, or past finding. Final risk confidence is recalculated in
code from validated evidence; generic guidance alone cannot produce high
confidence.

The graph state is intentionally generic so later agents can append recon
results, Burp MCP evidence, and validation outcomes without rewriting the Jira
analysis layer.

## Development Checks

Run the same checks used by CI:

```bash
ruff check src tests
mypy src/vulle
pytest --cov=vulle --cov-report=term-missing
bandit -q -r src/vulle
pip-audit --requirement constraints.txt
docker compose config
```

GitHub Actions runs these checks for pushes and pull requests and also scans
the repository for committed secrets.

Before moving to the bank environment, follow
[`docs/bank-integration-checklist.md`](docs/bank-integration-checklist.md).

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
