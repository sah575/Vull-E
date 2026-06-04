# Vull-E

Vull-E is an agentic security-analysis prototype for pre-deployment review.

```text
 __      __        _  _             ______
 \ \    / /       | || |           |  ____|
  \ \  / /  _   _ | || |  ______  | |__
   \ \/ /  | | | || || | |______| |  __|
    \  /   | |_| || || |          | |____
     \/     \__,_||_||_|          |______|

 Agentic Pre-Deployment Security Analysis
 Local LLM + Jira Intelligence + Future Burp MCP
```

The first milestone analyzes Jira issues with a local OpenAI-compatible model
such as `gpt-oss-120b` and produces a structured security review: assets,
business flows, likely vulnerability classes, test ideas, and follow-up
questions.

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
pip install -e .
cp .env.example .env
```

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
```

The LLM server must expose an OpenAI-compatible `/chat/completions` API.
The embedding server must expose an OpenAI-compatible `/embeddings` API.

Start local Qdrant:

```bash
docker compose up -d qdrant
```

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
```

Index local RAG knowledge into Qdrant:

```bash
vulle rag-index docs/knowledge
```

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

Search the knowledge base:

```bash
vulle rag-search "maker checker document approval"
```

Evaluate whether expected sources are retrieved for sample queries:

```bash
vulle rag-eval tests/rag_eval_cases.json
```

Output is written to stdout as JSON.

## Architecture

```text
CLI
  -> Jira + Confluence connectors / file loader
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
