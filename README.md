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
```

The LLM server must expose an OpenAI-compatible `/chat/completions` API.

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

Output is written to stdout as JSON.

## Architecture

```text
CLI
  -> Jira + Confluence connectors / file loader
  -> LangGraph workflow
      -> normalize issue
      -> extract security signals
      -> threat model
      -> test plan
      -> final structured report
```

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
