# Bank Environment Integration Checklist

Use this checklist on the target device before changing retrieval or agent
architecture. Record non-secret results, timings, and error messages.

## 1. Installation And Baseline

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -c constraints.txt setuptools wheel
python -m pip install --no-build-isolation -c constraints.txt -e ".[dev]"

ruff check src tests
mypy src/vulle
pytest --cov=vulle --cov-report=term-missing --cov-fail-under=65
bandit -q -r src/vulle
```

Expected: every command exits with status zero.

## 2. Target Profile

1. Copy `examples/profiles/bank-a.env.example` to
   `.vulle/profiles/<target>.env`.
2. Set Jira, Confluence, model, embedding, Qdrant, tenant, environment, and
   knowledge-base values.
3. Keep `HTTP_VERIFY_SSL=true`.
4. Set `HTTP_CA_BUNDLE` when the bank uses a private CA or TLS inspection.
5. Set `JIRA_API_VERSION` to the API version supported by the target.
6. Set `JIRA_ACCEPTANCE_CRITERIA_FIELD` only after confirming the real field ID.
7. Confirm the profile file is ignored by Git.

```bash
git status --short
vulle --profile <target> doctor --offline
```

## 3. Network Access

Confirm DNS, proxy, firewall, and certificate-chain access for:

- Jira base URL
- Confluence base URL
- local LLM `/chat/completions`
- embedding `/embeddings`
- Qdrant

Run:

```bash
vulle --profile <target> doctor
```

The doctor report distinguishes connection, timeout, authentication,
permission, TLS certificate, endpoint, response-format, dimension, and Qdrant
compatibility failures.

## 4. Jira Validation

1. Confirm authentication succeeds.
2. Confirm `/rest/api/<version>/myself` is reachable.
3. Fetch one non-sensitive test issue.
4. Confirm summary, description, status, priority, labels, components, and
   comments are parsed.
5. Inspect the returned field names before setting
   `JIRA_ACCEPTANCE_CRITERIA_FIELD`.
6. Confirm the configured custom field is present and contains expected text.
7. Confirm issue permissions match the intended review scope.

## 5. Confluence Validation

1. Confirm authentication and space visibility.
2. Confirm a Jira-linked page can be loaded.
3. Check tables, headings, links, and page body text.
4. Record whether Server/DC or Cloud endpoint behavior differs.
5. Confirm no page outside the intended target scope is retrieved.

## 6. Local Model Validation

1. Confirm the configured model name exists.
2. Confirm `response_format={"type":"json_object"}` is supported.
3. Run one structured response through `doctor`.
4. Record latency and timeout behavior.
5. Confirm invalid JSON repair behavior with a sanitized sample.

Do not add model-specific workarounds until actual incompatibility is observed.

## 7. Embedding And Qdrant

1. Confirm the embedding model name and vector dimension.
2. Confirm the Qdrant collection dimension matches.
3. Confirm tenant, environment, and knowledge-base scope values.
4. Index only sanitized target documents:

```bash
vulle --profile <target> rag-index docs/knowledge --sync
```

5. Search an exact endpoint, identifier, role, and business-flow term.
6. Verify every result belongs to the active target scope.

## 8. First Analysis

Use one sanitized, representative Jira issue:

```bash
vulle --profile <target> analyze-jira BANK-123 \
  --output .vulle/reports/BANK-123.json
```

Review:

- change summary accuracy
- detected security areas
- retrieved source relevance
- no stale/template/other-tenant evidence
- citation source IDs and exact quotes
- confidence level and assumptions
- safe, executable test steps
- no claim of a confirmed vulnerability without runtime evidence

## 9. Data Protection

1. Use `PII_REDACTION_MODE=mask` for the pilot.
2. Confirm tokens, cookies, API keys, private keys, and connection strings do
   not appear in output or logs.
3. Confirm email, phone, national ID, IBAN, and card-like values are masked
   before embedding and LLM requests.
4. Inspect generated reports before sharing or publishing.
5. Never commit profile files, internal documents, reports, or credentials.

## 10. Performance Record

Record:

- Jira request duration
- Confluence request duration
- embedding latency
- retrieval latency and chunk count
- LLM latency and JSON repair count
- total analysis duration
- timeout or retry events

Stop feature development after this baseline. Use observed Jira fields, model
behavior, document quality, retrieval misses, and network constraints to choose
the next engineering work.
