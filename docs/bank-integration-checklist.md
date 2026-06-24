# Bank Pilot Migration Runbook

Use this runbook on the target device before changing retrieval or agent
architecture. Record non-secret results, timings, command output paths, and
error messages. Do not proceed through a gate while any required check is red.

## 0. Release Baseline

1. Use the tagged pre-bank-pilot release as the deployment baseline.
2. Confirm the worktree only contains deployment-local ignored files:

```bash
git fetch --tags
git checkout v0.1.0-pre-bank-pilot
git status --short
```

3. Do not develop new features during the pilot. Only allow configuration,
   sanitized knowledge updates, and defect fixes approved from observed pilot
   evidence.
4. Keep all target secrets, internal documents, reports, and profiles outside
   Git or under ignored paths.

Go/no-go: stop if the tag is missing, the checkout is dirty with tracked code
changes, or the deployed commit differs from the approved pilot baseline.

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
pip-audit --requirement constraints.txt
docker compose config
```

Expected: every command exits with status zero.

Go/no-go: stop if any command fails. Fix the baseline in development, retag a
new approved pilot baseline, and redeploy.

## 2. Target Profile

1. Copy `examples/profiles/bank-a.env.example` to
   `.vulle/profiles/<target>.env`.
2. Keep the target's complete runtime configuration in that one profile:
   Jira, Confluence, LLM, embedding, Qdrant, TLS, tenant, environment, and
   knowledge-base values. The root `.env` is optional when the profile contains
   all required values.
3. Keep `HTTP_VERIFY_SSL=true`.
4. Set `HTTP_CA_BUNDLE` when the bank uses a private CA or TLS inspection.
5. Use `QDRANT_PATH=.vulle/qdrant_local` when Docker/local admin rights are not
   available, or use `QDRANT_URL` for an approved Qdrant service.
6. Set `JIRA_AUTH_MODE=basic` for email/API-token authentication or
   `JIRA_AUTH_MODE=bearer` for a Jira Data Center personal access token.
7. Set `JIRA_API_VERSION` to the API version supported by the target.
8. Set `JIRA_ACCEPTANCE_CRITERIA_FIELD` only after confirming the real field ID.
9. Confirm the profile file is ignored by Git.
10. Set `CONFLUENCE_AUTH_MODE=basic` for email/API-token authentication or
   `CONFLUENCE_AUTH_MODE=bearer` for a Confluence Data Center personal access
   token. An omitted Confluence token reuses the configured Jira token.

```bash
git status --short
vulle --profile <target> doctor --offline
```

Go/no-go: stop if credentials are missing, the CA bundle is not approved, the
profile appears in `git status`, or the offline doctor reports failed required
configuration.

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

Go/no-go: stop if Jira, LLM, embedding, or Qdrant are required for the pilot and
doctor reports connection, TLS, authentication, permission, dimension, or
response-format failures. Confluence may remain disabled only when the pilot
scope explicitly excludes linked-page analysis.

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

Go/no-go: stop if the test issue cannot be fetched, if parsed fields are empty
or wrong, or if the service account can read issues outside the approved pilot
scope.

## 5. Confluence Validation

1. Confirm authentication and space visibility.
2. Confirm a Jira-linked page can be loaded.
3. Check tables, headings, links, and page body text.
4. Record whether Server/DC or Cloud endpoint behavior differs.
5. Confirm no page outside the intended target scope is retrieved.

Go/no-go: stop if linked pages cannot be fetched when Confluence is in scope, or
if the service account can read spaces outside the approved pilot scope.

## 6. Local Model Validation

1. Confirm the configured model name exists.
2. Confirm `response_format={"type":"json_object"}` is supported.
3. Run one structured response through `doctor`.
4. Record latency and timeout behavior.
5. Confirm invalid JSON repair behavior with a sanitized sample.

Do not add model-specific workarounds until actual incompatibility is observed.

Go/no-go: stop if the model cannot return valid JSON after the configured repair
attempts, if latency exceeds the pilot SLA, or if requests leave the approved
local environment.

## 7. Embedding And Qdrant

1. Confirm the embedding model name and vector dimension.
2. Confirm the Qdrant collection dimension matches.
3. Confirm tenant, environment, and knowledge-base scope values.
4. Preview every index run before writing vectors:

```bash
vulle --profile <target> rag-index docs/knowledge --dry-run \
  --output .vulle/reports/local-knowledge-dry-run.json
```

5. Review the dry-run report:
   - `files_failed` must be `0`.
   - `chunks_created` must be non-zero for intended knowledge roots.
   - skipped files must match expected templates, private paths, or unsupported
     files.
   - warnings must be understood and recorded.
6. Index only sanitized target documents after dry-run approval:

```bash
vulle --profile <target> rag-index docs/knowledge --sync
```

7. Search an exact endpoint, identifier, role, and business-flow term.
8. Verify every result belongs to the active target scope.

Go/no-go: stop if dry-run selection is wrong, if Qdrant dimensions do not match,
if scope metadata is missing, or if searches return another tenant,
environment, or knowledge base.

## 8. Optional HackTricks Source

HackTricks is external testing guidance. It is not bank policy, a business
requirement, a system fact, or proof of a vulnerability.

1. Confirm the local HackTricks clone path and license review status.
2. Preview the selected subset:

```bash
vulle --profile <target> rag-index-hacktricks /path/to/hacktricks \
  --dry-run \
  --output .vulle/reports/hacktricks-dry-run.json
```

3. Review the dry-run report:
   - `files_failed` must be `0`.
   - accepted files must be Web/API/AppSec methodology, primarily
     `pentesting-web` and `network-services-pentesting/pentesting-web`.
   - excluded files must include binary exploitation, reverse engineering,
     OS privilege escalation, Active Directory, cloud, Kubernetes, wireless,
     CTF, mobile, hardware physical access, todo, and welcome content.
   - `chunks_upserted` must be `0` in dry-run mode.
4. Index HackTricks only after explicit approval:

```bash
vulle --profile <target> rag-index-hacktricks /path/to/hacktricks --sync \
  --output .vulle/reports/hacktricks-index-report.json
```

Go/no-go: stop if the dry-run includes off-scope sources, license review is not
approved, or stakeholders do not want external testing guidance in the pilot
knowledge base.

## 9. First Analysis

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

Go/no-go: stop if citations are missing, evidence quotes do not exist in the
cited source, the report treats guidance as proof, or sensitive values are
visible.

## 10. Data Protection

1. Use `PII_REDACTION_MODE=mask` for the pilot.
2. Confirm tokens, cookies, API keys, private keys, and connection strings do
   not appear in output or logs.
3. Confirm email, phone, national ID, IBAN, and card-like values are masked
   before embedding and LLM requests.
4. Inspect generated reports before sharing or publishing.
5. Never commit profile files, internal documents, reports, or credentials.

Go/no-go: stop if secrets or PII appear in logs, embeddings, LLM prompts,
reports, or committed files.

## 11. Performance Record

Record:

- Jira request duration
- Confluence request duration
- embedding latency
- retrieval latency and chunk count
- LLM latency and JSON repair count
- total analysis duration
- timeout or retry events

## 12. Rollback

1. Disable the pilot profile or remove its credentials from the target device.
2. Stop services that were started only for the pilot.
3. Preserve non-secret reports and timing records under `.vulle/reports/`.
4. If indexed data must be removed, delete only the approved target collection
   or target-scoped points after confirming tenant, environment, and knowledge
   base.
5. Return the deployment checkout to the approved tag:

```bash
git checkout v0.1.0-pre-bank-pilot
```

## 13. Development Freeze

After the pre-bank-pilot baseline is tagged:

1. Stop feature development.
2. Do not change prompts, ranking, indexing, chunking, source filters, security
   controls, or connector behavior during the pilot unless a defect blocks a
   go/no-go gate.
3. Use observed Jira fields, model behavior, document quality, retrieval misses,
   and network constraints to choose the next engineering work after the pilot.
4. If a defect fix is required, create a new reviewed commit and tag. Do not
   move the existing pilot tag.
