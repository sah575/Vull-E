# Qdrant RAG Architecture

Vull-E uses Qdrant as the vector database for internal security knowledge.

```text
docs/knowledge
    |
    v
rag-index
    |
    v
document loader -> chunker -> embedding client
    |
    v
Qdrant collection: vulle_knowledge
```

During Jira analysis:

```text
Jira issue + Confluence pages
    |
    v
LangGraph normalize_issue
    |
    v
retrieve_context
    |
    v
embedding query -> Qdrant search -> relevant chunks
    |
    v
dense + lexical + source-priority reranking
    |
    v
analyze_issue prompt
```

Qdrant stores only document chunks and metadata. Jira and Confluence content is
used as the retrieval query and is not automatically written to Qdrant.
Common credential patterns are redacted before query embedding.
Optional PII masking is controlled by `PII_REDACTION_MODE=off|mask`. Secret
redaction is mandatory and remains enabled in both modes.

Every point includes `tenant_id`, `environment`, and `knowledge_base_id`.
Search, replacement, and sync deletion require all three values as server-side
Qdrant filters.

The embedding service must expose an OpenAI-compatible `/embeddings` endpoint.
The chat model must expose an OpenAI-compatible `/chat/completions` endpoint.

For local development:

```bash
docker compose up -d qdrant
vulle rag-index docs/knowledge --sync
vulle rag-search "maker checker approval"
vulle rag-eval tests/rag_eval_cases.json
```

Recommended knowledge layout:

```text
docs/knowledge/owasp/      public security standards and testing notes
docs/knowledge/mitre/      CWE weakness mappings and CAPEC attack patterns
docs/knowledge/portswigger/ PortSwigger-style practical web/API testing methodologies
docs/knowledge/internal/   sanitized bank/application-specific knowledge
docs/knowledge/examples/   small local examples and experiments
```

OWASP material should be summarized into retrieval-friendly notes with source
URLs. Internal documents should be sanitized before indexing; do not index
secrets, tokens, production credentials, or real customer data.

RAG context is not proof of a vulnerability. It should be used to generate and
rank hypotheses. Jira, Confluence, internal rules, and later Burp evidence are
needed before reporting a validated finding.

Vull-E exposes RAG health in the analysis JSON through `rag_status`, `rag_error`,
and `rag_sources`. Retrieval failures should be visible to reviewers and should
not be silently treated as a complete analysis.

Chunk metadata includes `source_type`, `source_priority`, `is_template`,
`control_areas`, stable `document_id`, `content_hash`, and `index_root` values.
Normal indexing replaces current documents; `--sync` rebuilds the scoped index
root and removes deleted documents. Template files are intentionally low
priority because an unfilled template is not an internal control or business
rule.

Markdown chunks preserve heading paths and keep code blocks intact. Long tables
are split by row with their header repeated. JSON documents are split by key
path and retain `json_path` metadata. Retrieval queries are generated only for
security facets detected in the Jira and Confluence text, while endpoint and
identifier terms are propagated into those facet queries.

Points created before tenant scoping are not matched by scoped filters. Migrate
once by using a new collection or recreating the existing collection, then run
`rag-index --sync`.
