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
analyze_issue prompt
```

Qdrant stores only document chunks and metadata. Jira and Confluence content is
used as the retrieval query and is not automatically written to Qdrant.

The embedding service must expose an OpenAI-compatible `/embeddings` endpoint.
The chat model must expose an OpenAI-compatible `/chat/completions` endpoint.

For local development:

```bash
docker compose up -d qdrant
vulle rag-index docs/knowledge
vulle rag-search "maker checker approval"
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
