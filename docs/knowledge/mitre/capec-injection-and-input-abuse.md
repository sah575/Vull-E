# MITRE CAPEC - Injection And Input Abuse Patterns

Source reference:
- MITRE CAPEC: https://capec.mitre.org/

Use this document when Jira or Confluence mentions user-controlled inputs that
drive queries, rendering, commands, file paths, templates, filters, reports,
imports, redirects, callbacks, or integrations.

## Pattern: Query Manipulation

Risk signals:
- Search, filter, report, dashboard, export, dynamic SQL/NoSQL, or custom query
  builder.

Test pattern:
- Try unexpected operators and field names.
- Try malformed filters.
- Check whether errors expose query internals.
- Verify parameterization or safe query builder use.

## Pattern: Output Injection

Risk signals:
- User-controlled text is rendered in HTML, notification, email, PDF, Excel,
  CSV, or template.

Test pattern:
- Identify output contexts.
- Verify context-specific encoding.
- Check stored and reflected paths.
- Check CSV/Excel formula handling.

## Pattern: Path Manipulation

Risk signals:
- filenames, download paths, archive extraction, template names, storage keys.

Test pattern:
- traversal sequences
- encoded paths
- path separators
- long filenames
- duplicate names

## Pattern: URL And Callback Manipulation

Risk signals:
- webhook URL, callback URL, redirect URL, import URL, image URL, document URL.

Test pattern:
- scheme validation
- host allowlist
- redirect handling
- DNS and private IP handling
- response size and timeout limits

## Vull-E Retrieval Keywords

CAPEC injection, input abuse, query manipulation, output injection, path
manipulation, URL manipulation, filter, report, template, callback, redirect,
webhook, import, export

