# MITRE CWE - Input Validation And Injection Mapping

Source reference:
- MITRE CWE: https://cwe.mitre.org/

Use this document when Jira or Confluence mentions user-controlled input,
search, filters, reports, exports, imports, templates, dynamic queries, command
execution, file paths, redirects, URLs, XML, JSON, SQL, NoSQL, LDAP, or
expression evaluation.

## Common CWE Mappings

### CWE-20 - Improper Input Validation

Use when a feature accepts input but the expected format, range, type, length,
or allowlist is unclear.

Jira signals:
- search filters
- sort parameters
- status/type fields
- import files
- amount/limit/range fields
- free-text criteria

Test direction:
- unexpected types
- null/empty values
- duplicate keys
- negative values
- large numbers
- overlong strings
- arrays/objects instead of scalar values

### CWE-89 - SQL Injection

Use when the ticket mentions SQL, reports, filters, dynamic query generation, or
database-backed search.

Vull-E should not generate destructive payloads. It should recommend safe,
authorized validation through controlled test inputs and code/config review.

Test direction:
- verify parameterized queries
- test unexpected filter operators
- check error messages for SQL details
- review whether sorting/filtering accepts raw field names

### CWE-79 - Cross-Site Scripting

Use when user-controlled text is rendered in web UI, notifications, comments,
file metadata, names, descriptions, or templates.

Test direction:
- identify rendering contexts
- check output encoding
- compare HTML, JavaScript, URL, JSON, and template contexts
- verify stored vs reflected paths

### CWE-78 - OS Command Injection

Use when input reaches shell commands, scripts, converters, antivirus wrappers,
document processing, image processing, or external utilities.

Test direction:
- review command construction
- verify argument separation
- avoid shell invocation where possible
- test only in isolated safe environment

### CWE-22 - Path Traversal

Use when file paths, filenames, downloads, archives, templates, or document
storage paths are user-controlled.

Test direction:
- filenames with traversal sequences
- URL-encoded path variants
- archive extraction paths
- direct download object authorization

### CWE-918 - Server-Side Request Forgery

Use when backend fetches a user-provided or partner-provided URL.

Test direction:
- scheme allowlist
- host allowlist
- DNS resolution
- redirect validation
- internal IP and metadata service blocking

## Evidence Expectations

- parameter name and expected format
- modified input
- response behavior
- error details if any
- side effects such as export, file creation, outbound request, or rendered UI
- relevant CWE mapping

## Vull-E Retrieval Keywords

CWE-20, CWE-89, CWE-79, CWE-78, CWE-22, CWE-918, input validation, injection,
SQL injection, XSS, command injection, path traversal, SSRF, search, report,
filter, import, export, template

