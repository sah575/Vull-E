# OWASP Top 10 2021 - Vull-E Risk Mapping

Source reference:
- OWASP Top 10: https://owasp.org/Top10/2021/

Use this document for broad risk categorization. Prefer ASVS and WSTG documents
for detailed control and testing guidance.

## Categories Most Relevant To Jira Analysis

### Broken Access Control

Triggered by role changes, object identifiers, approval workflows, branch scope,
admin pages, or customer/account/document access.

Vull-E should produce IDOR, role bypass, forced browsing, and workflow bypass
test ideas.

### Cryptographic Failures

Triggered by sensitive data, PII, card data, masking, export files, logs, or
transport/storage changes.

Vull-E should ask whether data is encrypted, masked, minimized, and excluded
from logs.

### Injection

Triggered by search fields, filters, dynamic SQL, reports, exports, imports,
templates, LDAP queries, command execution, or user-controlled expressions.

Vull-E should recommend input validation and query parameterization checks.

### Insecure Design

Triggered by new business workflows, approval flows, limit handling, exception
paths, manual override, or complex state machines.

Vull-E should produce abuse-case and business-logic test ideas.

### Security Logging And Monitoring Failures

Triggered by approvals, rejects, failed authorization, sensitive data access,
role changes, or admin actions.

Vull-E should ask which events are logged, which fields are included, and how
failed authorization attempts are handled.

## Vull-E Retrieval Keywords

OWASP Top 10, broken access control, cryptographic failures, injection, insecure
design, logging, monitoring, sensitive data, business logic

