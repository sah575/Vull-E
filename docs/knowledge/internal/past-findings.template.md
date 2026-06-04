# Internal Template - Sanitized Past Findings

Purpose:
Capture sanitized historical findings so Vull-E can learn recurring weakness
patterns, likely risky modules, remediation examples, and false-positive
patterns.

Do not include real customer data, production credentials, tokens, or raw
production request/response bodies.

## Finding Template

### Finding ID

- Internal reference:
- Year:
- Application/domain:
- Severity:
- Status:

### Finding Summary

Describe the issue without sensitive data.

### Weakness Mapping

- OWASP category:
- CWE:
- CAPEC pattern:
- Affected asset type:

### Root Cause

Examples:

- missing object-level authorization
- incorrect branch-scope check
- client-controlled role field
- missing audit event
- excessive response field
- unsafe file parser

### Detection Pattern

How was it found?

- role replay
- object ID tampering
- endpoint forced browsing
- export comparison
- log review
- source review

### Safe Reproduction Pattern

Describe with synthetic IDs and test users only.

### Remediation Pattern

Describe accepted remediation:

- server-side authorization check
- centralized permission service
- object relationship validation
- response field filtering
- audit event addition
- deny-by-default rule

### False Positive Notes

When should Vull-E avoid reporting a similar case?

## Vull-E Retrieval Keywords

past findings, remediation, root cause, recurring issue, IDOR, role bypass,
branch scope, audit log, data exposure, false positive, detection pattern

