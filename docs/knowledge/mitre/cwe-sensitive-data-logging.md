# MITRE CWE - Sensitive Data Exposure And Logging Mapping

Source reference:
- MITRE CWE: https://cwe.mitre.org/

Use this document when Jira or Confluence mentions PII, KVKK, GDPR, customer
data, account data, card data, documents, masking, audit logs, application
logs, exports, reports, notifications, or third-party data sharing.

## Common CWE Mappings

### CWE-200 - Exposure Of Sensitive Information To An Unauthorized Actor

Use when sensitive fields may be returned to users or roles that should not see
them.

Jira signals:
- customer detail
- document preview
- export
- report
- masked/unmasked behavior
- mobile API response
- search/autocomplete

Test direction:
- compare response fields across roles
- test export vs detail page
- test search/autocomplete leakage
- test unauthorized object access for partial data exposure

### CWE-201 - Insertion Of Sensitive Information Into Sent Data

Use when data is sent in responses, redirects, notifications, emails, SMS,
webhooks, or partner API calls.

Test direction:
- inspect response body, headers, URLs
- inspect email/SMS/notification content
- inspect webhook payloads
- confirm minimum necessary data

### CWE-532 - Insertion Of Sensitive Information Into Log File

Use when logs may contain tokens, OTPs, passwords, PII, account numbers, full
card data, request bodies, or authorization headers.

Test direction:
- review application logs for sensitive fields
- trigger error paths and denied authorization paths
- verify redaction for tokens and PII
- check correlation IDs do not embed sensitive values

### CWE-359 - Exposure Of Private Personal Information

Use for PII/KVKK/GDPR-related exposure.

Test direction:
- role-based masking
- export/download controls
- unauthorized branch/user access
- logging and audit paths

## Evidence Expectations

- data classification
- role and expected visibility
- exposed field names
- response/log/export sample with sensitive values redacted
- source of expected rule: internal policy, Jira, Confluence, or data standard

## Vull-E Retrieval Keywords

CWE-200, CWE-201, CWE-532, CWE-359, sensitive data, PII, KVKK, GDPR, masking,
audit log, application log, export, report, notification, webhook, data exposure

