# OWASP ASVS - Data Protection And Logging Notes

Source reference:
- OWASP ASVS: https://owasp.org/www-project-application-security-verification-standard/

Use this document when Jira or Confluence mentions PII, KVKK, GDPR, card data,
account data, masking, encryption, export, logs, audit, monitoring, reporting,
or document viewing.

## Risk Signals

- New fields containing personal, financial, card, address, phone, email,
  national identity, account, transaction, or document data.
- Masking rules differ by role or channel.
- Export, report, print, PDF, Excel, email, SMS, or notification changes.
- Audit logging is required for approve, reject, access, update, or failed
  authorization events.
- New integration sends data to another system.

## Security Expectations

- Sensitive data should be minimized in responses.
- Masking rules must be enforced server-side.
- Logs must not contain secrets, tokens, OTPs, passwords, full card data, or
  unnecessary PII.
- Sensitive exports should require authorization, audit logs, and retention
  controls.
- Audit events should include actor, action, object, decision, timestamp,
  channel, correlation id, and business context.
- Failed authorization attempts should be logged without leaking sensitive
  values.

## Test Ideas

- Compare the same endpoint response across maker, checker, admin, branch user,
  and unauthorized users.
- Check whether masked fields become unmasked through export, print, detail,
  search, autocomplete, or mobile API paths.
- Trigger denied access and verify safe audit logging.
- Review response bodies, browser storage, URLs, and logs for sensitive data.
- Verify audit logs for approve/reject include actor role, object ID, branch or
  customer scope, result, and timestamp.
- Check if sensitive data appears in error messages or analytics events.

## Evidence

- Role used and expected masking rule.
- Response fields exposed.
- Export/report output if applicable.
- Audit event content.
- Log or error evidence with secrets redacted.

## Vull-E Retrieval Keywords

PII, KVKK, GDPR, masking, encryption, sensitive data, audit logging, monitoring,
export, report, print, document, card data, account data, customer data

