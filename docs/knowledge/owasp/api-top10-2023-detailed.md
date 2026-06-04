# OWASP API Security Top 10 2023 - Detailed Vull-E Mapping

Source references:
- OWASP API Security Top 10 2023: https://owasp.org/API-Security/editions/2023/en/0x00-header/
- OWASP API Security Project: https://owasp.org/www-project-api-security/

Use this document to map Jira API changes to API-specific risk categories and
generate concrete test hypotheses.

## API1 - Broken Object Level Authorization

Risk signals:
- Path or body contains direct object IDs.
- API returns customer, account, card, document, transaction, case, or branch
  objects.
- Ticket says users can only access assigned customers, own accounts, own cases,
  or branch-scoped records.

Test ideas:
- Change one object ID at a time.
- Test parent-child mismatch such as customerId A with documentId B.
- Test list and detail endpoints separately.
- Test export and report endpoints for the same object family.

## API2 - Broken Authentication

Risk signals:
- Login, token, refresh token, OTP, MFA, device binding, password reset, SSO,
  mobile session, or channel authentication changes.

Test ideas:
- Reuse old tokens after password reset, logout, role change, or MFA update.
- Verify refresh token rotation and replay handling.
- Check whether OTP is bound to user, session, and transaction.

## API3 - Broken Object Property Level Authorization

Risk signals:
- API returns nested objects.
- Request body accepts full customer/account/user/document objects.
- Ticket mentions field-level masking or role-based visibility.

Test ideas:
- Compare response fields across roles.
- Try adding privileged fields to update requests.
- Check whether hidden fields are accepted and persisted.

## API4 - Unrestricted Resource Consumption

Risk signals:
- Search, export, report, file upload, bulk operation, pagination, expensive
  filters, async jobs, PDF generation, or external API calls.

Test ideas:
- Increase page size, date range, file size, item count, or nested depth.
- Check rate limits and job limits.
- Verify expensive operations require authorization and throttling.

## API5 - Broken Function Level Authorization

Risk signals:
- New privileged API action such as approve, reject, cancel, reverse, export,
  role update, branch assignment, or admin operation.

Test ideas:
- Call privileged action with lower-privileged token.
- Call hidden endpoint directly even if UI does not show it.
- Check method override and alternate route aliases.

## API6 - Unrestricted Access To Sensitive Business Flows

Risk signals:
- High-value workflows such as payment, transfer, onboarding, activation,
  approval, limit change, account closure, or document approval.

Test ideas:
- Check abuse cases, rate limits, duplicate submissions, replay, and self-approval.
- Verify monitoring and audit controls.

## API7 - Server Side Request Forgery

Risk signals:
- API accepts URL, webhook, callback, image URL, document URL, import URL,
  redirect URL, or external integration target.

Test ideas:
- Validate scheme and host allowlist.
- Block internal IP ranges and metadata services.
- Check redirects, DNS resolution, and encoded host variants.

## API8 - Security Misconfiguration

Risk signals:
- New API gateway route, CORS change, environment config, debug mode,
  documentation exposure, admin console, headers, or error handling change.

Test ideas:
- Check CORS origin handling.
- Check verbose errors and stack traces.
- Check exposed OpenAPI docs, actuator endpoints, and admin routes.

## API9 - Improper Inventory Management

Risk signals:
- Deprecated endpoint, legacy route, mobile-only API, versioned API, shadow API,
  temporary migration endpoint, or external partner API.

Test ideas:
- Verify old versions enforce the same authorization.
- Check whether deprecated APIs expose more fields.
- Compare gateway route inventory with documented endpoints.

## API10 - Unsafe Consumption Of APIs

Risk signals:
- Integration with third-party or internal service, callback, webhook, data sync,
  fraud scoring, KYC, payment gateway, or document provider.

Test ideas:
- Validate trust boundary and data validation on received responses.
- Check timeout, retry, signature verification, and schema validation.
- Ensure third-party data does not directly drive authorization or money movement.

## Vull-E Retrieval Keywords

OWASP API Top 10 2023, BOLA, BFLA, broken authentication, object property
authorization, resource consumption, sensitive business flow, SSRF,
misconfiguration, inventory management, unsafe API consumption

