# OWASP API Security - Rate Limit And Resource Consumption Notes

Source reference:
- OWASP API Security Top 10 2023: https://owasp.org/API-Security/editions/2023/en/0x00-header/

Use this document when Jira or Confluence mentions search, export, upload,
report, PDF generation, bulk operation, async job, retry, notification,
password reset, OTP, login, expensive filter, or third-party API calls.

## Risk Signals

- User can control page size, date range, filter complexity, file size, batch
  size, or report scope.
- Flow sends OTP, SMS, email, push notification, or external API request.
- Operation starts background jobs or creates downloadable files.
- Endpoint can be called repeatedly without clear throttling.

## Security Expectations

- Apply rate limits per user, IP, device, session, customer, and business action
  where appropriate.
- Limit file size, item count, page size, date range, recursion, and query depth.
- Use quotas for expensive operations.
- Protect OTP, login, password reset, and notification endpoints from abuse.
- Ensure retries and async jobs are idempotent where needed.

## Test Ideas

- Increase page size, export range, file size, and bulk item count.
- Repeat OTP, email, SMS, report, or export requests.
- Submit parallel requests for the same business action.
- Test if rate limit differs between web, mobile, and direct API.
- Check whether blocked requests are logged and whether response reveals limit
  internals.

## Evidence

- Request volume and parameters.
- Rate-limit response behavior.
- Business impact such as duplicate notifications or heavy reports.
- Logs and monitoring behavior.

## Automation Guard

Resource consumption tests can affect shared environments. Use low-volume
threshold tests first and require explicit approval for stress-like behavior.

## Vull-E Retrieval Keywords

rate limit, resource consumption, quota, page size, export, report, bulk,
parallel request, OTP, SMS, email, notification, async job, idempotency, retry

