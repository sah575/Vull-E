# OWASP ASVS/WSTG - Input Validation And Injection Notes

Source references:
- OWASP ASVS: https://owasp.org/www-project-application-security-verification-standard/
- OWASP WSTG: https://owasp.org/www-project-web-security-testing-guide/

Use this document when Jira or Confluence mentions search, filters, reports,
exports, imports, templates, dynamic rules, formulas, SQL, NoSQL, LDAP, command
execution, file paths, redirects, webhooks, callbacks, or user-supplied URLs.

## Risk Signals

- New search or advanced filter functionality.
- Report builder, export, dashboard, or data grid changes.
- Upload/import flows for CSV, Excel, XML, JSON, or PDF metadata.
- Dynamic query construction or free-text criteria.
- Webhook, callback URL, external integration, or URL fetch behavior.
- Template rendering, notification templates, document generation, or formulas.

## Security Expectations

- Use allowlist validation for structured fields such as status, type, channel,
  sort order, currency, country, branch, and role.
- Use parameterized queries or safe query builders.
- Validate both client-side and server-side, with server-side as authoritative.
- Encode output according to context: HTML, JavaScript, URL, JSON, CSV, XML.
- Do not pass user input to shell commands, file paths, interpreters, or dynamic
  expression engines without strict controls.
- Normalize and validate URLs before outbound requests.

## Test Ideas

- Try unexpected data types: arrays instead of strings, objects instead of IDs,
  very large numbers, negative values, null, empty string, duplicate keys.
- Test sort/filter parameters for unauthorized fields and query manipulation.
- Check report/export endpoints for formula injection and excessive data.
- Test import parsers with malformed rows, duplicate IDs, hidden columns, and
  unauthorized object IDs.
- For redirect/callback/webhook URLs, test scheme, host allowlist, localhost,
  metadata IP ranges, DNS rebinding-style hostnames, and encoded variants.
- Check whether error messages expose SQL, stack traces, table names, or service
  internals.

## Evidence

- Input parameter and expected accepted format.
- Modified input and response/error behavior.
- Whether data was changed, exported, fetched, or rendered unsafely.
- Any server-side logs or error traces.

## Vull-E Retrieval Keywords

input validation, injection, SQL, NoSQL, LDAP, command injection, template
injection, SSRF, redirect, webhook, callback, report, export, import, filter,
sort, search, parser, CSV, Excel

