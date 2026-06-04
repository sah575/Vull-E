# OWASP Cheat Sheet - SSRF And External Integration Notes

Source reference:
- OWASP SSRF Prevention Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html

Use this document when Jira or Confluence mentions URL fetching, webhook,
callback, redirect, image URL, document URL, import from URL, partner API,
notification endpoint, HTTP client, proxy, metadata, or external integration.

## Risk Signals

- User or partner can submit a URL.
- Backend fetches files, images, documents, callbacks, or webhooks.
- System integrates with internal services or third-party APIs.
- New allowlist, proxy, gateway, or outbound network rule is introduced.
- Redirect following or DNS resolution behavior is not specified.

## Security Expectations

- Use strict allowlists for schemes, hosts, and ports.
- Block localhost, link-local, private networks, metadata services, and internal
  service ranges unless explicitly required.
- Resolve and validate DNS carefully.
- Re-validate after redirects.
- Limit response size, timeout, redirects, and content types.
- Do not expose fetched response details to unauthorized users.

## Test Ideas

- Try unsupported schemes such as file, gopher, ftp, or data if parser accepts
  arbitrary URLs.
- Try localhost, private IPs, IPv6 localhost, link-local, and encoded variants.
- Try domain names that resolve to blocked ranges.
- Try redirects from allowed domain to blocked destination.
- Test large response, slow response, and unexpected content type.
- Check whether errors expose internal network details.

## Evidence

- Submitted URL and normalized backend interpretation.
- Outbound request behavior if observable.
- Response or error returned to user.
- Network deny/allow decision.
- Logs showing safe rejection without leaking sensitive internals.

## Automation Guard

SSRF testing can touch internal infrastructure. Automated SSRF tests must be
limited to approved canary endpoints and must not probe arbitrary internal IP
ranges.

## Vull-E Retrieval Keywords

SSRF, webhook, callback, redirect, URL fetch, image URL, document URL, metadata,
localhost, private IP, DNS, redirect, external integration, partner API

