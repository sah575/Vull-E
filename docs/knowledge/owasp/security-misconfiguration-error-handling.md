# OWASP ASVS/WSTG - Security Misconfiguration And Error Handling

Source references:
- OWASP ASVS: https://owasp.org/www-project-application-security-verification-standard/
- OWASP WSTG: https://owasp.org/www-project-web-security-testing-guide/

Use this document when Jira or Confluence mentions deployment, gateway route,
environment variable, CORS, headers, debug, OpenAPI docs, admin endpoint,
feature flag, error response, logging, or infrastructure change.

## Risk Signals

- New route is exposed through API gateway.
- CORS, CSP, security headers, or proxy behavior changes.
- Swagger/OpenAPI, actuator, metrics, health, admin, or debug endpoints are
  introduced.
- Error handling or exception mapping changes.
- Feature flag exposes hidden functionality.

## Security Expectations

- Production-like environments should not expose debug details.
- Error responses should not leak stack traces, SQL, internal hostnames,
  service names, tokens, or customer data.
- CORS must not allow arbitrary origins with credentials.
- Security headers should be reviewed for browser-facing pages.
- Admin and operational endpoints require strong authentication and
  authorization.
- OpenAPI documentation exposure should be intentional and scoped.

## Test Ideas

- Trigger validation and authorization errors and inspect response details.
- Check CORS behavior with arbitrary origin and credentials.
- Check whether internal endpoints are reachable through gateway routes.
- Check security headers on new pages.
- Review Swagger/OpenAPI exposure and whether hidden endpoints are documented.
- Check if feature flags can be toggled client-side.

## Evidence

- Request that triggers error or route exposure.
- Response headers and body.
- Environment or deployment note that explains expected exposure.
- Any leaked internal detail.

## Vull-E Retrieval Keywords

security misconfiguration, error handling, CORS, headers, CSP, debug, stack
trace, OpenAPI, Swagger, actuator, admin endpoint, health, metrics, feature flag,
gateway route

