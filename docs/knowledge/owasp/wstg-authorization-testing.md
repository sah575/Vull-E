# OWASP WSTG - Authorization Testing Notes

Source reference:
- OWASP WSTG: https://owasp.org/www-project-web-security-testing-guide/

Use this document to convert an authorization risk hypothesis into concrete
manual or Burp replay tests.

## Test Planning Pattern

1. Identify roles and business scopes.
2. Capture a valid request for each relevant role.
3. Identify object identifiers and action parameters.
4. Replay the request with a different role.
5. Replay the request with a different object identifier.
6. Compare status code, response body, sensitive fields, and side effects.
7. Verify expected audit events.

## Evidence To Collect

- Original request and authorized role.
- Modified request and changed identifier or token.
- Response difference.
- Business impact.
- Whether state changed.
- Whether audit logging captured the denied attempt.

## Common Authorization Test Cases

- Horizontal privilege bypass: same role, different user's object.
- Vertical privilege bypass: lower role executes higher role action.
- Business-scope bypass: same role, different branch/region/portfolio.
- Forced browsing: direct access to hidden routes.
- Workflow bypass: action executed before prerequisite step.

## Safe Automation Notes

Read-only authorization checks are better automation candidates. State-changing
operations such as approve, reject, transfer, delete, update, or submit should
require explicit approval unless a safe test environment and reversible test
data are guaranteed.

## Vull-E Retrieval Keywords

authorization testing, horizontal privilege, vertical privilege, forced browsing,
workflow bypass, Burp replay, role token, object id, branch scope

