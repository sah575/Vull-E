# MITRE CWE - Access Control And Authorization Mapping

Source reference:
- MITRE CWE: https://cwe.mitre.org/

Use this document when Vull-E detects roles, permissions, object identifiers,
maker-checker flows, branch scope, admin operations, approval actions, or
authorization-sensitive APIs.

## Purpose

CWE helps classify the underlying software weakness. Vull-E should use CWE
mapping to make reports more standard, but CWE mapping alone does not prove a
vulnerability.

## Common CWE Mappings

### CWE-862 - Missing Authorization

Use when an endpoint or function appears to require authorization but the ticket
does not describe any server-side authorization check.

Jira signals:
- new endpoint
- direct object access
- approve/reject/cancel/export action
- admin or privileged workflow
- "UI only" role restriction

Test direction:
- Call the endpoint with authenticated but unauthorized role.
- Call the endpoint directly without using the UI.
- Verify server-side denial independent of frontend visibility.

### CWE-863 - Incorrect Authorization

Use when authorization exists but may be applied incorrectly.

Jira signals:
- branch-scoped access
- regional/global access
- owner-based access
- maker-checker restrictions
- parent-child object relationships

Test direction:
- Use same role with object outside scope.
- Use valid customerId with unrelated documentId.
- Try maker user on checker-only action.
- Try checker outside assigned branch.

### CWE-639 - Authorization Bypass Through User-Controlled Key

Use for IDOR/BOLA-style risks where object IDs are user-controlled.

Jira signals:
- `customerId`
- `accountId`
- `documentId`
- `transactionId`
- `caseId`
- IDs in path, query, JSON body, GraphQL variables, or hidden form fields

Test direction:
- Replace object ID with another user's object.
- Test list, detail, export, and action endpoints.
- Check whether unauthorized response leaks existence or partial data.

### CWE-285 - Improper Authorization

Use as a broader category when the exact authorization flaw is not yet clear.

Good for early hypothesis output:
- role confusion
- missing permission boundary
- ambiguous business scope
- unclear server-side enforcement

## Evidence Expectations

For access-control findings, evidence should include:

- user role and business scope
- original authorized request
- modified unauthorized request
- object ID or function changed
- response difference
- expected business rule
- side effect if any
- audit log behavior

## False Positive Controls

- Do not report only because an ID exists in the URL.
- Do not report only because OWASP/CWE context was retrieved.
- Confirm that authorization should be denied by Jira, Confluence, internal role
  matrix, or manual business confirmation.
- For `200 OK`, inspect actual data and side effects.

## Vull-E Retrieval Keywords

CWE-862, CWE-863, CWE-639, CWE-285, missing authorization, incorrect
authorization, IDOR, BOLA, user-controlled key, branch scope, role bypass,
maker checker, object authorization

