# OWASP ASVS - Access Control Notes

Source reference:
- OWASP ASVS: https://owasp.org/www-project-application-security-verification-standard/

Use this document when Jira or Confluence mentions roles, permissions, makers,
checkers, branch scope, customer ownership, account ownership, approval flows,
admin screens, or object identifiers.

## Risk Signals

- URL, request body, or GraphQL variables contain direct object identifiers.
- The ticket mentions role-specific behavior.
- The workflow has approval, rejection, maker-checker, or delegation.
- The same page behaves differently for branch, region, admin, maker, checker,
  customer service, or operations users.
- Access rules are described in business language but not in technical
  endpoint-level controls.

## Security Expectations

- Authorization must be enforced on the server side for every request.
- UI hiding is not an access-control mechanism.
- Object ownership and business scope must be checked for read and write
  operations.
- Privilege changes must not be accepted from client-controlled fields.
- Denied requests should fail safely and should not leak object existence or
  sensitive fields.
- Authorization checks should happen close to the protected resource or service
  boundary, not only at the gateway or frontend.
- Collection endpoints must filter results by the user's allowed scope.
- Export, report, search, and autocomplete endpoints require the same
  authorization rules as detail pages.

## Test Ideas

- Replay the same request with a lower-privileged role.
- Replace customerId, accountId, documentId, transactionId, or branchId with an
  object outside the user's scope.
- Try workflow actions out of order, such as approve before upload completion.
- Verify maker users cannot approve their own or anyone else's submitted item.
- Verify checker users cannot approve items outside their branch or assigned
  scope.
- Confirm unauthorized responses are consistent and do not disclose whether the
  object exists.
- Test list endpoints by changing filters such as branchId, customerType,
  status, ownerUserId, page size, sort, and date range.
- Compare API behavior between UI navigation and direct request replay.
- Check whether cached responses, exports, or async jobs bypass authorization.

## Jira And Confluence Triggers

If a ticket contains these terms, Vull-E should consider access-control risk:

- maker, checker, approver, reviewer, admin, operator, branch, region
- assign, delegate, approve, reject, submit, cancel, override, manual update
- customerId, accountId, documentId, cardId, transactionId, caseId
- page visible only to, role matrix, permission, entitlement, scope

## Evidence Expectations

- User/role used for original authorized request.
- User/role used for unauthorized replay.
- Exact object identifier changed.
- Response status, response body difference, and side effect.
- Business rule that proves the access should be denied.
- Audit log behavior for denied and successful attempts.

## False Positive Checks

- A `200 OK` response is not enough; verify whether sensitive data or side
  effects are actually exposed.
- A `403` is not enough if response body still contains sensitive fields.
- An empty list may still be vulnerable if total counts, facets, exports, or
  pagination metadata leak unauthorized records.
- Masked data may still be sensitive if identifiers, addresses, names, or
  relationship metadata are exposed.

## Vull-E Retrieval Keywords

access control, authorization, permission, role, maker, checker, branch,
customerId, accountId, documentId, object id, IDOR, approval, reject, admin,
scope, ownership
