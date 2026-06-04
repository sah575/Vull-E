# OWASP API Security Notes

Source reference:
- OWASP API Security Project: https://owasp.org/www-project-api-security/

Use this document when Jira or Confluence mentions REST APIs, GraphQL, mobile
backend APIs, service-to-service APIs, gateway routes, object IDs, filtering,
sorting, bulk operations, or API authorization.

## Risk Signals

- Endpoint path contains customerId, accountId, documentId, cardId, branchId,
  transactionId, or similar identifiers.
- Request body contains role, permission, userId, branchId, status, amount,
  limit, or approval state.
- API supports bulk actions, filtering, export, import, or search.
- API returns nested customer, account, card, document, or transaction objects.

## Security Expectations

- APIs must enforce object-level authorization and function-level authorization.
- Client-provided identity, role, branch, or permission fields must not drive
  authorization decisions.
- Response objects should not expose excessive fields.
- Bulk APIs must apply authorization to every object in the collection.
- Rate limits and abuse controls should exist for sensitive or high-volume APIs.

## Test Ideas

- Replace path identifiers with another user's object.
- Replay privileged API actions using a lower-privileged token.
- Request extra fields, expanded objects, or larger page sizes.
- Test bulk requests containing a mix of authorized and unauthorized object IDs.
- Check whether hidden mobile/API endpoints enforce the same rules as the web UI.

## Vull-E Retrieval Keywords

API security, BOLA, object level authorization, function level authorization,
excessive data exposure, mass assignment, bulk API, GraphQL, REST, mobile API,
rate limit

