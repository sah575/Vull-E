# OWASP API Security - Object And Function Authorization

Source reference:
- OWASP API Security Project: https://owasp.org/www-project-api-security/

Use this document when a Jira ticket introduces or changes REST, GraphQL,
mobile, gateway, or service-to-service APIs that accept object identifiers or
perform privileged functions.

## Core Risk

APIs often expose direct object identifiers and business actions. The main risk
is that the API validates authentication but fails to verify whether the
authenticated principal can access the specific object or execute the specific
function.

## High-Risk API Shapes

- `GET /customers/{customerId}`
- `GET /accounts/{accountId}/transactions`
- `GET /customers/{customerId}/documents/{documentId}`
- `POST /cases/{caseId}/approve`
- `POST /payments/{paymentId}/cancel`
- `POST /users/{userId}/roles`
- GraphQL queries with `id`, `node`, `edges`, `filter`, or `includeInactive`
- Bulk APIs that accept arrays of IDs.

## Object-Level Authorization Checks

For every object ID in path, query, body, headers, GraphQL variables, or nested
JSON arrays, verify:

- The object exists.
- The object belongs to the expected parent object.
- The requesting user has permission for that object.
- The user's business scope includes the object.
- The object state allows the requested operation.

Example: if request path includes both `customerId` and `documentId`, the server
must verify that the document belongs to that customer and that the current user
can access that customer's documents.

## Function-Level Authorization Checks

Privileged functions must not rely on frontend menus or hidden buttons. Verify
server-side permission for:

- approve, reject, submit, cancel, reverse, refund
- role update, limit update, branch assignment
- export, bulk download, report generation
- manual override and exception handling

## API Test Ideas

- Change only the object ID and keep the same token.
- Keep object ID unchanged and replay with lower-privileged token.
- Change parent and child IDs independently to test relationship validation.
- Submit a bulk request containing one unauthorized object among authorized
  objects.
- Try direct API calls to actions hidden in the UI.
- Test GraphQL introspection, nested fields, and object expansion if enabled.
- Increase pagination limit or request additional fields to identify excessive
  data exposure.

## Evidence

- Original API request and token role.
- Modified object/function request.
- Expected business rule.
- Response difference and leaked fields.
- Whether the action changed state.
- Whether the denial or bypass was logged.

## Automation Guidance

Read-only object access checks can often be automated. State-changing functions
should require explicit approval unless isolated test data exists and rollback
is safe.

## Vull-E Retrieval Keywords

BOLA, BFLA, API authorization, object authorization, function authorization,
customerId, accountId, documentId, GraphQL, bulk API, excessive data exposure,
mass assignment, nested object

