# PortSwigger-Style Methodology - API Testing

Source reference:
- PortSwigger Web Security Academy: https://portswigger.net/web-security
- PortSwigger API testing topic: https://portswigger.net/web-security/api-testing

Purpose:
Help Vull-E generate practical tests for REST, JSON, mobile backend, GraphQL,
gateway, and service APIs.

## When Vull-E Should Retrieve This

Retrieve this when Jira or Confluence mentions:

- API, REST, GraphQL, mobile API, backend-for-frontend
- OpenAPI/Swagger
- endpoint, route, gateway
- JSON body, DTO, filter, search, export
- customerId, accountId, documentId, branchId, userId
- bulk operation, pagination, sorting, field expansion
- role-specific API behavior

## API Recon Questions

Before testing, identify:

- endpoints changed
- methods supported
- path/query/body/header parameters
- object identifiers
- authentication mechanism
- required roles
- state-changing actions
- response fields
- OpenAPI docs or schema
- legacy/mobile/internal route variants

## Test Pattern: Object-Level Authorization

Test every object identifier:

- path IDs
- query IDs
- JSON body IDs
- nested object IDs
- header IDs
- GraphQL variables
- arrays of IDs

Method:

1. Capture authorized request.
2. Change one ID at a time.
3. Test parent-child mismatch.
4. Test same role different scope.
5. Test lower role same object.

## Test Pattern: Function-Level Authorization

Privileged functions:

- approve
- reject
- cancel
- export
- role update
- limit update
- branch assignment
- manual override

Method:

1. Capture request with privileged role.
2. Replay with lower role.
3. Call hidden endpoint directly.
4. Try old API version if available.

## Test Pattern: Object Property Authorization

Use when request or response contains rich objects.

Test ideas:

- add forbidden fields to request body
- modify status, role, owner, branch, approval state
- request extra fields
- compare response fields across roles
- test nested object visibility

## Test Pattern: Bulk API Authorization

Use when request accepts arrays or filters.

Test ideas:

- authorized and unauthorized IDs mixed in one request
- large array size
- duplicate IDs
- hidden IDs
- object from another branch/tenant

Expected secure behavior:

- authorization applied per object
- unauthorized items fail safely
- no partial leakage unless explicitly designed and safe

## Test Pattern: API Inventory Gaps

Look for:

- legacy `/v1` routes
- mobile-only endpoints
- admin endpoints hidden from UI
- deprecated routes
- debug/test endpoints
- OpenAPI docs exposing unexpected paths

## Evidence To Collect

- endpoint and method
- role/token used
- object IDs tested
- request/response
- response field differences
- state change if any
- source rule from endpoint inventory or role matrix

## Automation Guidance

Good automation candidates:

- read-only object authorization
- response field comparison
- OpenAPI inventory diff
- route reachability checks

Require approval:

- bulk update
- approve/reject/cancel
- export/download sensitive data
- delete/update/create

## Vull-E Retrieval Keywords

PortSwigger API testing, REST, OpenAPI, Swagger, object authorization, function
authorization, BOLA, BFLA, mass assignment, bulk API, JSON body, DTO, endpoint
inventory, mobile API

