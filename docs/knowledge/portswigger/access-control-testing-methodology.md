# PortSwigger-Style Methodology - Access Control Testing

Source reference:
- PortSwigger Web Security Academy: https://portswigger.net/web-security
- PortSwigger Access Control topic: https://portswigger.net/web-security/access-control

Purpose:
Help Vull-E turn Jira and Confluence access-control signals into practical,
Burp-friendly test plans. This document summarizes testing methodology and does
not copy lab solutions.

## When Vull-E Should Retrieve This

Retrieve this when the ticket mentions:

- roles, permissions, entitlements, authorization, access matrix
- maker, checker, approver, reviewer, admin, branch user, regional user
- customerId, accountId, documentId, cardId, transactionId, caseId
- approve, reject, submit, cancel, export, download, upload
- "only assigned users", "same branch", "own customer", "admin only"
- hidden UI buttons, protected pages, direct URLs, or new backend endpoints

## Core Testing Model

Access-control testing usually requires at least two identities:

1. A user who is authorized for the object/action.
2. A user who is authenticated but not authorized for the same object/action.

If possible, prepare:

- same-role different-scope users
- lower-privileged users
- maker/checker pair
- cross-branch users
- admin and non-admin users

The core method is request comparison:

```text
authorized request
        |
        v
change role, token, object ID, path, method, or workflow state
        |
        v
compare response, data, and side effects
```

## Burp-Oriented Workflow

1. Log in as an authorized user.
2. Browse the relevant UI flow.
3. Capture requests in Burp Proxy or HTTP history.
4. Send interesting requests to Repeater.
5. Repeat the flow with another role.
6. Compare requests and identify role/object identifiers.
7. Replay authorized request with unauthorized token.
8. Replay unauthorized request with modified object ID.
9. Check status code, response body, sensitive fields, redirects, and state.
10. Record audit/logging behavior if visible.

## Test Pattern: Vertical Privilege Bypass

Use when a lower role may access higher role functionality.

Examples:

- maker attempts checker approval
- branch user attempts admin endpoint
- viewer attempts update/export/delete
- non-privileged user calls hidden privileged route

Test steps:

1. Capture privileged request with authorized role.
2. Replace session/token with lower-privileged role.
3. Keep request body and object IDs unchanged.
4. Replay the request.
5. Verify whether the action is denied server-side.

Expected secure behavior:

- `403`, safe redirect, or equivalent denial.
- No state change.
- No sensitive data in response.
- Denied attempt is audit logged if policy requires it.

## Test Pattern: Horizontal Privilege Bypass

Use when same role users should access only their own objects.

Examples:

- branch A checker accesses branch B customer document
- user A accesses user B profile or case
- customer service user accesses unassigned customer

Test steps:

1. Capture User A request for User A object.
2. Replace object ID with User B object ID.
3. Keep User A token/session.
4. Replay request.
5. Check response fields and side effects.

Expected secure behavior:

- object access denied
- no existence leak where possible
- no partial sensitive data exposure
- no state transition

## Test Pattern: Multi-Identifier Relationship Bypass

Use when request contains parent and child IDs.

Example:

```text
GET /customers/{customerId}/documents/{documentId}
```

Test steps:

1. Use valid `customerId` and valid `documentId`.
2. Change only `documentId` to another customer's document.
3. Change only `customerId` to another customer.
4. Try mismatched parent-child combinations.
5. Verify the backend checks relationship and authorization.

Expected secure behavior:

- document must belong to customer
- user must be authorized for customer
- action must be authorized for document state

## Test Pattern: Forced Browsing

Use when UI hides functionality but endpoint may still be reachable.

Test steps:

1. Identify hidden or privileged page/API route.
2. Request it directly with lower role.
3. Try direct URL navigation.
4. Try captured API request replay.
5. Check whether frontend-only protection exists.

Expected secure behavior:

- backend enforces authorization independently of UI.

## Test Pattern: Method And Route Confusion

Use when the same resource supports multiple methods/routes.

Test ideas:

- `GET` allowed but `POST` should be denied.
- `/admin/users` protected but `/api/admin/users` exposed.
- old version route has weaker control.
- mobile route differs from web route.
- export route differs from detail route.

## Evidence To Collect

- authorized role and unauthorized role
- object IDs changed
- original request/response
- modified request/response
- expected business rule
- state before and after
- audit event if available
- RAG/internal source used for expected behavior

## False Positive Checks

- `200 OK` alone is not enough; check actual data and side effects.
- `403` alone is not enough if response body leaks data.
- Empty lists may still leak totals, facets, metadata, or object existence.
- Masked data may still be sensitive if identifiers or relationships leak.
- Confirm the business rule before reporting.

## Automation Guidance

Good automation candidates:

- read-only detail requests
- list filtering tests
- response field comparison
- route reachability checks

Require approval:

- approve/reject/cancel/submit
- export/download sensitive data
- delete/update/create
- workflow state changes

## Vull-E Retrieval Keywords

PortSwigger access control, Burp Repeater, vertical privilege, horizontal
privilege, forced browsing, IDOR, object ID, role token, maker checker, branch
scope, authorization replay, multi-identifier relationship

