# PortSwigger-Style Methodology - GraphQL Testing

Source reference:
- PortSwigger Web Security Academy: https://portswigger.net/web-security
- PortSwigger GraphQL API vulnerabilities topic: https://portswigger.net/web-security/graphql

Purpose:
Help Vull-E generate test plans for GraphQL APIs, especially object
authorization, field-level authorization, introspection, query complexity, and
mutation abuse.

## When Vull-E Should Retrieve This

Retrieve this when Jira or Confluence mentions:

- GraphQL
- query, mutation, resolver
- schema, introspection
- node, edge, connection
- nested fields
- variables
- mobile API
- field-level permissions

## GraphQL Risk Model

GraphQL concentrates many operations behind one endpoint. Authorization failures
can occur at:

- operation level
- resolver level
- object level
- field level
- nested relationship level
- mutation/action level

## Burp-Oriented Workflow

1. Capture GraphQL request.
2. Identify operation name, query, variables, and headers.
3. Identify object IDs in variables and query.
4. Compare queries across roles.
5. Test nested fields and sensitive fields.
6. Test mutations with lower-privileged roles.
7. Test query depth/complexity controls safely.

## Test Pattern: Object ID Manipulation

Method:

- change ID in variables
- change parent ID and child ID independently
- request same object through alternate query
- test node lookup if supported

Expected secure behavior:

- resolver enforces object-level authorization.

## Test Pattern: Field-Level Authorization

Use when sensitive fields exist:

- nationalId
- phone
- address
- balance
- document metadata
- risk score
- internal status
- audit fields

Method:

1. Capture allowed query.
2. Add sensitive fields.
3. Replay as lower role.
4. Compare field visibility and errors.

## Test Pattern: Mutation Authorization

Use for approve, reject, update, assign, export, create, delete, or state change.

Method:

1. Capture mutation as authorized role.
2. Replay with lower role.
3. Modify variables such as owner, branch, status, approval state.
4. Check state change.

## Test Pattern: Query Complexity And Batching

Safe checks:

- nested depth limit
- repeated aliases
- batch requests
- large pagination
- expensive filters

Automation guard:

- do not stress shared environments without approval.

## Evidence To Collect

- GraphQL operation
- variables
- role/token
- returned fields
- nested object leakage
- mutation side effect
- complexity/rate-limit behavior

## Vull-E Retrieval Keywords

PortSwigger GraphQL, query, mutation, resolver, introspection, field-level
authorization, node, edge, nested fields, variables, complexity, alias, batching

