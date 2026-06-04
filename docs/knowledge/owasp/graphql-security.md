# OWASP Cheat Sheet - GraphQL Security Notes

Source reference:
- OWASP GraphQL Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html

Use this document when Jira or Confluence mentions GraphQL, schema, query,
mutation, resolver, node, edge, introspection, nested fields, or mobile API
query changes.

## Risk Signals

- New query or mutation is added.
- Resolver accepts IDs or filter objects.
- Nested objects expose customer/account/document/transaction data.
- Introspection or schema exposure is enabled.
- Query depth, complexity, or batching controls are not described.

## Security Expectations

- Authorization must be enforced in resolvers for every object and nested field.
- Field-level authorization is required for sensitive data.
- Mutations must enforce function-level authorization.
- Query complexity, depth, batching, and rate limits should be controlled.
- Introspection should be reviewed for environment and exposure risk.

## Test Ideas

- Query nested sensitive fields with lower-privileged role.
- Change IDs inside variables.
- Use aliases to repeat expensive or sensitive fields.
- Try deep nested queries and large pagination sizes.
- Check whether mutation accepts fields not visible in UI.
- Compare GraphQL behavior with REST endpoints for the same object.

## Evidence

- Query, variables, role, and expected access rule.
- Response fields and nested objects returned.
- Resolver side effects for mutations.
- Complexity/rate-limit behavior.

## Vull-E Retrieval Keywords

GraphQL, query, mutation, resolver, node, edge, introspection, nested fields,
field-level authorization, query complexity, batching, alias, depth limit

