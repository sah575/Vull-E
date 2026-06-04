# Internal Template - Endpoint Inventory

Purpose:
Document APIs, object identifiers, authorization requirements, data
classification, and automation safety. Vull-E uses this to produce precise test
plans instead of generic recommendations.

Do not include production secrets, real tokens, or real customer identifiers.

## Application / Service

- Service name:
- Base path:
- Owner team:
- Auth mechanism:
- Gateway:
- Last updated:

## Endpoint Table

| Endpoint | Method | Description | Object IDs | Required Role | Scope Rule | State-Changing | Safe To Automate |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `/customers/{customerId}/documents/{documentId}` | GET | Document detail | customerId, documentId |  |  | No | Yes |
| `/customers/{customerId}/documents/{documentId}/approve` | POST | Approve document | customerId, documentId |  |  | Yes | No |

## Object Relationship Rules

Document object relationship rules:

- `documentId` must belong to `customerId`.
- `customerId` must be inside the user's business scope.
- Branch-scoped users must not access other branches.

Add application-specific relationship rules here.

## Sensitive Response Fields

| Field | Classification | Masking Rule | Allowed Roles |
| --- | --- | --- | --- |
| nationalId | PII | Mask for maker | checker, admin |
| phoneNumber | PII | Mask by default | checker if needed |

## Test Data Requirements

Define safe test data:

- test customer in same branch:
- test customer in different branch:
- maker test user:
- checker test user:
- admin test user:
- reversible state-changing records:

## Vull-E Retrieval Keywords

endpoint inventory, API, object IDs, required role, scope rule, state-changing,
safe to automate, customerId, documentId, masking, test data

