# Internal Template - Role Matrix

Purpose:
Define which roles can access which objects, pages, APIs, and business actions.
This is one of the most important RAG sources for Vull-E.

Do not include real customer data, secrets, passwords, tokens, or production
credentials.

## Application / Domain

- Application name:
- Business domain:
- Environment:
- Owner team:
- Last updated:

## Roles

| Role | Description | Scope | Notes |
| --- | --- | --- | --- |
| Maker | Creates or uploads records | Branch / own assignments | Cannot approve own work |
| Checker | Approves or rejects records | Branch / assigned scope | Can view unmasked data only when required |
| Admin | Administrative operations | Global / restricted | Requires elevated controls |

## Scope Rules

Describe business scope boundaries:

- Branch scope:
- Region scope:
- Portfolio scope:
- Customer ownership:
- Tenant or legal entity boundary:

## Page Access

| Page / Screen | Maker | Checker | Admin | Notes |
| --- | --- | --- | --- | --- |
| Customer document list | Allowed / denied | Allowed / denied | Allowed / denied | Add masking and branch rules |
| Document approval page | Allowed / denied | Allowed / denied | Allowed / denied | Add workflow rules |

## API Access

| Endpoint | Method | Maker | Checker | Admin | Scope Rule |
| --- | --- | --- | --- | --- | --- |
| `/customers/{customerId}/documents/{documentId}` | GET |  |  |  |  |
| `/customers/{customerId}/documents/{documentId}/approve` | POST |  |  |  |  |

## State-Changing Actions

| Action | Allowed Roles | Approval Required | Audit Required | Notes |
| --- | --- | --- | --- | --- |
| upload document |  |  |  |  |
| approve document |  |  |  |  |
| reject document |  |  |  |  |
| export data |  |  |  |  |

## Vull-E Retrieval Keywords

role matrix, maker, checker, branch scope, region scope, admin, permission,
endpoint access, page access, approve, reject, export, scope rule

