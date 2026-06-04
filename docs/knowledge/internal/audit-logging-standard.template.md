# Internal Template - Audit Logging Standard

Purpose:
Define which security and business events must be logged, which fields must be
included, and which data must be redacted.

## Required Audit Events

| Event | Required | Notes |
| --- | --- | --- |
| Login success/failure |  |  |
| Authorization denied |  |  |
| Sensitive data view |  |  |
| Document download/preview |  |  |
| Approval |  |  |
| Rejection |  |  |
| Export/report generation |  |  |
| Role/permission change |  |  |
| Limit/threshold change |  |  |

## Required Audit Fields

| Field | Required | Notes |
| --- | --- | --- |
| actorUserId |  |  |
| actorRole |  |  |
| action |  |  |
| result |  | success/denied/failed |
| customerId |  | if applicable |
| objectId |  | if applicable |
| branchId |  | if applicable |
| timestamp |  |  |
| correlationId |  |  |
| sourceChannel |  | web/mobile/API |

## Redaction Rules

Never log:

- password
- OTP
- access token
- refresh token
- full card number
- CVV
- unnecessary PII
- raw request body if it contains sensitive data

## Test Ideas

- Trigger successful approve/reject and verify audit event.
- Trigger denied authorization and verify safe audit event.
- Trigger validation error and verify sensitive data is not logged.
- Verify correlation ID links request and audit event.

## Vull-E Retrieval Keywords

audit logging, authorization denied, approval audit, reject audit, sensitive
data access, log redaction, correlationId, actorRole, customerId, objectId,
branchId

