# MITRE CAPEC - Parameter Tampering And Workflow Abuse

Source reference:
- MITRE CAPEC: https://capec.mitre.org/

Use this document when Jira or Confluence mentions workflow states, status
fields, approval actions, limits, fees, amounts, ownership, branch assignment,
manual override, retry, or cancellation.

## Pattern: Parameter Tampering

Risk signals:
- Request body contains status, role, branchId, ownerUserId, amount, limit,
  fee, approvalState, customerType, riskScore, or permission.

Test pattern:
- Modify fields that should be server-controlled.
- Add hidden or read-only fields to request body.
- Change nested object IDs or parent IDs.
- Compare stored state after request.

## Pattern: State Machine Bypass

Risk signals:
- Multi-step business flow.
- Ticket mentions upload, submit, approve, reject, activate, cancel, close, or
  reverse.

Test pattern:
- Execute steps out of order.
- Repeat completed actions.
- Use stale record IDs.
- Approve rejected or cancelled item.
- Submit without prerequisite step.

## Pattern: Self-Approval

Risk signals:
- Maker-checker, four-eyes, dual control, supervisor approval.

Test pattern:
- User initiates a record and then attempts approval.
- Same person acts through different channel/session.
- User changes owner/initiator fields before approval.

## Pattern: Replay And Duplicate Action

Risk signals:
- Approve, transfer, payment, notification, export, report generation, or async
  job.

Test pattern:
- Repeat the same request.
- Send parallel requests.
- Retry with stale idempotency token.
- Check duplicate state changes and duplicate notifications.

## Evidence

- initial state
- modified request
- final state
- expected workflow rule
- audit/event sequence

## Vull-E Retrieval Keywords

CAPEC parameter tampering, workflow bypass, state machine, maker checker,
self-approval, approvalState, status, branchId, ownerUserId, replay, duplicate,
idempotency

