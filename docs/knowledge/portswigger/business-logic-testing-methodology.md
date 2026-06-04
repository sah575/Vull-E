# PortSwigger-Style Methodology - Business Logic Testing

Source reference:
- PortSwigger Web Security Academy: https://portswigger.net/web-security
- PortSwigger Business logic vulnerabilities topic: https://portswigger.net/web-security/logic-flaws

Purpose:
Help Vull-E produce business-logic test ideas for multi-step workflows, approval
flows, limits, state transitions, and banking-specific abuse cases.

## When Vull-E Should Retrieve This

Retrieve this when the ticket mentions:

- workflow, process, state, status
- maker-checker, approval, reject, submit, activate
- payment, transfer, refund, reversal, cancellation
- limit, fee, threshold, eligibility
- retry, duplicate, idempotency
- manual override, exception, escalation
- background job or async callback

## Business Logic Testing Mindset

Business logic flaws often exist even when input validation and authentication
are correct. The key question is:

> Can a valid user perform a valid action in an invalid context?

Examples:

- maker approves own record
- checker approves outside branch
- rejected item is approved through direct API replay
- cancelled transaction is reused
- limit is changed client-side
- duplicate approval occurs through parallel requests

## Test Pattern: Step Skipping

Use when flow has ordered states.

Method:

1. Identify normal sequence.
2. Capture each state-changing request.
3. Attempt later step before prerequisite step.
4. Attempt action after cancellation/rejection.
5. Verify server-side state transition validation.

## Test Pattern: Parameter-Controlled State

Use when request body includes status, action, approvalState, owner, branch,
amount, limit, or fee.

Method:

1. Send normal request.
2. Add or modify state fields.
3. Observe stored state and response.
4. Verify server ignores or rejects client-controlled business fields.

## Test Pattern: Self-Approval

Use for maker-checker/four-eyes flows.

Method:

1. Create record as maker.
2. Attempt approval with same user/session.
3. Attempt approval through alternate channel or direct API.
4. Attempt to change initiator/owner fields.

Expected secure behavior:

- self-approval denied unless business policy explicitly allows it.

## Test Pattern: Replay And Idempotency

Use for money movement, approval, notifications, exports, and async jobs.

Method:

1. Capture state-changing request.
2. Replay same request.
3. Send parallel requests.
4. Retry with stale token/idempotency key.
5. Check duplicate state changes, events, or notifications.

## Test Pattern: Boundary Abuse

Use when ticket mentions limits, thresholds, fees, eligibility, or scoring.

Test ideas:

- amount just below/above threshold
- negative values
- zero values
- currency mismatch
- date boundary
- branch/region threshold differences
- client-controlled fee/limit fields

## Evidence To Collect

- normal business rule
- state before test
- request sequence
- modified request
- state after test
- audit events
- whether action was reversible

## Automation Guidance

Business logic tests are high risk because they often change state.

Automate only when:

- isolated test data exists
- rollback is safe
- state-changing policy approval exists
- environment owner approves

## Vull-E Retrieval Keywords

PortSwigger business logic, workflow bypass, step skipping, state transition,
maker checker, self-approval, replay, idempotency, duplicate action, limit,
threshold, fee, cancellation, refund, reversal

