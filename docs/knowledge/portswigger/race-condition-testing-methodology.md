# PortSwigger-Style Methodology - Race Condition Testing

Source reference:
- PortSwigger Web Security Academy: https://portswigger.net/web-security
- PortSwigger Race conditions topic: https://portswigger.net/web-security/race-conditions

Purpose:
Help Vull-E identify where concurrency and timing issues may affect business
logic, approvals, payments, duplicate actions, limits, or one-time operations.

## When Vull-E Should Retrieve This

Retrieve this when Jira or Confluence mentions:

- approve, reject, submit, cancel
- payment, transfer, refund, reversal
- coupon, campaign, discount, fee, limit
- OTP, token, password reset
- idempotency, retry, duplicate
- background job, async worker, queue
- inventory, balance, quota

## Race Condition Risk Model

Race conditions occur when two or more requests interact with shared state before
the system commits the correct decision.

Risky operations:

- one-time use token
- approval/rejection
- balance/limit update
- discount/campaign redemption
- file processing state
- duplicate payment/notification
- account activation

## Test Planning Questions

- What state changes?
- Is the action supposed to be one-time?
- Is there an idempotency key?
- Is the backend transaction atomic?
- What happens with parallel requests?
- Are duplicate events/audit logs created?

## Test Pattern: Duplicate State Change

Method:

1. Prepare isolated test record.
2. Capture state-changing request.
3. Send closely timed duplicate requests.
4. Check final state, event count, and audit logs.

Expected secure behavior:

- only one state transition succeeds.
- duplicates are rejected or idempotent.

## Test Pattern: Limit Or Quota Race

Use for limits, balances, quotas, campaigns, or exports.

Method:

1. Identify remaining quota/limit.
2. Send parallel requests near boundary.
3. Verify aggregate effect does not exceed allowed limit.

## Test Pattern: Token Reuse Race

Use for OTP, password reset, invitation, approval token, or one-time link.

Method:

1. Capture one-time token flow.
2. Attempt parallel use.
3. Verify token is consumed exactly once.

## Evidence To Collect

- initial state
- request set
- timing/parallelism description
- final state
- duplicate side effects
- audit events

## Automation Guidance

Race tests are high risk. They should require:

- isolated data
- explicit approval
- low volume
- no shared production-like records
- rollback or cleanup plan

## Vull-E Retrieval Keywords

PortSwigger race condition, parallel request, duplicate action, idempotency,
one-time token, approval race, payment race, quota, limit, retry, async job

