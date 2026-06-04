# OWASP Top 10 - Insecure Design And Business Logic Notes

Source reference:
- OWASP Top 10: https://owasp.org/Top10/2021/

Use this document when Jira or Confluence describes a new business workflow,
approval chain, limit, fee, transaction, exception path, manual operation,
state machine, or multi-step process.

## Risk Signals

- Multi-step workflow with upload, submit, approve, reject, activate, or close.
- Maker-checker, four-eyes, dual control, or supervisor approval.
- Limits, thresholds, fees, campaigns, discounts, eligibility, or scoring.
- Manual override, exception handling, retry, cancellation, reversal, or refund.
- Background jobs, queues, async callbacks, or scheduled processing.

## Security Expectations

- Business state transitions must be validated server-side.
- Users must not skip mandatory workflow steps.
- Approvers must not approve their own initiated changes unless explicitly
  allowed by policy.
- Limits and thresholds must be recalculated server-side.
- Idempotency and replay handling should prevent duplicate state changes.
- Race conditions should not allow duplicate approval or inconsistent state.
- Audit logs should capture critical business decisions.

## Test Ideas

- Execute steps out of order.
- Repeat the same approval/reject/submit request.
- Use stale IDs after cancellation or rejection.
- Modify status, amount, branch, owner, or approval state in the request body.
- Try parallel requests for the same workflow action.
- Attempt self-approval with maker credentials.
- Change limit or amount around threshold boundaries.
- Test whether a rejected item can be approved through direct API replay.

## Evidence

- Expected business rule.
- Sequence of requests.
- State before and after each request.
- Whether duplicate or unauthorized state transition occurred.
- Audit trail and event ordering.

## Automation Guidance

Business-logic tests are often risky because they change state. Automate only
when isolated test data exists, side effects are reversible, and the policy
guard allows the method and endpoint.

## Vull-E Retrieval Keywords

business logic, insecure design, workflow, maker checker, approval, reject,
submit, activate, cancel, refund, reverse, limit, threshold, duplicate, replay,
race condition, state transition, self approval

