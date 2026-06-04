# Internal Template - Business Flow Rules

Purpose:
Describe allowed workflow states and transitions so Vull-E can detect business
logic and workflow bypass risks.

## Flow Metadata

- Flow name:
- Application:
- Owner:
- Criticality:
- Last updated:

## Actors

| Actor / Role | Responsibilities | Restrictions |
| --- | --- | --- |
| Maker |  |  |
| Checker |  |  |
| Admin |  |  |

## Allowed States

| State | Description | Who Can Create | Who Can View |
| --- | --- | --- | --- |
| draft |  |  |  |
| submitted |  |  |  |
| approved |  |  |  |
| rejected |  |  |  |
| cancelled |  |  |  |

## Allowed Transitions

| From | To | Action | Allowed Role | Preconditions | Audit Required |
| --- | --- | --- | --- | --- | --- |
| draft | submitted | submit |  |  |  |
| submitted | approved | approve |  |  |  |
| submitted | rejected | reject |  |  |  |

## Prohibited Actions

Examples:

- Maker must not approve own submitted record.
- Checker must not approve outside assigned scope.
- Rejected records must not be approved without re-submission.
- Cancelled records must not be reused.

Add application-specific prohibited actions here.

## Business Logic Test Ideas

- Try actions out of order.
- Repeat the same action.
- Replay stale request after state change.
- Change status or owner fields in request body.
- Submit parallel requests for the same action.
- Attempt self-approval.

## Vull-E Retrieval Keywords

business flow, workflow, state transition, maker checker, approve, reject,
submit, cancel, self-approval, stale request, replay, race condition

