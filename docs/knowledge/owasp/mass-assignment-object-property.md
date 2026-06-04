# OWASP API Security - Mass Assignment And Object Property Authorization

Source reference:
- OWASP API Security Top 10 2023: https://owasp.org/API-Security/editions/2023/en/0x00-header/

Use this document when Jira or Confluence mentions create/update APIs that
accept JSON objects, DTOs, forms, profile updates, customer updates, role
updates, status changes, or configuration changes.

## Risk Signals

- Request body accepts complete objects.
- Ticket says only some fields are editable by a role.
- Hidden UI fields exist but API accepts generic payload.
- Status, role, permission, owner, branch, limit, fee, approval state, or audit
  fields appear in request/response models.

## Security Expectations

- Server must bind only allowed fields for the current operation and role.
- Sensitive fields must be ignored or rejected if client supplied.
- Response fields must be filtered by role and data classification.
- Object property authorization must apply to nested objects too.

## Test Ideas

- Add forbidden fields to update payload.
- Change read-only fields such as status, ownerUserId, branchId, role, limit, or
  approvalState.
- Submit nested objects with unauthorized child IDs.
- Compare response fields across roles.
- Try bulk update with mixed authorized and unauthorized fields.

## Evidence

- Original allowed payload.
- Modified payload with forbidden property.
- Response and stored state after request.
- Business rule showing why property should be blocked.

## Vull-E Retrieval Keywords

mass assignment, object property authorization, DTO, JSON body, hidden field,
role, status, branchId, ownerUserId, approvalState, read-only field, nested object

