# MITRE CAPEC - Authorization Abuse Patterns

Source reference:
- MITRE CAPEC: https://capec.mitre.org/

Use this document to convert access-control risk signals into attacker-style
test patterns. CAPEC describes attack patterns; it should guide test strategy,
not replace business-specific authorization rules.

## Pattern: Direct Object Reference Manipulation

When to use:
- URL or body contains customerId, accountId, documentId, transactionId, caseId,
  cardId, branchId, or userId.

Test pattern:
- Start with an authorized request.
- Change one object identifier at a time.
- Keep authentication context unchanged.
- Observe whether unauthorized object data or state change occurs.

Evidence:
- original object owner/scope
- modified object owner/scope
- request/response comparison
- expected rule

## Pattern: Horizontal Privilege Abuse

When to use:
- Same role users should see only their own or assigned objects.

Test pattern:
- Use User A token to request User B's object.
- Use branch A user to request branch B customer.
- Use same privilege level but different ownership/scope.

## Pattern: Vertical Privilege Abuse

When to use:
- Lower role attempts higher role action.

Test pattern:
- Maker attempts checker action.
- Branch user attempts admin action.
- Viewer attempts update/export/approve action.

## Pattern: Forced Browsing

When to use:
- UI hides page or button, but backend endpoint may still exist.

Test pattern:
- Call hidden API endpoint directly.
- Navigate directly to protected page route.
- Replay request captured from higher-privileged role.

## Pattern: Permission Boundary Confusion

When to use:
- Multiple scopes exist: branch, region, portfolio, customer segment, product,
  channel, or tenant.

Test pattern:
- Hold role constant and change only business scope.
- Test list, detail, action, export, and search endpoints.

## Vull-E Retrieval Keywords

CAPEC authorization, direct object reference, horizontal privilege, vertical
privilege, forced browsing, permission boundary, scope bypass, role bypass,
branch bypass, IDOR

