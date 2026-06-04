# IDOR Checklist

IDOR risk is high when a request contains direct object identifiers such as
customerId, documentId, accountId, cardId, orderId, or transactionId.

Recommended checks:

- Replace object identifiers with another authorized user's object.
- Replay the same request with a lower-privileged role.
- Replay branch-scoped requests with a customer from a different branch.
- Verify that unauthorized responses do not reveal masked or partial data.
- Check both read endpoints and state-changing endpoints.

Evidence should include the original authorized request, the modified request,
authorization context, and response differences.

