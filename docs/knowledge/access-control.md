# Access Control Review Notes

Every endpoint that accepts customerId, accountId, documentId, transactionId,
or a similar object identifier must enforce authorization on the server side.

For maker-checker flows:

- Maker users can create or upload records but cannot approve their own work.
- Checker users can approve only records inside their allowed business scope.
- Branch-scoped users must not access customers assigned to another branch.
- Role checks must use server-side identity and permissions, not request fields.

Security tests should verify horizontal access control, vertical access control,
and workflow bypass attempts.

