# Testing Directory Traversal File Include

Authorization testing should verify that a user cannot access files or objects
outside their allowed scope. Test cases include changing object identifiers,
branch identifiers, and path values.

## Test Objectives

- Identify authorization checks on every server-side request.
- Verify horizontal and vertical access control boundaries.
- Confirm denied access is logged and does not expose sensitive data.
