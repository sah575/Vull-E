# Audit Logging Standard

Sensitive banking workflows must create audit logs for approval, rejection,
customer data access, document access, permission changes, and failed
authorization decisions.

Audit records should include actor id, role, customer id, object id, action,
decision, timestamp, source channel, and correlation id.

Security review should check that rejected authorization attempts are logged
without exposing sensitive data in logs.

