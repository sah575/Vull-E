# OWASP ASVS - Authentication And Session Notes

Source reference:
- OWASP ASVS: https://owasp.org/www-project-application-security-verification-standard/

Use this document when Jira or Confluence mentions login, OTP, MFA, session,
token, refresh token, password, device binding, remember-me, timeout, or
identity federation.

## Risk Signals

- New login, OTP, MFA, reset-password, or session renewal behavior.
- Token values are passed through URL parameters or client-controlled storage.
- Different channels share the same session or authentication state.
- Session timeout, logout, device change, or password reset behavior changes.

## Security Expectations

- Authentication decisions must be performed on trusted server-side state.
- Session identifiers and tokens must not be exposed in URLs or logs.
- Sensitive authentication events should rotate or invalidate sessions where
  appropriate.
- MFA and OTP verification must be bound to the correct user, transaction, and
  session.
- Failed authentication attempts should be rate-limited and logged safely.

## Test Ideas

- Check whether old sessions remain valid after password reset, role change, or
  MFA enrollment.
- Verify OTP codes cannot be reused across sessions, users, or transactions.
- Confirm logout invalidates server-side session state.
- Try replaying a token from another role or channel.
- Review logs and redirects for token leakage.

## Vull-E Retrieval Keywords

authentication, session, token, refresh token, OTP, MFA, password reset, logout,
remember me, federation, SSO, device, rate limit

