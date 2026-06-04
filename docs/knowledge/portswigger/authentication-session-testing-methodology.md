# PortSwigger-Style Methodology - Authentication And Session Testing

Source reference:
- PortSwigger Web Security Academy: https://portswigger.net/web-security
- PortSwigger Authentication topic: https://portswigger.net/web-security/authentication

Purpose:
Help Vull-E identify authentication, session, MFA, OTP, password reset, and
token lifecycle risks from Jira and Confluence changes.

## When Vull-E Should Retrieve This

Retrieve this when the ticket mentions:

- login, logout, session, token, refresh token, JWT
- OTP, MFA, device verification, step-up authentication
- password reset, password change, account recovery
- remember me, session timeout, idle timeout
- SSO, OAuth, OIDC, SAML, federation
- channel switch between web/mobile/API
- role change, password change, or device change behavior

## Core Testing Questions

Authentication testing should answer:

- Can a user prove identity correctly?
- Can authentication be bypassed?
- Are sessions invalidated when security state changes?
- Are tokens bound to the right user, session, device, and action?
- Are rate limits and lockouts safe?
- Are secrets exposed in URLs, logs, responses, or browser storage?

## Burp-Oriented Workflow

1. Capture login and post-login requests.
2. Identify session cookies, CSRF tokens, JWTs, refresh tokens, and device IDs.
3. Capture logout, password reset, MFA, and refresh flows.
4. Replay requests after state changes.
5. Compare behavior across roles, browsers, and sessions.
6. Inspect redirects, URLs, response bodies, cookies, and headers.

## Test Pattern: Session Invalidation

Use when password, MFA, role, or device state changes.

Test steps:

1. Log in from two sessions.
2. Change password, role, MFA, or device binding in one session.
3. Replay sensitive request from old session.
4. Check whether old session remains valid.

Expected secure behavior:

- high-risk state changes invalidate or re-authenticate existing sessions where
  policy requires it.

## Test Pattern: OTP/MFA Binding

Use when OTP or MFA is introduced or changed.

Test steps:

1. Request OTP for User A/session A.
2. Attempt use in session B or for User B.
3. Attempt reuse after success.
4. Attempt use after timeout.
5. Check rate limits and failed-attempt behavior.

Expected secure behavior:

- OTP is bound to correct user, session, channel, and transaction.
- OTP cannot be reused.
- failed attempts are rate-limited and logged.

## Test Pattern: Password Reset And Recovery

Use when reset-password or account recovery changes.

Test steps:

1. Capture reset request.
2. Inspect token exposure in URL, email, logs, and redirects.
3. Try token reuse after success.
4. Try old token after new reset request.
5. Verify reset does not allow account enumeration.

Expected secure behavior:

- tokens are single-use, short-lived, unpredictable, and scoped.
- account enumeration is minimized.
- existing sessions are handled according to policy.

## Test Pattern: Session Fixation And Token Reuse

Use when session cookies or login flow changes.

Test steps:

1. Capture pre-login session ID.
2. Log in and check whether session ID rotates.
3. Replay old token/cookie.
4. Verify secure cookie attributes.

Expected secure behavior:

- session identifiers rotate after login.
- cookies use secure attributes where applicable.

## Test Pattern: Rate Limit And Lockout

Use for login, OTP, password reset, and token refresh flows.

Test ideas:

- repeated failed login attempts
- repeated OTP attempts
- repeated password reset requests
- distributed attempts across username/IP/session if policy covers it

Automation guard:

- do not perform high-volume brute force against shared environments.
- use low-volume threshold tests unless explicit approval exists.

## Evidence To Collect

- flow type
- session/token before and after state change
- request/response showing reuse or invalidation
- cookie attributes
- rate-limit behavior
- audit/logging behavior

## False Positive Checks

- Some systems intentionally keep sessions after password change; verify policy.
- MFA may be step-up only for high-risk actions; check requirements.
- Account enumeration risk depends on response consistency and business context.

## Vull-E Retrieval Keywords

PortSwigger authentication, session invalidation, OTP, MFA, password reset,
token reuse, refresh token, session fixation, rate limit, account recovery,
logout, cookie, Burp Repeater

