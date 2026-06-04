# PortSwigger-Style Methodology - JWT And OAuth Testing

Source reference:
- PortSwigger Web Security Academy: https://portswigger.net/web-security
- PortSwigger JWT topic: https://portswigger.net/web-security/jwt
- PortSwigger OAuth topic: https://portswigger.net/web-security/oauth

Purpose:
Help Vull-E identify token, JWT, OAuth/OIDC, SSO, and authorization flow risks
from Jira and Confluence changes.

## When Vull-E Should Retrieve This

Retrieve this when ticket mentions:

- JWT
- OAuth
- OIDC
- SSO
- authorization code
- access token
- refresh token
- ID token
- client ID
- redirect URI
- scope
- audience
- issuer
- federation

## JWT Risk Model

Important questions:

- Is signature verified?
- Is algorithm restricted?
- Are issuer and audience checked?
- Are expiration and not-before checked?
- Are roles/scopes trusted from token safely?
- Are tokens logged or exposed?
- Is refresh token rotation enforced?

## OAuth/OIDC Risk Model

Important questions:

- Are redirect URIs strictly allowlisted?
- Is state parameter used and validated?
- Is PKCE required where appropriate?
- Are scopes minimized?
- Is token audience correct?
- Can authorization codes be reused?
- Is account linking safe?

## Test Pattern: Token Claim Trust

Use when ticket changes role/scope/token handling.

Method:

1. Decode token without treating it as proof.
2. Identify role, scope, audience, issuer, expiry.
3. Verify backend enforces these correctly.
4. Compare token behavior across roles.

## Test Pattern: Refresh Token Lifecycle

Method:

1. Capture refresh flow.
2. Use refresh token once.
3. Attempt reuse.
4. Check rotation and revocation.
5. Check logout/password-change behavior.

## Test Pattern: OAuth Redirect And State

Method:

1. Inspect redirect URI handling.
2. Check exact-match allowlist.
3. Verify state binding.
4. Verify code cannot be reused.
5. Verify account linking requires authenticated expected identity.

## Evidence To Collect

- token type
- decoded non-sensitive claims
- issuer/audience/scope
- flow request/response
- replay behavior
- redirect URI behavior
- session linking behavior

## False Positive Checks

- Token content visible to client is normal for JWT; weakness depends on trust,
  validation, leakage, and authorization impact.
- OAuth misconfiguration depends on provider/client configuration and threat
  model.

## Vull-E Retrieval Keywords

PortSwigger JWT, OAuth, OIDC, SSO, access token, refresh token, ID token,
issuer, audience, scope, redirect URI, state, PKCE, authorization code, token
replay

