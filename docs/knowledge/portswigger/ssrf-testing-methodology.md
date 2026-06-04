# PortSwigger-Style Methodology - SSRF Testing

Source reference:
- PortSwigger Web Security Academy: https://portswigger.net/web-security
- PortSwigger SSRF topic: https://portswigger.net/web-security/ssrf

Purpose:
Help Vull-E identify and plan safe SSRF testing for features that cause the
server to fetch or interact with user-controlled URLs or external systems.

## When Vull-E Should Retrieve This

Retrieve this when Jira or Confluence mentions:

- URL fetch
- webhook
- callback
- redirect
- import from URL
- image URL
- document URL
- partner endpoint
- third-party API
- notification callback
- proxy
- outbound HTTP client
- metadata service

## SSRF Risk Model

SSRF occurs when the backend can be influenced to make requests to unintended
locations.

Typical target classes:

- internal services
- localhost
- cloud metadata endpoints
- private IP ranges
- admin panels
- service discovery endpoints
- restricted partner APIs

## Safe Testing Principle

Do not blindly scan internal networks. For authorized enterprise testing, use
approved canary endpoints and environment-specific allowlists.

Vull-E should recommend SSRF testing only when:

- the feature accepts URLs or external targets
- scope policy allows the test
- a safe callback/canary endpoint exists
- testing will not probe arbitrary internal ranges

## Burp-Oriented Workflow

1. Identify request parameter that carries URL/host/path.
2. Capture request in Burp.
3. Send to Repeater.
4. Replace URL with approved canary endpoint.
5. Observe whether backend makes outbound request.
6. Test scheme/host validation with safe variants.
7. Test redirect behavior with approved redirect target.
8. Check error messages and logs for internal leakage.

## Test Pattern: Basic URL Fetch Control

Questions:

- Which schemes are allowed?
- Are hosts allowlisted?
- Are ports restricted?
- Are redirects followed?
- Is DNS resolved safely?
- Are private ranges blocked?

Safe test ideas:

- approved external canary URL
- disallowed scheme
- non-HTTP scheme if parser accepts it
- redirect from allowed to disallowed host
- oversized response
- slow response timeout

## Test Pattern: Internal Address Protection

Validate policy rather than scan:

- localhost should be blocked
- private IP ranges should be blocked
- link-local addresses should be blocked
- metadata service addresses should be blocked
- encoded IP forms should be normalized before allow/deny decision

## Test Pattern: Blind SSRF

Use when response does not show fetched content.

Safe method:

1. Submit approved out-of-band canary URL.
2. Observe whether canary receives request.
3. Record method, headers, source, and timing.
4. Do not use arbitrary internal targets.

## Evidence To Collect

- parameter name
- original URL
- test URL
- outbound canary hit if any
- response or error
- redirect behavior
- validation rule
- whether internal details leaked

## False Positive Checks

- Client-side fetch is not SSRF unless backend performs request.
- URL stored but not fetched is not SSRF by itself.
- A rejected URL is expected secure behavior.
- DNS/cache/proxy behavior must be understood before reporting.

## Automation Guidance

SSRF automation must be restricted to approved canary endpoints. No internal
network discovery should occur without explicit authorization and scope guard.

## Vull-E Retrieval Keywords

PortSwigger SSRF, URL fetch, webhook, callback, redirect, import URL, image URL,
document URL, canary endpoint, blind SSRF, metadata service, localhost, private
IP, outbound request

