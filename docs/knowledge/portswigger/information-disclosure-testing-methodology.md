# PortSwigger-Style Methodology - Information Disclosure Testing

Source reference:
- PortSwigger Web Security Academy: https://portswigger.net/web-security
- PortSwigger Information disclosure topic: https://portswigger.net/web-security/information-disclosure

Purpose:
Help Vull-E identify information disclosure risks in responses, errors, logs,
exports, debug features, metadata, and documentation exposure.

## When Vull-E Should Retrieve This

Retrieve this when Jira or Confluence mentions:

- error handling
- logs
- debug
- stack trace
- OpenAPI/Swagger
- health/metrics
- report/export
- file metadata
- customer data
- masking
- admin route
- environment config

## Disclosure Risk Model

Information disclosure may include:

- PII or financial data
- internal IDs
- object existence
- stack traces
- SQL errors
- service names
- hostnames
- versions
- tokens/secrets
- debug configuration
- hidden endpoints
- excessive response fields

## Burp-Oriented Workflow

1. Browse normal flow and capture responses.
2. Trigger validation errors safely.
3. Trigger unauthorized access safely.
4. Inspect headers, redirects, cookies, and response bodies.
5. Compare roles for response fields.
6. Check OpenAPI/Swagger and operational endpoints.
7. Check exports and downloaded files.

## Test Pattern: Error Message Disclosure

Method:

- invalid type
- missing required field
- invalid object ID
- unauthorized object
- malformed JSON
- invalid filter/sort

Look for:

- stack trace
- SQL/ORM details
- internal service names
- full path
- sensitive values

## Test Pattern: Metadata Disclosure

Look for:

- total counts
- branch names
- owner names
- customer status
- document names
- internal IDs
- timestamps
- workflow state

Even when primary data is masked, metadata may reveal sensitive business
information.

## Test Pattern: Documentation And Debug Exposure

Check:

- Swagger/OpenAPI
- actuator
- health
- metrics
- debug endpoints
- admin consoles
- feature flag endpoints

Expected secure behavior:

- exposed only intentionally
- authenticated and authorized
- no secrets or internal-only routes leaked

## Evidence To Collect

- request that triggered disclosure
- response body/header
- exposed fields
- expected classification
- role used
- source rule or policy

## Vull-E Retrieval Keywords

PortSwigger information disclosure, error handling, stack trace, debug,
OpenAPI, Swagger, actuator, health, metrics, metadata leakage, excessive fields,
masked data, response comparison

