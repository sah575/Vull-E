# Testing for SQL Injection

SQL injection testing checks whether query parameters, JSON fields, filters, and
sorting expressions can alter backend database queries. Safe testing should use
approved payloads and low-impact probes in shared environments.

## Test Objectives

- Identify input values used in database queries.
- Test numeric, string, and boolean contexts.
- Collect evidence without destructive payloads.
