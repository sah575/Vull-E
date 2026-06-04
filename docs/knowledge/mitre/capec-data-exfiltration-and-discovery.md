# MITRE CAPEC - Data Discovery And Exfiltration-Oriented Patterns

Source reference:
- MITRE CAPEC: https://capec.mitre.org/

Use this document when Jira or Confluence mentions export, report, search,
download, document preview, bulk API, pagination, customer data, account data,
PII, logs, or data sharing.

## Pattern: Excessive Data Retrieval

Risk signals:
- Endpoint returns lists, search results, exports, reports, or nested objects.

Test pattern:
- Increase page size.
- Expand date range.
- Request hidden fields or nested expansions.
- Compare role-based response fields.
- Check whether unauthorized records appear in list endpoints.

## Pattern: Unauthorized Export

Risk signals:
- PDF, Excel, CSV, report, bulk download, archive, or scheduled export.

Test pattern:
- Try export with lower-privileged role.
- Try changing filter scope.
- Compare export output with UI-visible records.
- Check audit log and retention behavior.

## Pattern: Metadata Leakage

Risk signals:
- Response includes counts, facets, owner names, branch names, document names,
  status, timestamps, or relationship metadata.

Test pattern:
- Attempt unauthorized object access.
- Inspect response body even when main sensitive values are masked.
- Check pagination totals and search facets.

## Pattern: Log Or Error-Based Discovery

Risk signals:
- New error handling, validation messages, logging, monitoring, or debug output.

Test pattern:
- Trigger validation errors.
- Trigger unauthorized access.
- Inspect whether errors disclose internal object existence, table names,
  service names, stack traces, or sensitive data.

## Vull-E Retrieval Keywords

CAPEC data exfiltration, excessive data retrieval, unauthorized export, metadata
leakage, discovery, search, report, CSV, Excel, PDF, pagination, facets, logs,
error leakage

