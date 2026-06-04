# MITRE CWE - File Upload, Parsing, And Deserialization Mapping

Source reference:
- MITRE CWE: https://cwe.mitre.org/

Use this document when Jira or Confluence mentions file upload, import, export,
document preview, PDF, Excel, CSV, ZIP, XML, JSON parser, archive extraction,
deserialization, template import, OCR, antivirus scanning, or document
conversion.

## Common CWE Mappings

### CWE-434 - Unrestricted Upload Of File With Dangerous Type

Use when uploaded file types, extensions, content signatures, or processing
rules are unclear.

Test direction:
- extension/content mismatch
- active content files
- oversized files
- multiple file upload limits
- authorization on upload/download/preview

### CWE-22 - Path Traversal

Use when filenames, archive paths, export paths, or download paths are
user-controlled.

Test direction:
- traversal sequences
- encoded traversal
- archive extraction paths
- generated file names

### CWE-502 - Deserialization Of Untrusted Data

Use when imports, queues, cached objects, serialized payloads, or binary object
formats are accepted.

Test direction:
- identify serialization format
- verify only trusted formats are accepted
- verify schema validation
- avoid unsafe object deserialization

### CWE-611 - Improper Restriction Of XML External Entity Reference

Use when XML upload, SOAP, document parsing, or XML-based import is introduced.

Test direction:
- confirm external entity processing is disabled
- confirm DTD handling is restricted
- test only with safe authorized payloads

### CWE-409 - Improper Handling Of Highly Compressed Data

Use when ZIP or archive uploads are supported.

Test direction:
- archive size limits
- nested archive limits
- compression ratio limits
- extraction timeout and storage quota

## Evidence Expectations

- accepted file types
- validation rules
- upload request and response
- stored metadata
- download/preview authorization behavior
- parser/converter side effects

## Automation Guard

File and parser tests can trigger persistent data, antivirus, OCR, conversion,
or downstream workflows. Require isolated test data and explicit approval for
state-changing tests.

## Vull-E Retrieval Keywords

CWE-434, CWE-22, CWE-502, CWE-611, CWE-409, file upload, file download, archive,
ZIP, XML, XXE, deserialization, parser, import, export, PDF, CSV, Excel, OCR

