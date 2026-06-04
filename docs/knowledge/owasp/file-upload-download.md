# OWASP Cheat Sheet - File Upload And Download Notes

Source reference:
- OWASP File Upload Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html

Use this document when Jira or Confluence mentions upload, download, document,
attachment, image, PDF, Excel, CSV, ZIP, import, export, antivirus, preview,
thumbnail, or document approval.

## Risk Signals

- Users upload identity, customer, onboarding, claim, or transaction documents.
- Uploaded files are previewed, converted, OCR processed, emailed, or exported.
- File metadata is stored and later rendered.
- Files are downloaded through object IDs or temporary links.
- ZIP, Excel, CSV, XML, SVG, HTML, or PDF uploads are supported.

## Security Expectations

- Validate extension, MIME type, content signature, size, and file structure.
- Store files outside web root or behind controlled object storage access.
- Generate server-side filenames; do not trust client filenames or paths.
- Scan files where business risk requires it.
- Enforce authorization on upload, preview, download, delete, and metadata APIs.
- Disable active content where possible.
- Prevent path traversal and unsafe archive extraction.

## Test Ideas

- Upload mismatched extension and content type.
- Upload oversized files and many small files.
- Use filenames with path traversal, Unicode confusables, very long names, null
  bytes, reserved characters, and duplicate names.
- Test whether maker can download another customer's document.
- Test whether checker can access documents outside branch scope.
- Test document preview and converted output for authorization and data leakage.
- Test CSV/Excel exports for formula injection.
- Test ZIP extraction with nested paths and high compression ratio if archives
  are supported.

## Evidence

- Upload request, file metadata, and server response.
- Download/preview request showing object authorization behavior.
- Stored filename or returned URL if exposed.
- Scanner or validation decision if available.
- Side effects such as generated preview, OCR text, or exported file.

## Automation Guard

File upload tests can create persistent data. Use isolated test records and
explicit approval for uploads that trigger downstream processing, antivirus,
OCR, email, or document approval workflows.

## Vull-E Retrieval Keywords

file upload, file download, document, attachment, PDF, Excel, CSV, ZIP, OCR,
preview, thumbnail, MIME, extension, antivirus, object storage, path traversal,
formula injection

