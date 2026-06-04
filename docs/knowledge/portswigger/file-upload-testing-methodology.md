# PortSwigger-Style Methodology - File Upload Testing

Source reference:
- PortSwigger Web Security Academy: https://portswigger.net/web-security
- PortSwigger File upload topic: https://portswigger.net/web-security/file-upload

Purpose:
Help Vull-E plan file upload, download, preview, import, export, and document
processing tests without relying on lab-specific exploit steps.

## When Vull-E Should Retrieve This

Retrieve this when Jira or Confluence mentions:

- upload, download, document, attachment
- PDF, Excel, CSV, ZIP, XML, image, archive
- import/export
- document preview
- OCR
- antivirus
- file conversion
- object storage
- signed URL
- customer document approval

## File Upload Risk Model

File upload risk is not only about dangerous files. It also includes:

- authorization on upload/download/preview
- content type validation
- file size and quota
- path traversal in filenames
- unsafe parser/converter behavior
- sensitive data in previews
- formula injection in exports
- object storage permission errors
- persistent downstream workflow effects

## Burp-Oriented Workflow

1. Capture normal upload request.
2. Identify file field, metadata fields, object IDs, and auth token.
3. Capture download/preview request.
4. Test validation controls with safe files.
5. Test authorization separately for upload, download, preview, delete, and
   metadata endpoints.
6. Check generated URLs and object storage access.
7. Check side effects such as OCR, preview, email, or workflow state.

## Test Pattern: Extension And MIME Validation

Test questions:

- Is extension allowlisted?
- Is MIME type trusted from client?
- Is content signature checked?
- Are double extensions handled?
- Are uppercase/lowercase variants normalized?

Safe test ideas:

- valid extension with unexpected content
- invalid extension with valid content
- MIME mismatch
- oversized file
- empty file
- very long filename

## Test Pattern: Authorization On File Objects

Test every file operation:

- upload
- download
- preview
- delete
- replace
- metadata update
- generated thumbnail
- OCR text retrieval

Method:

1. Upload file as User A.
2. Attempt access as User B.
3. Attempt checker outside branch.
4. Attempt maker download after approval/rejection if policy differs.

## Test Pattern: Filename And Path Handling

Safe checks:

- path separators
- traversal-like names
- Unicode confusables
- duplicate filenames
- reserved characters
- very long names
- archive nested paths if ZIP is supported

Expected secure behavior:

- server-generated storage names
- no path control from client filename
- strict archive extraction controls

## Test Pattern: Export And Spreadsheet Safety

Use when CSV/Excel exports exist.

Test ideas:

- verify export authorization
- compare export fields by role
- check formula injection handling
- check whether masked UI fields are unmasked in export

## Evidence To Collect

- upload request/response
- file metadata
- validation decision
- download/preview request
- authorization comparison
- generated URL if exposed
- downstream processing side effects

## Automation Guidance

File upload can create persistent artifacts. Require approval for tests that:

- upload files to shared environments
- trigger antivirus/OCR/conversion
- send emails or notifications
- affect approval workflows

## Vull-E Retrieval Keywords

PortSwigger file upload, document upload, download, preview, OCR, antivirus,
MIME, extension, object storage, signed URL, file authorization, CSV export,
formula injection, path traversal

