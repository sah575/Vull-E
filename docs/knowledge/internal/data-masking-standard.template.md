# Internal Template - Data Masking And Classification Standard

Purpose:
Define sensitive data fields, masking requirements, role visibility, and export
rules. Vull-E uses this to detect sensitive data exposure risks.

Do not include real customer data.

## Data Classes

| Data Class | Examples | Sensitivity | Notes |
| --- | --- | --- | --- |
| PII | national ID, phone, address, email | High | Apply masking and least privilege |
| Financial | account number, IBAN, balance | High | Restrict and audit |
| Card | PAN, CVV, expiry | Critical | Follow card data rules |
| Authentication | token, OTP, password | Critical | Never log |

## Field-Level Rules

| Field | Data Class | Maker | Checker | Admin | Export Allowed | Log Allowed |
| --- | --- | --- | --- | --- | --- | --- |
| nationalId | PII | Masked | Unmasked if required | Restricted | Conditional | No |
| phoneNumber | PII | Masked | Conditional | Restricted | Conditional | No |
| accountNumber | Financial | Masked | Conditional | Restricted | Conditional | No |

## Channel Rules

| Channel | Rule |
| --- | --- |
| Web UI |  |
| Mobile API |  |
| Export |  |
| Email/SMS |  |
| Logs |  |
| Third-party API |  |

## Test Ideas

- Compare response fields by role.
- Compare UI, API, export, print, and mobile responses.
- Trigger errors and check sensitive data leakage.
- Verify denied requests do not reveal sensitive fields.
- Verify logs redact tokens, OTPs, and PII.

## Vull-E Retrieval Keywords

data masking, data classification, PII, KVKK, GDPR, account, IBAN, card,
national ID, phone, address, export, log redaction, sensitive data

