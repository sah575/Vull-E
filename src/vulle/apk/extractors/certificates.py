from typing import Any

from vulle.apk.models import CertificateInfo, SignatureInfo

_DEBUG_CERT_SUBJECT_MARKER = "Android Debug"


def extract_signature_info(apk: Any) -> SignatureInfo:
    certificates = [_certificate_info(cert) for cert in apk.get_certificates()]
    return SignatureInfo(
        signed_v1=bool(apk.is_signed_v1()),
        signed_v2=bool(apk.is_signed_v2()),
        signed_v3=bool(apk.is_signed_v3()),
        signer_count=len(certificates),
        certificates=certificates,
    )


def _certificate_info(cert: Any) -> CertificateInfo:
    subject = _human_friendly(cert.subject)
    issuer = _human_friendly(cert.issuer)
    return CertificateInfo(
        subject=subject,
        issuer=issuer,
        valid_from=_isoformat(cert.not_valid_before),
        valid_to=_isoformat(cert.not_valid_after),
        sha256_fingerprint=_hex_fingerprint(cert.sha256_fingerprint),
        is_debug_cert=_DEBUG_CERT_SUBJECT_MARKER in (subject or ""),
    )


def _human_friendly(name: Any) -> str | None:
    try:
        return str(name.human_friendly)
    except Exception:
        return None


def _isoformat(value: Any) -> str | None:
    if value is None:
        return None
    try:
        return str(value.isoformat())
    except Exception:
        return str(value)


def _hex_fingerprint(value: Any) -> str | None:
    if value is None:
        return None
    return str(value).replace(" ", "").upper()
