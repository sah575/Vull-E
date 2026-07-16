import hashlib
import threading
import zipfile
from collections.abc import Callable
from pathlib import Path
from typing import TypeVar

from vulle.apk.limits import (
    MAX_APK_SIZE_BYTES,
    MAX_COMPRESSION_RATIO,
    MAX_TOTAL_UNCOMPRESSED_BYTES,
    MAX_ZIP_ENTRIES,
)
from vulle.errors import ApkAnalysisTimeoutError, ApkValidationError

T = TypeVar("T")


def validate_apk_zip(path: Path) -> zipfile.ZipFile:
    if not path.is_file():
        raise ApkValidationError(f"APK file does not exist: {path}")

    file_size = path.stat().st_size
    if file_size > MAX_APK_SIZE_BYTES:
        raise ApkValidationError(
            f"APK file size {file_size} bytes exceeds the maximum of "
            f"{MAX_APK_SIZE_BYTES} bytes: {path}"
        )

    try:
        archive = zipfile.ZipFile(path)
    except zipfile.BadZipFile as exc:
        raise ApkValidationError(f"File is not a valid ZIP/APK archive: {path}") from exc

    infolist = archive.infolist()
    if len(infolist) > MAX_ZIP_ENTRIES:
        archive.close()
        raise ApkValidationError(
            f"APK contains {len(infolist)} ZIP entries, exceeding the maximum of "
            f"{MAX_ZIP_ENTRIES}: {path}"
        )

    total_uncompressed = 0
    for info in infolist:
        _reject_path_traversal(info.filename)
        total_uncompressed += info.file_size
        if info.compress_size > 0 and info.file_size / info.compress_size > MAX_COMPRESSION_RATIO:
            archive.close()
            raise ApkValidationError(
                f"ZIP entry '{info.filename}' has a compression ratio above the "
                f"maximum of {MAX_COMPRESSION_RATIO}: {path}"
            )

    if total_uncompressed > MAX_TOTAL_UNCOMPRESSED_BYTES:
        archive.close()
        raise ApkValidationError(
            f"APK's total uncompressed size {total_uncompressed} bytes exceeds the "
            f"maximum of {MAX_TOTAL_UNCOMPRESSED_BYTES} bytes: {path}"
        )

    return archive


def _reject_path_traversal(filename: str) -> None:
    normalized = filename.replace("\\", "/")
    if normalized.startswith("/") or ":" in normalized or ".." in normalized.split("/"):
        raise ApkValidationError(f"ZIP entry has an unsafe path: {filename}")


def compute_sha256(path: Path) -> str:
    return _compute_digest(path, hashlib.sha256())


def compute_sha1(path: Path) -> str:
    # Not used for security purposes here - only as a file-identification hash
    # alongside SHA-256, matching the conventional VirusTotal-style report format.
    return _compute_digest(path, hashlib.sha1(usedforsecurity=False))


def _compute_digest(path: Path, digest: "hashlib._Hash") -> str:
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def run_with_timeout(fn: Callable[[], T], *, timeout: float) -> T:
    result: list[T] = []
    error: list[BaseException] = []

    def _target() -> None:
        try:
            result.append(fn())
        except BaseException as exc:  # noqa: BLE001 - re-raised in the caller's thread
            error.append(exc)

    worker = threading.Thread(target=_target, daemon=True)
    worker.start()
    worker.join(timeout=timeout)

    if worker.is_alive():
        # The thread cannot be killed; abandon it as a daemon so the interpreter
        # can still exit promptly instead of waiting for it to finish naturally.
        raise ApkAnalysisTimeoutError(
            f"APK analysis step did not complete within {timeout} seconds"
        )
    if error:
        raise error[0]
    return result[0]
