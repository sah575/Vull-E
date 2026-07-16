import hashlib
import zipfile
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as FutureTimeoutError
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
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def run_with_timeout(fn: Callable[[], T], *, timeout: float) -> T:
    executor = ThreadPoolExecutor(max_workers=1)
    future = executor.submit(fn)
    try:
        return future.result(timeout=timeout)
    except FutureTimeoutError as exc:
        raise ApkAnalysisTimeoutError(
            f"APK analysis step did not complete within {timeout} seconds"
        ) from exc
    finally:
        executor.shutdown(wait=False)
