import time
import zipfile
from pathlib import Path

import pytest

from vulle.apk import workspace
from vulle.errors import ApkAnalysisTimeoutError, ApkValidationError


def _write_zip(
    path: Path,
    entries: dict[str, bytes],
    *,
    compress_type: int = zipfile.ZIP_DEFLATED,
) -> None:
    with zipfile.ZipFile(path, "w", compress_type) as archive:
        for name, data in entries.items():
            archive.writestr(name, data)


def test_missing_file_raises(tmp_path: Path) -> None:
    with pytest.raises(ApkValidationError, match="does not exist"):
        workspace.validate_apk_zip(tmp_path / "missing.apk")


def test_oversized_file_is_rejected(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(workspace, "MAX_APK_SIZE_BYTES", 10)
    apk_path = tmp_path / "sample.apk"
    _write_zip(apk_path, {"AndroidManifest.xml": b"x" * 100})

    with pytest.raises(ApkValidationError, match="exceeds the maximum"):
        workspace.validate_apk_zip(apk_path)


def test_invalid_zip_is_rejected(tmp_path: Path) -> None:
    apk_path = tmp_path / "sample.apk"
    apk_path.write_bytes(b"not a zip file")

    with pytest.raises(ApkValidationError, match="not a valid ZIP"):
        workspace.validate_apk_zip(apk_path)


def test_path_traversal_entry_is_rejected(tmp_path: Path) -> None:
    apk_path = tmp_path / "sample.apk"
    _write_zip(apk_path, {"../../etc/passwd": b"evil"})

    with pytest.raises(ApkValidationError, match="unsafe path"):
        workspace.validate_apk_zip(apk_path)


def test_absolute_path_entry_is_rejected(tmp_path: Path) -> None:
    apk_path = tmp_path / "sample.apk"
    _write_zip(apk_path, {"/etc/passwd": b"evil"})

    with pytest.raises(ApkValidationError, match="unsafe path"):
        workspace.validate_apk_zip(apk_path)


def test_too_many_entries_is_rejected(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(workspace, "MAX_ZIP_ENTRIES", 2)
    apk_path = tmp_path / "sample.apk"
    _write_zip(apk_path, {f"file{i}.txt": b"x" for i in range(5)})

    with pytest.raises(ApkValidationError, match="ZIP entries"):
        workspace.validate_apk_zip(apk_path)


def test_high_compression_ratio_is_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(workspace, "MAX_COMPRESSION_RATIO", 10)
    apk_path = tmp_path / "sample.apk"
    _write_zip(apk_path, {"zeros.bin": b"\x00" * (1024 * 1024)})

    with pytest.raises(ApkValidationError, match="compression ratio"):
        workspace.validate_apk_zip(apk_path)


def test_total_uncompressed_size_limit_is_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(workspace, "MAX_TOTAL_UNCOMPRESSED_BYTES", 10)
    monkeypatch.setattr(workspace, "MAX_COMPRESSION_RATIO", 10_000)
    apk_path = tmp_path / "sample.apk"
    _write_zip(apk_path, {"file.txt": b"x" * 100})

    with pytest.raises(ApkValidationError, match="total uncompressed size"):
        workspace.validate_apk_zip(apk_path)


def test_valid_zip_is_accepted(tmp_path: Path) -> None:
    apk_path = tmp_path / "sample.apk"
    _write_zip(apk_path, {"AndroidManifest.xml": b"manifest", "classes.dex": b"dex"})

    archive = workspace.validate_apk_zip(apk_path)
    try:
        assert sorted(archive.namelist()) == ["AndroidManifest.xml", "classes.dex"]
    finally:
        archive.close()


def test_compute_sha256_matches_hashlib(tmp_path: Path) -> None:
    import hashlib

    apk_path = tmp_path / "sample.bin"
    apk_path.write_bytes(b"hello world")

    assert workspace.compute_sha256(apk_path) == hashlib.sha256(b"hello world").hexdigest()


def test_run_with_timeout_returns_result_within_budget() -> None:
    assert workspace.run_with_timeout(lambda: 42, timeout=5) == 42


def test_run_with_timeout_raises_on_slow_function() -> None:
    with pytest.raises(ApkAnalysisTimeoutError):
        workspace.run_with_timeout(lambda: time.sleep(2), timeout=0.01)
