import subprocess
import time
from collections.abc import Callable
from pathlib import Path
from typing import TypeVar

from vulle.apk.workspace import run_with_timeout
from vulle.audit import emit_audit_event
from vulle.config import Settings
from vulle.dynamic.limits import ADB_DUMP_RETRY_COUNT, MAX_SCREENSHOT_BYTES
from vulle.errors import AdbCommandError, AdbTimeoutError

T = TypeVar("T")

_DUMP_DEVICE_PATH = "/sdcard/vulle_window_dump.xml"


class AdbClient:
    """Thin subprocess wrapper around ``adb`` - the only place adb is invoked."""

    def __init__(self, settings: Settings, *, device_serial: str | None = None) -> None:
        self._settings = settings
        self._device_serial = device_serial

    def launch_app(self, package: str) -> None:
        self._run_audited(
            "adb.launch_app",
            {"package": package},
            lambda: self._run(
                ["shell", "monkey", "-p", package, "-c", "android.intent.category.LAUNCHER", "1"]
            ),
        )

    def dump_ui(self) -> str:
        def _dump() -> str:
            last_error: Exception = AdbCommandError("uiautomator dump failed")
            for _ in range(ADB_DUMP_RETRY_COUNT + 1):
                self._run(["shell", "uiautomator", "dump", _DUMP_DEVICE_PATH])
                result = self._run(["shell", "cat", _DUMP_DEVICE_PATH])
                xml = result.stdout.decode("utf-8", errors="replace")
                if "<hierarchy" in xml:
                    return xml
                last_error = AdbCommandError("uiautomator dump did not produce a hierarchy")
            raise last_error

        return self._run_audited("adb.dump_ui", {}, _dump)

    def tap(self, x: int, y: int) -> None:
        self._run_audited(
            "adb.tap",
            {"x": x, "y": y},
            lambda: self._run(["shell", "input", "tap", str(x), str(y)]),
        )

    def screenshot(self, dest: Path) -> bytes:
        def _capture() -> bytes:
            result = self._run(["exec-out", "screencap", "-p"])
            data = result.stdout
            if len(data) > MAX_SCREENSHOT_BYTES:
                raise AdbCommandError(f"Screenshot exceeded {MAX_SCREENSHOT_BYTES} bytes")
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes(data)
            return data

        return self._run_audited("adb.screenshot", {"dest": str(dest)}, _capture)

    def _run_audited(
        self,
        action: str,
        extra: dict[str, object],
        fn: Callable[[], T],
    ) -> T:
        started = time.monotonic()
        try:
            result = run_with_timeout(fn, timeout=self._settings.adb_command_timeout_seconds)
        except Exception as exc:
            self._audit(action, extra, result="error", error=str(exc), started=started)
            raise
        self._audit(action, extra, result="ok", error=None, started=started)
        return result

    def _audit(
        self,
        action: str,
        extra: dict[str, object],
        *,
        result: str,
        error: str | None,
        started: float,
    ) -> None:
        event: dict[str, object] = {
            "action": action,
            **extra,
            "result": result,
            "duration_ms": int((time.monotonic() - started) * 1000),
        }
        if error is not None:
            event["error"] = error
        emit_audit_event(
            self._settings.vulle_audit_log,
            event,
            pii_mode=self._settings.pii_redaction_mode,
        )

    def _run(self, args: list[str]) -> subprocess.CompletedProcess[bytes]:
        command = [self._settings.adb_binary]
        if self._device_serial:
            command.extend(["-s", self._device_serial])
        command.extend(args)
        try:
            result = subprocess.run(
                command,
                capture_output=True,
                timeout=self._settings.adb_command_timeout_seconds,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise AdbTimeoutError(f"adb command timed out: {' '.join(args)}") from exc
        if result.returncode != 0:
            stderr = result.stderr.decode("utf-8", errors="replace")
            raise AdbCommandError(
                f"adb command failed (exit {result.returncode}): {' '.join(args)}: {stderr}"
            )
        return result
