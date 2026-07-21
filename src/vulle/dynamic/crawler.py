import re
import time
import uuid
import xml.etree.ElementTree as ET
from datetime import UTC, datetime
from typing import Literal

from vulle.audit import emit_audit_event
from vulle.config import Settings
from vulle.dynamic.adb import AdbClient
from vulle.dynamic.models import ClickableElement, CrawlSessionConfig, CrawlSessionReport
from vulle.errors import AdbCommandError, AdbTimeoutError

_BOUNDS_PATTERN = re.compile(r"\[(-?\d+),(-?\d+)\]\[(-?\d+),(-?\d+)\]")

StopReason = Literal["max_actions_reached", "kill_switch", "no_safe_candidates", "adb_error"]


def parse_clickable_elements(xml_text: str) -> list[ClickableElement]:
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return []
    elements = []
    for node in root.iter("node"):
        if node.get("clickable") != "true":
            continue
        elements.append(
            ClickableElement(
                text=node.get("text", ""),
                content_desc=node.get("content-desc", ""),
                resource_id=node.get("resource-id", ""),
                class_name=node.get("class", ""),
                bounds=node.get("bounds", ""),
            )
        )
    return elements


def is_denylisted(element: ClickableElement, denylist_keywords: list[str]) -> bool:
    searchable = f"{element.text} {element.content_desc} {element.resource_id}".lower()
    if not searchable.strip():
        # Fail-closed: nothing readable to judge -> never a safe tap candidate.
        return True
    return any(keyword.lower() in searchable for keyword in denylist_keywords)


def center_of(bounds: str) -> tuple[int, int] | None:
    match = _BOUNDS_PATTERN.match(bounds)
    if not match:
        return None
    x1, y1, x2, y2 = (int(value) for value in match.groups())
    return (x1 + x2) // 2, (y1 + y2) // 2


def identity_of(element: ClickableElement) -> tuple[str, str]:
    return (element.resource_id, element.text)


def run_crawl_session(
    config: CrawlSessionConfig,
    adb: AdbClient,
    settings: Settings,
) -> CrawlSessionReport:
    session_id = str(uuid.uuid4())
    started_at = datetime.now(UTC).isoformat()
    actions_taken = 0
    tapped_identities: set[tuple[str, str]] = set()
    screenshots: list[str] = []
    denylist_blocked_count = 0
    stop_reason: StopReason = "max_actions_reached"

    _audit(settings, "crawl.session_start", session_id=session_id, package=config.package)

    try:
        adb.launch_app(config.package)
        actions_taken += 1

        while actions_taken < config.max_actions:
            if config.kill_switch_path.exists():
                stop_reason = "kill_switch"
                break

            xml_text = adb.dump_ui()
            actions_taken += 1
            if actions_taken >= config.max_actions:
                break

            elements = parse_clickable_elements(xml_text)
            candidates = [e for e in elements if not is_denylisted(e, config.denylist_keywords)]
            denylist_blocked_count += len(elements) - len(candidates)
            if not candidates:
                stop_reason = "no_safe_candidates"
                break

            target = _choose_next_element(candidates, tapped_identities)
            center = center_of(target.bounds)
            if center is None:
                stop_reason = "adb_error"
                break

            if config.kill_switch_path.exists():
                stop_reason = "kill_switch"
                break

            adb.tap(*center)
            actions_taken += 1
            tapped_identities.add(identity_of(target))

            if actions_taken < config.max_actions:
                screenshot_path = config.session_dir / f"{actions_taken:04d}.png"
                adb.screenshot(screenshot_path)
                actions_taken += 1
                screenshots.append(str(screenshot_path))

            time.sleep(config.tap_settle_seconds)
    except (AdbCommandError, AdbTimeoutError):
        stop_reason = "adb_error"

    ended_at = datetime.now(UTC).isoformat()
    _audit(
        settings,
        "crawl.session_end",
        session_id=session_id,
        actions_taken=actions_taken,
        stop_reason=stop_reason,
    )
    return CrawlSessionReport(
        session_id=session_id,
        package=config.package,
        started_at=started_at,
        ended_at=ended_at,
        actions_taken=actions_taken,
        stop_reason=stop_reason,
        screenshots=screenshots,
        denylist_blocked_count=denylist_blocked_count,
    )


def _choose_next_element(
    candidates: list[ClickableElement],
    tapped_identities: set[tuple[str, str]],
) -> ClickableElement:
    for element in candidates:
        if identity_of(element) not in tapped_identities:
            return element
    return candidates[0]


def _audit(settings: Settings, action: str, **fields: object) -> None:
    emit_audit_event(
        settings.vulle_audit_log,
        {"action": action, **fields},
        pii_mode=settings.pii_redaction_mode,
    )
