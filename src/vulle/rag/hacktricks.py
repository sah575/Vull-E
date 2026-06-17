import fnmatch
import hashlib
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from uuid import NAMESPACE_URL, uuid5

DEFAULT_CONFIG_PATH = Path("config/hacktricks_sources.yml")
HACKTRICKS_SOURCE_TYPE = "external_pentest_methodology"
HACKTRICKS_SOURCE_NAME = "hacktricks"
HACKTRICKS_SOURCE_PRIORITY = 0.50

DEFAULT_ALLOW_PATTERNS = [
    "**/*api*.md",
    "**/*auth*.md",
    "**/*authorization*.md",
    "**/*idor*.md",
    "**/*bola*.md",
    "**/*business*logic*.md",
    "**/*file*upload*.md",
    "**/*path*traversal*.md",
    "**/*ssrf*.md",
    "**/*sql*injection*.md",
    "**/*nosql*.md",
    "**/*command*injection*.md",
    "**/*template*injection*.md",
    "**/*xxe*.md",
    "**/*xss*.md",
    "**/*csrf*.md",
    "**/*cors*.md",
    "**/*jwt*.md",
    "**/*oauth*.md",
    "**/*oidc*.md",
    "**/*graphql*.md",
    "**/*websocket*.md",
    "**/*mass*assignment*.md",
    "**/*race*.md",
    "**/*replay*.md",
    "**/*rate*limit*.md",
    "**/*request*smuggling*.md",
    "**/*deserialization*.md",
    "**/*open*redirect*.md",
    "**/*http*parameter*pollution*.md",
    "**/pentesting-web/**/*.md",
    "**/network-services-pentesting/pentesting-web/**/*.md",
]
DEFAULT_EXCLUDE_PATTERNS = [
    "**/.git/**",
    "**/img/**",
    "**/images/**",
    "**/assets/**",
    "**/binary-exploitation/**",
    "**/reversing/**",
    "**/forensics/**",
    "**/generic-methodologies-and-resources/**ctf**",
    "**/windows-hardening/**",
    "**/linux-hardening/**",
    "**/linux-unix/**",
    "**/windows/**",
    "**/active-directory/**",
    "**/cloud-security/**",
    "**/kubernetes/**",
    "**/wireless/**",
    "**/*privilege*escalation*.md",
    "**/*privesc*.md",
    "**/*forensic*.md",
    "**/*ctf*.md",
]
DOMAIN_KEYWORDS = {
    "access_control": ["authorization", "access control", "idor", "bola", "permission"],
    "authentication": ["authentication", "login", "password", "mfa", "otp"],
    "session_management": ["session", "cookie", "csrf token", "refresh token"],
    "business_logic": ["business logic", "workflow", "approve", "payment", "limit"],
    "file_upload": ["file upload", "upload", "extension", "mime", "multipart"],
    "ssrf": ["ssrf", "server side request forgery", "webhook", "callback"],
    "injection": ["injection", "sql injection", "nosql", "command injection", "xxe"],
    "graphql": ["graphql", "mutation", "resolver", "introspection"],
    "jwt": ["jwt", "jws", "jwe", "json web token"],
    "oauth": ["oauth", "oidc", "openid connect", "authorization code"],
    "websocket": ["websocket", "socket.io"],
    "race_replay": ["race condition", "replay", "idempotency", "concurrent"],
    "mass_assignment": ["mass assignment", "object property", "hidden field"],
    "rate_limiting": ["rate limit", "throttle", "brute force"],
    "request_smuggling": ["request smuggling", "http desync", "cl.te", "te.cl"],
    "cors": ["cors", "access-control-allow-origin"],
    "xss": ["xss", "cross-site scripting"],
    "csrf": ["csrf", "cross-site request forgery"],
    "deserialization": ["deserialization", "deserialize", "pickle", "java serialized"],
    "path_traversal": ["path traversal", "directory traversal", "../"],
}


@dataclass
class HackTricksConfig:
    enabled: bool = True
    allow_path_patterns: list[str] = field(default_factory=lambda: list(DEFAULT_ALLOW_PATTERNS))
    exclude_path_patterns: list[str] = field(default_factory=lambda: list(DEFAULT_EXCLUDE_PATTERNS))
    source_priority: float = HACKTRICKS_SOURCE_PRIORITY
    minimum_content_chars: int = 120
    language: str = "en"
    domain_keywords: dict[str, list[str]] = field(
        default_factory=lambda: {key: list(value) for key, value in DOMAIN_KEYWORDS.items()}
    )


@dataclass
class HackTricksLoadReport:
    scanned_files: int = 0
    accepted_files: int = 0
    excluded_files: int = 0
    chunk_count: int = 0
    deduplicated_chunks: int = 0
    domain_counts: dict[str, int] = field(default_factory=dict)
    commit_sha: str = "unknown"
    warnings: list[str] = field(default_factory=list)


@dataclass
class HackTricksDocument:
    path: Path
    relative_path: str
    text: str
    title: str
    security_domain: str


def load_hacktricks_config(path: Path = DEFAULT_CONFIG_PATH) -> HackTricksConfig:
    config = HackTricksConfig()
    if not path.is_file():
        return config
    raw = _parse_simple_yaml(path.read_text(encoding="utf-8"))
    if "enabled" in raw:
        config.enabled = _as_bool(raw["enabled"])
    if "allow_path_patterns" in raw:
        config.allow_path_patterns = [str(item) for item in raw["allow_path_patterns"]]
    if "exclude_path_patterns" in raw:
        config.exclude_path_patterns = [str(item) for item in raw["exclude_path_patterns"]]
    if "source_priority" in raw:
        config.source_priority = float(raw["source_priority"])
    if "minimum_content_chars" in raw:
        config.minimum_content_chars = int(raw["minimum_content_chars"])
    if "language" in raw:
        config.language = str(raw["language"])
    if isinstance(raw.get("security_domain_mappings"), dict):
        config.domain_keywords.update(
            {
                str(key): [str(item) for item in value]
                for key, value in raw["security_domain_mappings"].items()
                if isinstance(value, list)
            }
        )
    return config


def select_hacktricks_documents(
    root: Path,
    *,
    config: HackTricksConfig | None = None,
    max_file_size_mb: int = 10,
    max_total_files: int = 10000,
) -> tuple[list[HackTricksDocument], HackTricksLoadReport]:
    config = config or load_hacktricks_config()
    report = HackTricksLoadReport(commit_sha=git_commit_sha(root))
    if not root.exists() or not root.is_dir():
        raise FileNotFoundError(f"HackTricks path does not exist or is not a directory: {root}")
    if not config.enabled:
        report.warnings.append("HackTricks source profile is disabled by config.")
        return [], report
    if report.commit_sha == "unknown":
        report.warnings.append("HackTricks Git commit SHA could not be determined; using unknown.")

    documents: list[HackTricksDocument] = []
    root_resolved = root.resolve()
    for file_path in sorted(root.rglob("*.md")):
        report.scanned_files += 1
        if report.scanned_files > max_total_files:
            report.warnings.append(f"Maximum HackTricks file count exceeded: {max_total_files}")
            break
        if file_path.is_symlink() or not _is_inside(file_path, root_resolved):
            report.excluded_files += 1
            continue
        relative_path = file_path.resolve().relative_to(root_resolved).as_posix()
        try:
            size = file_path.stat().st_size
        except OSError as exc:
            report.excluded_files += 1
            report.warnings.append(
                f"Skipped unreadable HackTricks file {relative_path}: "
                f"{exc.__class__.__name__}"
            )
            continue
        if size > max_file_size_mb * 1024 * 1024:
            report.excluded_files += 1
            report.warnings.append(f"Skipped oversized HackTricks file: {relative_path}")
            continue
        if _matches(relative_path, config.exclude_path_patterns) or not _matches(
            relative_path,
            config.allow_path_patterns,
        ):
            report.excluded_files += 1
            continue
        try:
            text = file_path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            report.excluded_files += 1
            report.warnings.append(f"Skipped non-UTF-8 HackTricks file: {relative_path}")
            continue
        cleaned = clean_hacktricks_markdown(text)
        if len(cleaned.strip()) < config.minimum_content_chars:
            report.excluded_files += 1
            continue
        title = _title_for(relative_path, cleaned)
        documents.append(
            HackTricksDocument(
                path=file_path,
                relative_path=relative_path,
                text=cleaned,
                title=title,
                security_domain=classify_security_domain(relative_path, title, cleaned, config),
            )
        )
    report.accepted_files = len(documents)
    return documents, report


def classify_security_domain(
    relative_path: str,
    title: str,
    text: str,
    config: HackTricksConfig | None = None,
) -> str:
    domains = classify_security_domains(relative_path, title, text, config)
    return domains[0] if domains else "general_web_security"


def classify_security_domains(
    relative_path: str,
    title: str,
    text: str,
    config: HackTricksConfig | None = None,
) -> list[str]:
    config = config or load_hacktricks_config()
    haystack = f"{relative_path} {title} {text[:2000]}".lower().replace("-", " ")
    scored: list[tuple[int, str]] = []
    for domain, keywords in config.domain_keywords.items():
        score = sum(1 for keyword in keywords if keyword.lower() in haystack)
        if score > 0:
            scored.append((score, domain))
    if not scored:
        return ["general_web_security"]
    return [
        domain
        for _, domain in sorted(
            scored,
            key=lambda item: (-item[0], item[1]),
        )
    ]


def hacktricks_chunk_id(
    *,
    source_name: str,
    relative_path: str,
    heading_path: list[str],
    content: str,
    knowledge_base_id: str,
    tenant_id: str = "default",
    environment: str = "preprod",
    index_schema_version: int = 2,
) -> str:
    digest = hashlib.sha256(content.encode("utf-8")).hexdigest()
    identity = "|".join(
        [
            str(index_schema_version),
            source_name,
            tenant_id,
            environment,
            knowledge_base_id,
            relative_path,
            " > ".join(heading_path),
            digest,
        ]
    )
    return str(uuid5(NAMESPACE_URL, identity))


def git_commit_sha(root: Path) -> str:
    try:
        result = subprocess.run(
            ["git", "-C", str(root), "rev-parse", "HEAD"],
            check=False,
            capture_output=True,
            text=True,
            timeout=3,
        )
    except (OSError, subprocess.SubprocessError):
        return "unknown"
    sha = result.stdout.strip()
    if result.returncode != 0 or not sha:
        return "unknown"
    return sha


def clean_hacktricks_markdown(text: str) -> str:
    drop_markers = (
        "## HackTricks Automatic Commands",
        "## HackTricks Cloud",
        "## HackTricks Training",
        "## HackTricks",
        "## Authors",
        "## Social",
        "## Sponsored",
    )
    lines: list[str] = []
    dropping = False
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("![](") or stripped.startswith("<figure"):
            continue
        if any(stripped.startswith(marker) for marker in drop_markers):
            dropping = True
            continue
        if dropping and stripped.startswith("#"):
            dropping = False
        if not dropping:
            lines.append(line)
    return "\n".join(lines).strip()


def is_low_value_chunk(text: str, *, minimum_chars: int) -> bool:
    stripped = text.strip()
    if len(stripped) < minimum_chars:
        return True
    lines = [line.strip() for line in stripped.splitlines() if line.strip()]
    url_lines = sum(
        1 for line in lines if line.startswith(("http://", "https://"))
    )
    return bool(lines and url_lines / len(lines) > 0.6)


def _matches(relative_path: str, patterns: list[str]) -> bool:
    lowered = relative_path.lower()
    basename = Path(lowered).name
    return any(
        fnmatch.fnmatch(lowered, lowered_pattern)
        or fnmatch.fnmatch(basename, _basename_pattern(lowered_pattern))
        for lowered_pattern in (pattern.lower() for pattern in patterns)
    )


def _basename_pattern(pattern: str) -> str:
    while pattern.startswith("**/"):
        pattern = pattern.removeprefix("**/")
    return pattern


def _is_inside(path: Path, root_resolved: Path) -> bool:
    try:
        path.resolve().relative_to(root_resolved)
    except ValueError:
        return False
    return True


def _title_for(relative_path: str, text: str) -> str:
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("#"):
            return stripped.lstrip("#").strip() or Path(relative_path).stem
    return Path(relative_path).stem.replace("-", " ").title()


def _parse_simple_yaml(text: str) -> dict[str, Any]:
    result: dict[str, Any] = {}
    current_list: str | None = None
    current_mapping: str | None = None
    current_nested_list: str | None = None
    for raw_line in text.splitlines():
        if not raw_line.strip() or raw_line.lstrip().startswith("#"):
            continue
        indent = len(raw_line) - len(raw_line.lstrip(" "))
        line = raw_line.strip()
        if indent == 0 and line.endswith(":"):
            key = line[:-1]
            result[key] = []
            current_list = key
            current_mapping = key if key == "security_domain_mappings" else None
            current_nested_list = None
            if current_mapping:
                result[key] = {}
            continue
        if indent == 0 and ":" in line:
            key, value = line.split(":", 1)
            result[key.strip()] = _scalar(value.strip())
            current_list = None
            current_mapping = None
            current_nested_list = None
            continue
        if current_mapping and indent == 2 and line.endswith(":"):
            current_nested_list = line[:-1]
            result[current_mapping][current_nested_list] = []
            continue
        if line.startswith("- "):
            value = _scalar(line[2:].strip())
            if current_mapping and current_nested_list:
                result[current_mapping][current_nested_list].append(value)
            elif current_list:
                result[current_list].append(value)
    return result


def _scalar(value: str) -> Any:
    value = value.strip().strip('"').strip("'")
    if value.lower() in {"true", "false"}:
        return _as_bool(value)
    try:
        if "." in value:
            return float(value)
        return int(value)
    except ValueError:
        return value


def _as_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in {"1", "true", "yes", "on"}
