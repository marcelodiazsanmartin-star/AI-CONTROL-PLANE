"""Security utilities for CONTROL TOWER: fail-closed validation and isolation."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

MAX_FILE_SIZE_BYTES = 1_000_000  # 1 MB bounded file read
MAX_JSON_DEPTH = 30
SECRET_PATTERNS = [
    re.compile(r"ghp_[a-zA-Z0-9]{20,}", re.IGNORECASE),
    re.compile(r"github_pat_[a-zA-Z0-9_]{20,}", re.IGNORECASE),
    re.compile(r"bearer\s+[a-zA-Z0-9._\-]+", re.IGNORECASE),
    re.compile(r"token\s*=\s*['\"][^'\"]+['\"]", re.IGNORECASE),
    re.compile(r"private[_-]?key", re.IGNORECASE),
]

ALLOWED_LOOPBACK_HOSTS = frozenset(
    {"127.0.0.1", "localhost", "::1", "[::1]"}
)


class SecurityError(Exception):
    """Raised when a security boundary is violated."""


def validate_host_header(host_header: str | None, server_port: int | None = None) -> bool:
    """Validate the Host HTTP header against the strict loopback allowlist."""
    if not host_header:
        return False

    raw = host_header.strip()
    if ":" in raw:
        if raw.startswith("[") and "]" in raw:
            hostname = raw[1:raw.rfind("]")]
            port_str = raw[raw.rfind(":") + 1:]
        else:
            hostname, _, port_str = raw.rpartition(":")

        if not port_str.isdigit():
            return False
        if server_port is not None and int(port_str) != server_port:
            return False
    else:
        hostname = raw.strip("[]")

    return hostname.lower() in ALLOWED_LOOPBACK_HOSTS


def sanitize_error(error: Exception | str) -> str:
    """Sanitize error messages to remove sensitive tokens or sensitive paths."""
    text = str(error)
    for pattern in SECRET_PATTERNS:
        text = pattern.sub("[REDACTED_SECRET]", text)
    text = re.sub(r"[A-Za-z]:\\[^\s:\"']+", "[REDACTED_PATH]", text)
    text = re.sub(r"/(?:home|Users)/[^\s:\"']+", "[REDACTED_PATH]", text)
    return text[:300]


def check_json_depth(obj: Any, current_depth: int = 0) -> None:
    """Defensively reject deeply nested / recursive JSON objects."""
    if current_depth > MAX_JSON_DEPTH:
        raise SecurityError(f"JSON depth exceeded limit of {MAX_JSON_DEPTH}")
    if isinstance(obj, dict):
        for val in obj.values():
            check_json_depth(val, current_depth + 1)
    elif isinstance(obj, (list, tuple)):
        for item in obj:
            check_json_depth(item, current_depth + 1)


def safe_read_json(
    file_path: Path,
    base_dir: Path | None = None,
    allowlist: set[str] | frozenset[str] | None = None,
) -> dict[str, Any]:
    """Defensively read and parse JSON file within allowlisted base directory."""
    if base_dir is not None:
        resolved_base = base_dir.resolve()
        try:
            resolved_target = file_path.resolve()
        except Exception as e:
            raise SecurityError(f"Failed to resolve file path: {sanitize_error(e)}") from e

        try:
            resolved_target.relative_to(resolved_base)
        except ValueError as e:
            raise SecurityError(f"Path escape detected: {sanitize_error(file_path)}") from e

        if allowlist is not None:
            rel_str = str(resolved_target.relative_to(resolved_base)).replace("\\", "/")
            if rel_str not in allowlist:
                raise SecurityError(f"File not in allowlist: {rel_str}")
    else:
        resolved_target = file_path.resolve()

    if not resolved_target.exists():
        raise FileNotFoundError(f"File does not exist: {file_path.name}")
    if not resolved_target.is_file():
        raise SecurityError(f"Target is not a regular file: {file_path.name}")

    stat_result = resolved_target.stat()
    if stat_result.st_size > MAX_FILE_SIZE_BYTES:
        raise SecurityError(
            f"File size {stat_result.st_size} exceeds maximum {MAX_FILE_SIZE_BYTES} bytes"
        )

    with open(resolved_target, "r", encoding="utf-8") as f:
        content = f.read(MAX_FILE_SIZE_BYTES + 1)
        if len(content) > MAX_FILE_SIZE_BYTES:
            raise SecurityError("File content exceeded maximum allowed length")

    try:
        data = json.loads(content)
    except Exception as e:
        raise SecurityError(f"Malformed JSON: {sanitize_error(e)}") from e

    if not isinstance(data, dict):
        raise SecurityError("JSON root must be an object")

    check_json_depth(data)
    return data
