"""Security utilities for CONTROL TOWER: fail-closed validation and bounded read isolation."""

from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any

MAX_FILE_SIZE_BYTES = 1_000_000  # 1 MB bounded file read
MAX_JSONL_LINE_BYTES = 65_536  # 64 KB per JSONL line
MAX_JSONL_LINES = 500  # 500 lines max in jsonl
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


def safe_resolve_path(
    file_path: Path,
    base_dir: Path | None = None,
    allowlist: set[str] | frozenset[str] | None = None,
) -> Path:
    """Validate that path does not escape base_dir and matches allowlist."""
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
            # Check direct match or directory prefix match
            matched = rel_str in allowlist or any(
                allowed.endswith("/*") and rel_str.startswith(allowed[:-2] + "/")
                or allowed.endswith("/*.json") and rel_str.startswith(allowed[:-7] + "/") and rel_str.endswith(".json")
                for allowed in allowlist
            )
            if not matched:
                raise SecurityError(f"File not in allowlist: {rel_str}")
        return resolved_target
    return file_path.resolve()


def safe_read_json(
    file_path: Path,
    base_dir: Path | None = None,
    allowlist: set[str] | frozenset[str] | None = None,
) -> dict[str, Any]:
    """Defensively read and parse JSON file within allowlisted base directory."""
    resolved_target = safe_resolve_path(file_path, base_dir, allowlist)

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


def safe_read_jsonl(
    file_path: Path,
    base_dir: Path | None = None,
    allowlist: set[str] | frozenset[str] | None = None,
    max_lines: int = MAX_JSONL_LINES,
    max_line_bytes: int = MAX_JSONL_LINE_BYTES,
) -> list[dict[str, Any]]:
    """Defensively read and parse bounded JSONL file."""
    resolved_target = safe_resolve_path(file_path, base_dir, allowlist)

    if not resolved_target.exists():
        return []
    if not resolved_target.is_file():
        raise SecurityError(f"Target is not a regular file: {file_path.name}")

    stat_result = resolved_target.stat()
    if stat_result.st_size > MAX_FILE_SIZE_BYTES:
        raise SecurityError(
            f"File size {stat_result.st_size} exceeds maximum {MAX_FILE_SIZE_BYTES} bytes"
        )

    records: list[dict[str, Any]] = []
    with open(resolved_target, "r", encoding="utf-8") as f:
        for line_no, raw_line in enumerate(f, start=1):
            if line_no > max_lines:
                break
            if len(raw_line.encode("utf-8")) > max_line_bytes:
                raise SecurityError(f"JSONL line {line_no} exceeded max line length {max_line_bytes}")
            stripped = raw_line.strip()
            if not stripped:
                continue
            try:
                data = json.loads(stripped)
            except Exception as e:
                raise SecurityError(f"Malformed JSONL at line {line_no}: {sanitize_error(e)}") from e
            if not isinstance(data, dict):
                raise SecurityError(f"JSONL line {line_no} root must be an object")
            check_json_depth(data)
            records.append(data)
    return records


def safe_list_dir_files(
    dir_path: Path,
    base_dir: Path,
    allowlist: set[str] | frozenset[str] | None = None,
    max_files: int = 20,
    extension: str = ".json",
) -> list[Path]:
    """Safely list bounded number of files in a directory within base_dir."""
    resolved_dir = safe_resolve_path(dir_path, base_dir, allowlist)
    if not resolved_dir.exists() or not resolved_dir.is_dir():
        return []

    files = [
        p for p in resolved_dir.iterdir()
        if p.is_file() and p.name.endswith(extension)
    ]
    # Sort by modification time descending
    files.sort(key=lambda p: p.stat().st_mtime, reverse=True)
    return files[:max_files]
