"""Schema versioning and validation for CONTROL TOWER CT-03."""

from __future__ import annotations

import re
from typing import Any

from control_tower.security import SecurityError, sanitize_error

CURRENT_SCHEMA_VERSION = "control-tower.v3.operational"

SUPPORTED_SCHEMA_VERSIONS = frozenset({
    "control-tower.phase0.v1",
    "control-tower.phase1.r1",
    "control-tower.phase2a.v1",
    "control-tower.v3.operational",
    "1.0",
    "1.0.0",
    "2.0",
    "2.0.0",
})

VERSION_REGEX = re.compile(r"^[a-zA-Z0-9.\-_]{1,64}$")


def validate_schema_version(version_str: str | None) -> bool:
    """Validate that schema version matches standard format and is supported."""
    if not version_str or not isinstance(version_str, str):
        return False
    if not VERSION_REGEX.match(version_str.strip()):
        return False
    return version_str.strip() in SUPPORTED_SCHEMA_VERSIONS


def assert_supported_schema(version_str: str | None, context_label: str = "upstream") -> None:
    """Raise SecurityError if schema version is unsupported or malformed."""
    if not version_str:
        return
    if not isinstance(version_str, str) or not VERSION_REGEX.match(version_str.strip()):
        raise SecurityError(f"Malformed schema version in {context_label}: {sanitize_error(version_str)}")
    if version_str.strip() not in SUPPORTED_SCHEMA_VERSIONS:
        raise SecurityError(f"Unsupported future schema version in {context_label}: {sanitize_error(version_str)}")
