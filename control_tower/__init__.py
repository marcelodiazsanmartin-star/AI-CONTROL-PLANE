"""CONTROL TOWER: Read-only operational observability and control tower service."""

from __future__ import annotations

from control_tower.preflight import run_preflight
from control_tower.schema import CURRENT_SCHEMA_VERSION, validate_schema_version
from control_tower.service import ControlTowerService

__version__ = "3.0.0"
__all__ = [
    "CURRENT_SCHEMA_VERSION",
    "ControlTowerService",
    "run_preflight",
    "validate_schema_version",
]
