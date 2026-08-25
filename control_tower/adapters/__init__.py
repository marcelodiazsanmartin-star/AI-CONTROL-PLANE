"""Deterministic read-only adapter suite for CONTROL TOWER CT-01."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Sequence

from control_tower.adapters.base import BaseAdapter
from control_tower.adapters.control_plane import ControlPlaneAdapter
from control_tower.adapters.github_ci import GitHubCIAdapter
from control_tower.adapters.micro import MicroAdapter
from control_tower.adapters.oracle import OracleAdapter
from control_tower.adapters.self_health import ControlTowerSelfAdapter
from control_tower.models import AdapterResult


def get_default_adapters(root_dir: Path | None = None) -> tuple[BaseAdapter, ...]:
    """Return the canonical suite of read-only adapters."""
    return (
        ControlTowerSelfAdapter(root_dir=root_dir),
        ControlPlaneAdapter(root_dir=root_dir),
        OracleAdapter(root_dir=root_dir),
        MicroAdapter(root_dir=root_dir),
        GitHubCIAdapter(root_dir=root_dir),
    )


def fetch_all_adapters(
    adapters: Sequence[BaseAdapter],
    now: datetime,
) -> dict[str, AdapterResult]:
    """Execute all adapters with complete failure isolation."""
    results: dict[str, AdapterResult] = {}
    for adapter in adapters:
        # Each adapter.fetch() already isolates exceptions fail-closed
        result = adapter.fetch(now)
        results[adapter.source_id] = result
    return results


__all__ = [
    "BaseAdapter",
    "ControlPlaneAdapter",
    "ControlTowerSelfAdapter",
    "GitHubCIAdapter",
    "MicroAdapter",
    "OracleAdapter",
    "fetch_all_adapters",
    "get_default_adapters",
]
