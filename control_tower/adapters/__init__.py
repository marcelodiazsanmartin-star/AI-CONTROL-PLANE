"""Deterministic read-only adapter suite for CONTROL TOWER."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Sequence

from control_tower.adapters.base import BaseAdapter
from control_tower.adapters.control_plane import ControlPlaneAdapter
from control_tower.adapters.directive_channel import DirectiveChannelAdapter
from control_tower.adapters.github_ci import GitHubCIAdapter
from control_tower.adapters.micro import MicroAdapter
from control_tower.adapters.oracle import OracleAdapter
from control_tower.adapters.self_health import ControlTowerSelfAdapter
from control_tower.models import AdapterResult
from control_tower.resilience import ResilientAdapterExecutor, resilient_executor


def get_default_adapters(root_dir: Path | None = None) -> tuple[BaseAdapter, ...]:
    """Return the canonical suite of read-only adapters."""
    return (
        ControlTowerSelfAdapter(root_dir=root_dir),
        ControlPlaneAdapter(root_dir=root_dir),
        DirectiveChannelAdapter(root_dir=root_dir),
        OracleAdapter(root_dir=root_dir),
        MicroAdapter(root_dir=root_dir),
        GitHubCIAdapter(root_dir=root_dir),
    )


def fetch_all_adapters(
    adapters: Sequence[BaseAdapter],
    now: datetime,
    executor: ResilientAdapterExecutor | None = None,
) -> dict[str, AdapterResult]:
    """Execute all adapters with resilient timeout, circuit breaker, retry, and failure isolation."""
    exec_inst = executor or resilient_executor
    results: dict[str, AdapterResult] = {}
    for adapter in adapters:
        result = exec_inst.execute_adapter(
            adapter_func=adapter.fetch,
            source_id=adapter.source_id,
            source_kind=adapter.source_kind,
            source_ref=adapter.source_ref,
            freshness_sla_seconds=adapter.freshness_sla_seconds,
            now=now,
        )
        results[adapter.source_id] = result
    return results


__all__ = [
    "BaseAdapter",
    "ControlPlaneAdapter",
    "ControlTowerSelfAdapter",
    "DirectiveChannelAdapter",
    "GitHubCIAdapter",
    "MicroAdapter",
    "OracleAdapter",
    "fetch_all_adapters",
    "get_default_adapters",
]
