"""CONTROL TOWER local application self-health adapter."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from control_tower.adapters.base import BaseAdapter
from control_tower.models import AdapterResult, SourceStatus


class ControlTowerSelfAdapter(BaseAdapter):
    """Read-only adapter for CONTROL TOWER application self-health and CT-01 readiness."""

    def __init__(
        self,
        freshness_sla_seconds: float = 60.0,
        root_dir: Path | None = None,
    ) -> None:
        super().__init__(
            source_id="control-tower-self",
            source_kind="CONTROL_TOWER_APPLICATION_HEALTH",
            source_ref="control_tower/api.py",
            freshness_sla_seconds=freshness_sla_seconds,
            root_dir=root_dir,
        )

    def _fetch_impl(self, now: datetime) -> AdapterResult:
        payload = {
            "application": "CONTROL TOWER",
            "version": "CT-01R1",
            "stage": "OPERATIONAL_READONLY",
            "loopback_only": True,
            "read_only": True,
            "allowed_origins": ["http://localhost:3000", "http://127.0.0.1:3000"],
            "host_header_validation": "STRICT_LOOPBACK",
            "fail_closed_evidence": True,
            "runtime_normalization": True,
            "adapter_isolation": True,
            "stale_precedence": True,
            "last_known_status": "HEALTHY",
        }

        return AdapterResult(
            source_id=self.source_id,
            source_kind=self.source_kind,
            source_ref=self.source_ref,
            fetched_at=now.isoformat(),
            observed_at=now.isoformat(),
            freshness_sla_seconds=self.freshness_sla_seconds,
            status=SourceStatus.HEALTHY,
            adapter_health=SourceStatus.HEALTHY,
            truth_status=SourceStatus.HEALTHY,
            last_known_status="HEALTHY",
            last_known_conflict=False,
            last_known_observed_at=now.isoformat(),
            payload=payload,
            provenance="stage:CT-01R1",
        )
