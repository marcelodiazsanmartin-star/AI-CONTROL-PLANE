"""Base read-only adapter contract for CONTROL TOWER CT-01R1."""

from __future__ import annotations

from abc import ABC, abstractmethod
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from control_tower.models import AdapterResult, SourceStatus
from control_tower.security import sanitize_error


class BaseAdapter(ABC):
    """Abstract base class for all deterministic read-only adapters."""

    def __init__(
        self,
        source_id: str,
        source_kind: str,
        source_ref: str,
        freshness_sla_seconds: float = 300.0,
        root_dir: Path | None = None,
    ) -> None:
        self.source_id = source_id
        self.source_kind = source_kind
        self.source_ref = source_ref
        self.freshness_sla_seconds = freshness_sla_seconds
        self.root_dir = (root_dir or Path(__file__).resolve().parents[2]).resolve()

    def fetch(self, now: datetime) -> AdapterResult:
        """Safely fetch source state, isolating any adapter exception fail-closed."""
        fetch_time = now.isoformat()
        try:
            return self._fetch_impl(now)
        except Exception as e:
            return AdapterResult(
                source_id=self.source_id,
                source_kind=self.source_kind,
                source_ref=self.source_ref,
                fetched_at=fetch_time,
                observed_at=None,
                freshness_sla_seconds=self.freshness_sla_seconds,
                status=SourceStatus.UNKNOWN,
                adapter_health=SourceStatus.UNKNOWN,
                truth_status=SourceStatus.UNKNOWN,
                last_known_status=None,
                last_known_conflict=None,
                last_known_observed_at=None,
                payload={},
                provenance=None,
                error_code=type(e).__name__,
                error_detail=sanitize_error(e),
            )

    @abstractmethod
    def _fetch_impl(self, now: datetime) -> AdapterResult:
        """Subclasses implement specific read-only data extraction."""
        raise NotImplementedError
