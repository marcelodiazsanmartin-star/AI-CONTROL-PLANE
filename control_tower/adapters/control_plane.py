"""AI-CONTROL-PLANE state adapter for CONTROL TOWER CT-01R1."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from control_tower.adapters.base import BaseAdapter
from control_tower.models import AdapterResult, SourceStatus
from control_tower.security import safe_read_json, sanitize_error

CONTROL_PLANE_ALLOWLIST = frozenset(
    {"state/global_status.json", "state/control_plane_status.json"}
)


class ControlPlaneAdapter(BaseAdapter):
    """Read-only adapter for AI-CONTROL-PLANE canonical state snapshots."""

    def __init__(
        self,
        freshness_sla_seconds: float = 300.0,
        root_dir: Path | None = None,
    ) -> None:
        super().__init__(
            source_id="control-plane-state",
            source_kind="AI_CONTROL_PLANE_CANONICAL_STATE",
            source_ref="state/global_status.json",
            freshness_sla_seconds=freshness_sla_seconds,
            root_dir=root_dir,
        )

    def _fetch_impl(self, now: datetime) -> AdapterResult:
        file_path = self.root_dir / "state" / "global_status.json"

        try:
            data = safe_read_json(
                file_path=file_path,
                base_dir=self.root_dir,
                allowlist=CONTROL_PLANE_ALLOWLIST,
            )
        except FileNotFoundError:
            return AdapterResult(
                source_id=self.source_id,
                source_kind=self.source_kind,
                source_ref=self.source_ref,
                fetched_at=now.isoformat(),
                observed_at=None,
                freshness_sla_seconds=self.freshness_sla_seconds,
                status=SourceStatus.NOT_CONNECTED,
                adapter_health=SourceStatus.NOT_CONNECTED,
                truth_status=SourceStatus.NOT_CONNECTED,
                last_known_status=None,
                last_known_conflict=None,
                last_known_observed_at=None,
                payload={},
                error_code="FILE_NOT_FOUND",
                error_detail="Canonical state/global_status.json is not present",
            )
        except Exception as e:
            return AdapterResult(
                source_id=self.source_id,
                source_kind=self.source_kind,
                source_ref=self.source_ref,
                fetched_at=now.isoformat(),
                observed_at=None,
                freshness_sla_seconds=self.freshness_sla_seconds,
                status=SourceStatus.UNKNOWN,
                adapter_health=SourceStatus.DEGRADED,
                truth_status=SourceStatus.UNKNOWN,
                last_known_status=None,
                last_known_conflict=None,
                last_known_observed_at=None,
                payload={},
                error_code=type(e).__name__,
                error_detail=sanitize_error(e),
            )

        adapter_health = SourceStatus.HEALTHY

        from control_tower.schema import validate_payload_schema_version
        from control_tower.security import SecurityError

        try:
            validate_payload_schema_version(self.source_id, data)
        except SecurityError as se:
            return AdapterResult(
                source_id=self.source_id,
                source_kind=self.source_kind,
                source_ref=self.source_ref,
                fetched_at=now.isoformat(),
                observed_at=None,
                freshness_sla_seconds=self.freshness_sla_seconds,
                status=SourceStatus.BLOCKED,
                adapter_health=SourceStatus.DEGRADED,
                truth_status=SourceStatus.BLOCKED,
                last_known_status="BLOCKED",
                last_known_conflict=True,
                last_known_observed_at=None,
                payload={},
                provenance=None,
                error_code="UNSUPPORTED_SCHEMA_VERSION",
                error_detail=sanitize_error(se),
            )

        cp_section = data.get("control_plane", {})
        observed_at_str = cp_section.get("observed_at") or data.get("last_heartbeat") or data.get("observed_at")
        observed_at = None
        if observed_at_str:
            try:
                observed_at = datetime.fromisoformat(observed_at_str)
                if observed_at.tzinfo is None:
                    observed_at = observed_at.replace(tzinfo=timezone.utc)
            except Exception:
                observed_at = None

        cp_status_path = self.root_dir / "state" / "control_plane_status.json"
        cp_daemon_data: dict[str, Any] = {}
        if cp_status_path.exists():
            try:
                cp_daemon_data = safe_read_json(
                    file_path=cp_status_path,
                    base_dir=self.root_dir,
                    allowlist=CONTROL_PLANE_ALLOWLIST,
                )
            except Exception:
                cp_daemon_data = {}

        # Project conflicts check
        projects_section = data.get("projects", {})
        has_conflict = any(
            isinstance(p, dict) and p.get("state_conflict") is True
            for p in projects_section.values()
        )
        overall_health = cp_section.get("overall_health") or data.get("overall_health", "UNKNOWN")
        last_known_status = "BLOCKED" if has_conflict else str(overall_health)

        # STALE SOURCE PRECEDENCE (Issue #27):
        # If a snapshot exceeds its freshness SLA, current truth status = STALE.
        # Do NOT project historical HEALTHY/WORKING/RUNNING/BLOCKED as current truth.
        truth_status: SourceStatus
        if observed_at is None:
            truth_status = SourceStatus.UNKNOWN
        else:
            age_seconds = (now - observed_at).total_seconds()
            if age_seconds < -30.0:  # Future clock skew
                truth_status = SourceStatus.UNKNOWN
            elif age_seconds > self.freshness_sla_seconds:
                truth_status = SourceStatus.STALE
            else:
                # Fresh snapshot evaluation
                if has_conflict:
                    truth_status = SourceStatus.BLOCKED
                elif "DEGRADED" in str(overall_health).upper():
                    truth_status = SourceStatus.DEGRADED
                else:
                    truth_status = SourceStatus.HEALTHY

        payload = {
            "permissions": cp_section.get("permissions", {}),
            "allowed_git_commands": cp_section.get("allowed_git_commands", []),
            "disallowed_git_commands": cp_section.get("disallowed_git_commands", []),
            "total_projects_monitored": cp_section.get("total_projects_monitored", 0),
            "overall_health": overall_health,
            "last_known_status": last_known_status,
            "projects_summary": {
                name: {
                    "status": p.get("status"),
                    "branch": p.get("branch"),
                    "local_head": p.get("local_head"),
                    "remote_head": p.get("remote_head"),
                    "state_conflict": p.get("state_conflict", False),
                    "conflicting_sources": p.get("conflicting_sources", []),
                    "last_heartbeat": p.get("last_heartbeat"),
                }
                for name, p in projects_section.items()
                if isinstance(p, dict)
            },
            "daemon_status": cp_daemon_data.get("status"),
            "daemon_pid": cp_daemon_data.get("pid"),
        }

        provenance = cp_section.get("version") or cp_daemon_data.get("observer_version")

        return AdapterResult(
            source_id=self.source_id,
            source_kind=self.source_kind,
            source_ref=self.source_ref,
            fetched_at=now.isoformat(),
            observed_at=observed_at.isoformat() if observed_at else None,
            freshness_sla_seconds=self.freshness_sla_seconds,
            status=truth_status,
            adapter_health=adapter_health,
            truth_status=truth_status,
            last_known_status=last_known_status,
            last_known_conflict=has_conflict,
            last_known_observed_at=observed_at.isoformat() if observed_at else None,
            payload=payload,
            provenance=f"version:{provenance}" if provenance else None,
        )
