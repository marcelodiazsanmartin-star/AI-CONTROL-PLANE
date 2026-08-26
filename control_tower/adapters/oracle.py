"""ORACLE-AI market intelligence read-only adapter for CONTROL TOWER CT-01R1."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from control_tower.adapters.base import BaseAdapter
from control_tower.models import AdapterResult, SourceStatus
from control_tower.security import safe_read_json, sanitize_error

ORACLE_ALLOWLIST = frozenset({"state/oracle.json", "state/global_status.json"})


class OracleAdapter(BaseAdapter):
    """Read-only adapter for ORACLE-AI runtime observations."""

    def __init__(
        self,
        freshness_sla_seconds: float = 3600.0,
        root_dir: Path | None = None,
    ) -> None:
        super().__init__(
            source_id="oracle-ai-state",
            source_kind="ORACLE_AI_SHADOW_OBSERVATION",
            source_ref="state/oracle.json",
            freshness_sla_seconds=freshness_sla_seconds,
            root_dir=root_dir,
        )

    def _fetch_impl(self, now: datetime) -> AdapterResult:
        oracle_file = self.root_dir / "state" / "oracle.json"
        data: dict[str, Any] = {}

        if oracle_file.exists():
            data = safe_read_json(
                file_path=oracle_file,
                base_dir=self.root_dir,
                allowlist=ORACLE_ALLOWLIST,
            )
        else:
            global_file = self.root_dir / "state" / "global_status.json"
            if global_file.exists():
                g_data = safe_read_json(
                    file_path=global_file,
                    base_dir=self.root_dir,
                    allowlist=ORACLE_ALLOWLIST,
                )
                data = g_data.get("projects", {}).get("ORACLE-AI", {})

        if not data or not isinstance(data, dict):
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
                error_code="NOT_CONNECTED",
                error_detail="No verified ORACLE-AI state file found",
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

        observed_at_str = data.get("observed_at")
        observed_at = None
        if observed_at_str:
            try:
                observed_at = datetime.fromisoformat(observed_at_str)
                if observed_at.tzinfo is None:
                    observed_at = observed_at.replace(tzinfo=timezone.utc)
            except Exception:
                observed_at = None

        has_conflict = bool(data.get("state_conflict", False))
        raw_status = data.get("status", "UNKNOWN")
        last_known_status = "BLOCKED" if has_conflict else str(raw_status)

        # STALE SOURCE PRECEDENCE
        truth_status: SourceStatus
        if observed_at is None:
            truth_status = SourceStatus.UNKNOWN
        else:
            age_seconds = (now - observed_at).total_seconds()
            if age_seconds < -30.0:
                truth_status = SourceStatus.UNKNOWN
            elif age_seconds > self.freshness_sla_seconds:
                truth_status = SourceStatus.STALE
            else:
                if has_conflict:
                    truth_status = SourceStatus.BLOCKED
                elif raw_status == "STALE":
                    truth_status = SourceStatus.STALE
                elif raw_status == "DEGRADED":
                    truth_status = SourceStatus.DEGRADED
                else:
                    truth_status = SourceStatus.HEALTHY

        gates = data.get("critical_gates", {})
        payload = {
            "project": "ORACLE-AI",
            "branch": data.get("branch"),
            "local_head": data.get("local_head"),
            "remote_head": data.get("remote_head"),
            "paper_shadow_mode": "PAPER_ONLY" if gates.get("PAPER_ONLY") == "TRUE" else "UNKNOWN",
            "real_money_blocked": gates.get("REAL_MONEY") == "BLOCKED",
            "accounting_drift": gates.get("ACCOUNTING_DRIFT", "UNKNOWN"),
            "ledger_integrity": gates.get("LEDGER_INTEGRITY", "UNKNOWN"),
            "watchdog": gates.get("WATCHDOG", "UNKNOWN"),
            "last_heartbeat": data.get("last_heartbeat"),
            "heartbeat_age_seconds": data.get("heartbeat_age_seconds"),
            "process_expected": data.get("process_expected"),
            "process_running": data.get("process_running"),
            "evidence_freshness": data.get("evidence_freshness", {}),
            "state_conflict": has_conflict,
            "last_known_status": last_known_status,
        }

        provenance = data.get("remote_head") or data.get("local_head")

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
            provenance=f"head:{provenance}" if provenance else None,
        )
