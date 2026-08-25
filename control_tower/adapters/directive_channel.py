"""Directive channel and runtime task queue read-only adapter for CONTROL TOWER CT-02A."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from control_tower.adapters.base import BaseAdapter
from control_tower.models import AdapterResult, SourceStatus
from control_tower.security import (
    safe_list_dir_files,
    safe_read_json,
    safe_read_jsonl,
    sanitize_error,
)

DIRECTIVE_CHANNEL_ALLOWLIST = frozenset({
    "state/directive_channel_status.json",
    "directives/runtime/execution_queue.jsonl",
    "directives/runtime/consumed_directives.jsonl",
    "directives/waiting_human",
    "directives/waiting_human/*.json",
    "directives/accepted",
    "directives/accepted/*.json",
    "directives/rejected",
    "directives/rejected/*.json",
    "directives/ack",
    "directives/ack/*.json",
})

MAX_RECENT_ENTRIES = 10


class DirectiveChannelAdapter(BaseAdapter):
    """Read-only adapter for Control Plane directive channel and execution queue."""

    def __init__(
        self,
        freshness_sla_seconds: float = 300.0,
        root_dir: Path | None = None,
    ) -> None:
        super().__init__(
            source_id="directive-channel",
            source_kind="DIRECTIVE_CHANNEL_RUNTIME_TRUTH",
            source_ref="state/directive_channel_status.json",
            freshness_sla_seconds=freshness_sla_seconds,
            root_dir=root_dir,
        )

    def _fetch_impl(self, now: datetime) -> AdapterResult:
        channel_file = self.root_dir / "state" / "directive_channel_status.json"

        if not channel_file.exists():
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
                error_detail="Canonical state/directive_channel_status.json is not present",
            )

        try:
            status_data = safe_read_json(
                file_path=channel_file,
                base_dir=self.root_dir,
                allowlist=DIRECTIVE_CHANNEL_ALLOWLIST,
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
            validate_payload_schema_version(self.source_id, status_data)
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

        # Extract timestamps
        last_poll_str = status_data.get("last_poll")
        observed_at = None
        if last_poll_str:
            try:
                observed_at = datetime.fromisoformat(last_poll_str)
                if observed_at.tzinfo is None:
                    observed_at = observed_at.replace(tzinfo=timezone.utc)
            except Exception:
                observed_at = None

        # Read execution queue jsonl
        queue_file = self.root_dir / "directives" / "runtime" / "execution_queue.jsonl"
        queue_records: list[dict[str, Any]] = []
        queue_corruption: str | None = None
        has_duplicate_directive_ids = False

        if queue_file.exists():
            try:
                queue_records = safe_read_jsonl(
                    file_path=queue_file,
                    base_dir=self.root_dir,
                    allowlist=DIRECTIVE_CHANNEL_ALLOWLIST,
                )
            except Exception as e:
                queue_corruption = sanitize_error(e)
                adapter_health = SourceStatus.DEGRADED

        # Sanitize and project queue items
        projected_queue: list[dict[str, Any]] = []
        seen_directive_ids: set[str] = set()
        unexecuted_count = 0

        for item in queue_records:
            d_id = item.get("directive_id", "UNKNOWN")
            if d_id in seen_directive_ids:
                has_duplicate_directive_ids = True
            seen_directive_ids.add(d_id)

            executed = bool(item.get("executed", False))
            if not executed:
                unexecuted_count += 1

            projected_queue.append({
                "directive_id": d_id,
                "queue_state": item.get("queue_state", "UNKNOWN"),
                "target_project": item.get("target_project", "UNKNOWN"),
                "action_type": item.get("action_type", "UNKNOWN"),
                "requires_human_approval": bool(item.get("requires_human_approval", False)),
                "executed": executed,
                "execution_attempts": int(item.get("execution_attempts", 0)),
                "readback_verified": bool(item.get("readback_verified", False)),
                "accepted_at": item.get("accepted_at"),
                "source_provenance": item.get("directive_blob_sha") or item.get("directive_source_sha"),
            })

        # Read waiting human items
        waiting_human_dir = self.root_dir / "directives" / "waiting_human"
        waiting_human_items: list[dict[str, Any]] = []
        if waiting_human_dir.exists():
            files = safe_list_dir_files(
                dir_path=waiting_human_dir,
                base_dir=self.root_dir,
                allowlist=DIRECTIVE_CHANNEL_ALLOWLIST,
                max_files=MAX_RECENT_ENTRIES,
            )
            for f in files:
                try:
                    w_data = safe_read_json(f, base_dir=self.root_dir, allowlist=DIRECTIVE_CHANNEL_ALLOWLIST)
                    waiting_human_items.append({
                        "directive_id": w_data.get("directive_id", f.stem),
                        "reason": sanitize_error(w_data.get("reason") or w_data.get("decision_reason") or "HUMAN_APPROVAL_REQUIRED"),
                        "observed_at": w_data.get("created_at") or w_data.get("received_at"),
                        "source_ref": f"directives/waiting_human/{f.name}",
                    })
                except Exception:
                    pass

        # Contradiction and Conflict Analysis
        state_conflicts_count = int(status_data.get("state_conflicts", 0))
        reported_queued_count = int(status_data.get("queued_count", 0))

        # Check count discrepancy: if channel status claims queued_count != len(unexecuted_queue)
        # when queue file exists and has records
        count_contradiction = (
            queue_file.exists()
            and not queue_corruption
            and len(queue_records) > 0
            and reported_queued_count != unexecuted_count
        )

        has_conflict = (
            state_conflicts_count > 0
            or bool(queue_corruption)
            or has_duplicate_directive_ids
            or count_contradiction
        )

        raw_status = status_data.get("status", "UNKNOWN")
        last_known_status = "BLOCKED" if has_conflict else ("HEALTHY" if raw_status == "RUNNING" else raw_status)

        # STALE SOURCE PRECEDENCE
        truth_status: SourceStatus
        if observed_at is None:
            truth_status = SourceStatus.UNKNOWN
        else:
            age_seconds = (now - observed_at).total_seconds()
            if age_seconds < -30.0:  # Clock skew
                truth_status = SourceStatus.UNKNOWN
            elif age_seconds > self.freshness_sla_seconds:
                truth_status = SourceStatus.STALE
            else:
                if has_conflict:
                    truth_status = SourceStatus.BLOCKED
                elif raw_status == "RUNNING":
                    truth_status = SourceStatus.HEALTHY
                else:
                    truth_status = SourceStatus.DEGRADED

        payload = {
            "channel_version": status_data.get("channel_version", "2.0.0"),
            "accepted_count": int(status_data.get("accepted_count", 0)),
            "rejected_count": int(status_data.get("rejected_count", 0)),
            "waiting_human_count": max(int(status_data.get("waiting_human_count", 0)), len(waiting_human_items)),
            "queued_count": reported_queued_count,
            "replay_rejections": int(status_data.get("replay_rejections", 0)),
            "auth_rejections": int(status_data.get("auth_rejections", 0)),
            "schema_rejections": int(status_data.get("schema_rejections", 0)),
            "state_conflicts": state_conflicts_count,
            "last_directive_id": status_data.get("last_directive_id"),
            "last_directive_seen": status_data.get("last_directive_seen"),
            "last_poll": last_poll_str,
            "last_error": sanitize_error(status_data.get("last_error") or queue_corruption or ""),
            "queue_items": projected_queue,
            "waiting_human_items": waiting_human_items,
            "queue_corruption": queue_corruption,
            "has_duplicate_directive_ids": has_duplicate_directive_ids,
            "count_contradiction": count_contradiction,
            "last_known_status": last_known_status,
        }

        provenance = f"version:{status_data.get('channel_version', '2.0')}"

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
            provenance=provenance,
            error_code="QUEUE_CORRUPTION" if queue_corruption else (status_data.get("last_error") and "CHANNEL_ERROR"),
            error_detail=queue_corruption or (status_data.get("last_error") and sanitize_error(status_data.get("last_error"))),
        )
