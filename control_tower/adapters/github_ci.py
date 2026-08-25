"""GitHub CI & remote governance read-only projection adapter for CONTROL TOWER CT-01R1."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from control_tower.adapters.base import BaseAdapter
from control_tower.models import AdapterResult, SourceStatus
from control_tower.security import safe_read_json

GITHUB_ALLOWLIST = frozenset({"reports/github_remote_governance_raw.json"})


class GitHubCIAdapter(BaseAdapter):
    """Read-only adapter projecting GitHub CI & branch governance evidence."""

    def __init__(
        self,
        freshness_sla_seconds: float = 3600.0,  # 1 hour SLA for live CI telemetry
        root_dir: Path | None = None,
    ) -> None:
        super().__init__(
            source_id="github-ci-governance",
            source_kind="GITHUB_REMOTE_GOVERNANCE_EVIDENCE",
            source_ref="reports/github_remote_governance_raw.json",
            freshness_sla_seconds=freshness_sla_seconds,
            root_dir=root_dir,
        )

    def _fetch_impl(self, now: datetime) -> AdapterResult:
        report_file = self.root_dir / "reports" / "github_remote_governance_raw.json"

        if not report_file.exists():
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
                error_detail="GitHub governance raw report is not present",
            )

        try:
            data = safe_read_json(
                file_path=report_file,
                base_dir=self.root_dir,
                allowlist=GITHUB_ALLOWLIST,
            )
        except Exception as e:
            return AdapterResult(
                source_id=self.source_id,
                source_kind=self.source_kind,
                source_ref=self.source_ref,
                fetched_at=now.isoformat(),
                observed_at=None,
                freshness_sla_seconds=self.freshness_sla_seconds,
                status=SourceStatus.DEGRADED,
                adapter_health=SourceStatus.DEGRADED,
                truth_status=SourceStatus.DEGRADED,
                last_known_status=None,
                last_known_conflict=None,
                last_known_observed_at=None,
                payload={},
                error_code=type(e).__name__,
                error_detail=str(e),
            )

        adapter_health = SourceStatus.HEALTHY

        api_data = data.get("api_data", {})
        repo = api_data.get("repo", {})
        branch = api_data.get("branch", {})
        protection = api_data.get("protection", {})
        runs = api_data.get("runs", {}).get("workflow_runs", [])

        latest_run = runs[0] if runs else {}
        workflow_timestamp = latest_run.get("created_at") or latest_run.get("updated_at")
        observed_at = None
        if workflow_timestamp:
            try:
                observed_at = datetime.fromisoformat(workflow_timestamp.replace("Z", "+00:00"))
            except Exception:
                observed_at = None

        commit_sha = branch.get("commit", {}).get("sha") or latest_run.get("head_commit", {}).get("id")

        is_healthy_config = (
            branch.get("protected") is True
            and protection.get("allow_force_pushes", {}).get("enabled") is False
            and latest_run.get("conclusion") in ("success", None)
        )
        last_known_status = "HEALTHY" if is_healthy_config else "DEGRADED"

        # STALE SOURCE PRECEDENCE (Issue #27):
        # A successfully parsed stale governance report MUST NOT produce GitHub/CI = HEALTHY.
        # If only stale committed evidence is available: GitHub/CI = STALE.
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
                truth_status = SourceStatus.HEALTHY if is_healthy_config else SourceStatus.DEGRADED

        payload = {
            "repository": repo.get("full_name", "marcelodiazsanmartin-star/AI-CONTROL-PLANE"),
            "default_branch": repo.get("default_branch", "main"),
            "head_sha": commit_sha,
            "branch_protected": branch.get("protected", False),
            "enforce_admins": protection.get("enforce_admins", {}).get("enabled", False),
            "allow_force_pushes": protection.get("allow_force_pushes", {}).get("enabled", False),
            "allow_deletions": protection.get("allow_deletions", {}).get("enabled", False),
            "latest_workflow_run": {
                "id": latest_run.get("check_suite_id"),
                "event": latest_run.get("event"),
                "conclusion": latest_run.get("conclusion"),
                "display_title": latest_run.get("display_title"),
                "head_branch": latest_run.get("head_branch"),
                "timestamp": workflow_timestamp,
            },
            "last_known_status": last_known_status,
        }

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
            last_known_conflict=False,
            last_known_observed_at=observed_at.isoformat() if observed_at else None,
            payload=payload,
            provenance=f"commit:{commit_sha}" if commit_sha else None,
        )
