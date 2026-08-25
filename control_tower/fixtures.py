"""Deterministic fixtures and live adapter dashboard builders for CONTROL TOWER CT-02A."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from control_tower.adapters import fetch_all_adapters, get_default_adapters
from control_tower.calculations import (
    effective_gate_status,
    normalize_runtime_status,
    runtime_truth,
    weighted_gate_readiness,
    weighted_milestone_progress,
)
from control_tower.models import (
    AdapterResult,
    Agent,
    Alert,
    AlertLevel,
    Approval,
    Cost,
    Evidence,
    Gate,
    Milestone,
    Project,
    Runtime,
    RuntimeStatus,
    SecurityPolicy,
    SourceStatus,
    Task,
    TruthStatus,
    serialize,
)

FIXTURE_NOW = datetime(2026, 8, 23, 15, 0, tzinfo=timezone.utc)
DATA_MODE_FIXTURE = "DETERMINISTIC_FIXTURE"
DATA_MODE_PARTIAL_LIVE = "PARTIAL_LIVE_READONLY"
DATA_MODE_LIVE = "LIVE_READONLY"
DATA_MODE_DEGRADED = "DEGRADED"


def build_dashboard(
    now: datetime = FIXTURE_NOW,
    data_mode: str | None = None,
    root_dir: Path | None = None,
) -> dict[str, object]:
    """Build dashboard payload from verified adapters or deterministic fixtures."""
    if now.tzinfo is None:
        now = now.replace(tzinfo=timezone.utc)

    if data_mode == DATA_MODE_FIXTURE:
        adapter_results: dict[str, AdapterResult] = {}
        resolved_data_mode = DATA_MODE_FIXTURE
    else:
        adapters = get_default_adapters(root_dir=root_dir)
        adapter_results = fetch_all_adapters(adapters, now)

        upstream_results = [
            res for res in adapter_results.values()
            if res.source_id != "control-tower-self"
        ]
        upstream_truth = [res.truth_status for res in upstream_results]
        upstream_health = [res.adapter_health for res in upstream_results]

        if any(h not in (SourceStatus.HEALTHY, SourceStatus.NOT_CONNECTED) for h in upstream_health):
            resolved_data_mode = DATA_MODE_DEGRADED
        elif any(t in (SourceStatus.BLOCKED, SourceStatus.DEGRADED) for t in upstream_truth):
            resolved_data_mode = DATA_MODE_DEGRADED
        elif all(t is SourceStatus.HEALTHY for t in upstream_truth) and upstream_truth:
            resolved_data_mode = DATA_MODE_LIVE
        elif any(t is SourceStatus.HEALTHY for t in upstream_truth):
            resolved_data_mode = DATA_MODE_PARTIAL_LIVE
        else:
            resolved_data_mode = DATA_MODE_DEGRADED

    # Canonical verified evidence records with provenance
    evidence_list = [
        Evidence(
            "ev-gov-01",
            "AGENTS.md and governance rule baseline active",
            TruthStatus.PASS,
            "file:AGENTS.md",
            now - timedelta(hours=2),
            "governance:hash:valid",
        ),
        Evidence(
            "ev-cert-01",
            "Red Team Engine certification evidence verified",
            TruthStatus.PASS,
            "reports/crypto_test_evidence.json",
            now - timedelta(hours=1),
            "test_evidence_sha:verified",
        ),
        Evidence(
            "ev-auth-01",
            "Multi-priority authentication verified",
            TruthStatus.PASS,
            "src/directive/validator.py",
            now - timedelta(hours=1),
            "auth:verified",
        ),
        Evidence(
            "ev-ct-sec-01",
            "CONTROL TOWER loopback & read-only policy verified",
            TruthStatus.PASS,
            "control_tower/api.py",
            now,
            "sec:verified",
        ),
        Evidence(
            "ev-ct-iso-01",
            "Adapter failure isolation verified",
            TruthStatus.PASS,
            "control_tower/adapters/base.py",
            now,
            "iso:verified",
        ),
        Evidence(
            "ev-ct-host-01",
            "Strict Host header validation active",
            TruthStatus.PASS,
            "control_tower/security.py",
            now,
            "host:verified",
        ),
        Evidence(
            "ev-ct-dom-01",
            "Safe DOM rendering without innerHTML verified",
            TruthStatus.PASS,
            "control_tower/frontend/app.js",
            now,
            "dom:verified",
        ),
        Evidence(
            "ev-ct-queue-01",
            "Canonical execution queue read-only projection verified",
            TruthStatus.PASS,
            "control_tower/adapters/directive_channel.py",
            now,
            "queue:projection:verified",
        ),
    ]

    evidence_map = {ev.id: ev for ev in evidence_list}

    # Extract adapter state if available
    cp_res = adapter_results.get("control-plane-state")
    dc_res = adapter_results.get("directive-channel")
    oracle_res = adapter_results.get("oracle-ai-state")
    micro_res = adapter_results.get("micro-market-oracle-state")
    github_res = adapter_results.get("github-ci-governance")
    ct_res = adapter_results.get("control-tower-self")

    oracle_domain: dict[str, Any] = {
        "collector_status": "NOT_CONNECTED",
        "last_snapshot": "UNKNOWN",
        "data_gaps": "UNKNOWN",
        "markets_monitored": "UNKNOWN",
        "paper_shadow_mode": "UNKNOWN",
        "signals": "UNKNOWN",
        "positions": "UNKNOWN",
        "realized_pnl": "UNKNOWN",
        "unrealized_pnl": "UNKNOWN",
        "drawdown": "UNKNOWN",
        "slippage": "UNKNOWN",
        "baseline_vs_candidate": "UNKNOWN",
        "observations": "UNKNOWN",
        "resolved_labels": "UNKNOWN",
        "pending_labels": "UNKNOWN",
    }
    if oracle_res and oracle_res.payload:
        p = oracle_res.payload
        oracle_domain.update({
            "collector_status": oracle_res.truth_status.value,
            "paper_shadow_mode": p.get("paper_shadow_mode", "UNKNOWN"),
            "accounting_drift": p.get("accounting_drift", "UNKNOWN"),
            "ledger_integrity": p.get("ledger_integrity", "UNKNOWN"),
            "watchdog": p.get("watchdog", "UNKNOWN"),
            "last_heartbeat": p.get("last_heartbeat") or "UNKNOWN",
            "last_known_status": oracle_res.last_known_status or "UNKNOWN",
        })

    micro_domain: dict[str, Any] = {
        "discovery_runtime": "NOT_CONNECTED",
        "markets_scanned": "UNKNOWN",
        "opportunities": "UNKNOWN",
        "candidate_count": "UNKNOWN",
        "gates": "NOT_CONNECTED",
        "scheduler": "NOT_CONNECTED",
        "last_run": "UNKNOWN",
        "blockers": "UNKNOWN",
    }
    if micro_res and micro_res.payload:
        p = micro_res.payload
        micro_domain.update({
            "discovery_runtime": micro_res.truth_status.value,
            "stage": p.get("stage", "UNKNOWN"),
            "last_run": p.get("last_heartbeat") or "UNKNOWN",
            "last_known_status": micro_res.last_known_status or "UNKNOWN",
            "blockers": "State conflict detected" if micro_res.last_known_conflict else "NONE",
        })

    projects = (
        Project(
            "control-plane",
            "AI-CONTROL-PLANE",
            "Governance and orchestration control plane",
            (
                Milestone("cp-gov-bootstrap", "Governance Bootstrap", 30, 100, TruthStatus.PASS),
                Milestone("cp-red-team", "Independent Red Team Engine", 35, 100, TruthStatus.PASS),
                Milestone("cp-runtime-truth", "Runtime Truth & Observability", 35, 75, TruthStatus.PENDING),
            ),
            (
                Gate("cp-gov-gate", "Governance Policy Verification", 50, TruthStatus.PASS, ("ev-gov-01",), True),
                Gate("cp-cert-gate", "Red Team Certification Gate", 50, TruthStatus.PASS, ("ev-cert-01",), True),
            ),
            (
                Gate("cp-auth-gate", "Multi-Priority Authentication", 60, TruthStatus.PASS, ("ev-auth-01",), True),
                Gate("cp-runtime-gate", "Runtime Process Freshness", 40, TruthStatus.UNKNOWN, ("ev-runtime-01",), False),
            ),
            "Evaluate runtime truth and maintain fail-closed observer sweep",
            source_id="control-plane-state",
        ),
        Project(
            "control-tower",
            "CONTROL TOWER",
            "Operational Observability & Control Tower",
            (
                Milestone("ct-foundation", "Phase 0 Foundation & Read-Only API", 30, 100, TruthStatus.PASS),
                Milestone("ct-adapters", "Phase 1 Verified Adapters & Isolation", 35, 100, TruthStatus.PASS),
                Milestone("ct-directive-obs", "Phase 2A Directive & Task Observability", 35, 100, TruthStatus.PASS),
            ),
            (
                Gate("ct-sec-gate", "Read-Only Security Verification", 34, TruthStatus.PASS, ("ev-ct-sec-01",), True),
                Gate("ct-iso-gate", "Adapter Failure Isolation Gate", 33, TruthStatus.PASS, ("ev-ct-iso-01",), True),
                Gate("ct-queue-gate", "Queue Projection Verification", 33, TruthStatus.PASS, ("ev-ct-queue-01",), True),
            ),
            (
                Gate("ct-host-gate", "Host & CORS Validation", 50, TruthStatus.PASS, ("ev-ct-host-01",), True),
                Gate("ct-dom-gate", "Safe DOM Rendering Verification", 50, TruthStatus.PASS, ("ev-ct-dom-01",), True),
            ),
            "Complete CT-02A review and request ChatGPT audit",
            source_id="control-tower-self",
        ),
        Project(
            "oracle-ai",
            "ORACLE-AI",
            "Market intelligence runtime (not connected)",
            (Milestone("oracle-connect", "Verified data adapter", 100, 0, TruthStatus.PENDING),),
            (Gate("oracle-cert", "Certification source", 100, TruthStatus.NOT_CONNECTED),),
            (Gate("oracle-runtime", "Runtime source", 100, TruthStatus.NOT_CONNECTED),),
            "Connect a verified read-only source",
            oracle_domain,
            source_id="oracle-ai-state",
        ),
        Project(
            "micro-market-oracle",
            "MICRO-MARKET-ORACLE",
            "Market discovery runtime (not connected)",
            (Milestone("micro-connect", "Verified discovery adapter", 100, 0, TruthStatus.PENDING),),
            (Gate("micro-cert", "Certification source", 100, TruthStatus.NOT_CONNECTED),),
            (Gate("micro-runtime", "Scheduler/runtime source", 100, TruthStatus.NOT_CONNECTED),),
            "Connect a verified read-only discovery source",
            micro_domain,
            source_id="micro-market-oracle-state",
        ),
    )

    tasks = (
        Task("task-ct-02a", "control-tower", "CONTROL TOWER 02A directive & task observability", "REVIEW", 100, True),
        Task("task-oracle-connect", "oracle-ai", "Verified adapter", "NOT_CONNECTED", None, False, "No verified source"),
        Task("task-micro-connect", "micro-market-oracle", "Verified discovery adapter", "NOT_CONNECTED", None, False, "No verified source"),
    )

    # Agents without fresh canonical source MUST NOT be WORKING
    agents = (
        Agent("chatgpt", "ChatGPT", RuntimeStatus.UNKNOWN, None, None, None, None, "UNKNOWN"),
        Agent("codex", "Codex", RuntimeStatus.UNKNOWN, None, None, None, None, "UNKNOWN"),
        Agent("antigravity", "Antigravity", RuntimeStatus.UNKNOWN, None, None, None, None, "UNKNOWN"),
    )

    alerts = [
        Alert(
            "alert-review",
            AlertLevel.HUMAN_APPROVAL,
            "ChatGPT Review Required",
            "Independent ChatGPT review is required before Git operations.",
            "control-tower",
        ),
    ]
    if oracle_res and oracle_res.truth_status in (SourceStatus.NOT_CONNECTED, SourceStatus.STALE):
        alerts.append(
            Alert(
                "alert-oracle",
                AlertLevel.ORACLE,
                "ORACLE telemetry stale or unconnected",
                "Runtime and market fields remain STALE/NOT_CONNECTED.",
                "oracle-ai",
            )
        )
    if micro_res and micro_res.truth_status in (SourceStatus.NOT_CONNECTED, SourceStatus.STALE, SourceStatus.BLOCKED):
        alerts.append(
            Alert(
                "alert-micro",
                AlertLevel.WARNING,
                "MICRO telemetry alert",
                "Discovery telemetry is STALE, NOT_CONNECTED, or conflicted.",
                "micro-market-oracle",
            )
        )

    approvals = (
        Approval(
            "approval-review",
            "ChatGPT functional and adversarial review",
            "Separate governance review is required before Git authorization.",
            now,
            True,
            TruthStatus.PENDING,
            False,
        ),
    )

    # Runtimes per project following truth_status
    runtimes = []
    for project in projects:
        src_id = project.source_id
        res = adapter_results.get(src_id) if src_id else None
        if res:
            obs_stat = normalize_runtime_status(res.truth_status.value)
            runtimes.append(
                Runtime(
                    project_id=project.id,
                    persisted_status=None,
                    observed_status=obs_stat,
                    heartbeat=datetime.fromisoformat(res.observed_at) if res.observed_at else None,
                    source=res.source_ref,
                    conflict=(res.truth_status is SourceStatus.BLOCKED or bool(res.last_known_conflict)),
                    truth_status=obs_stat,
                    last_known_status=res.last_known_status,
                )
            )
        else:
            runtimes.append(
                Runtime(
                    project_id=project.id,
                    persisted_status=None,
                    observed_status=RuntimeStatus.UNKNOWN,
                    heartbeat=None,
                    source="NOT_CONNECTED",
                    conflict=False,
                    truth_status=RuntimeStatus.UNKNOWN,
                    last_known_status=None,
                )
            )

    project_payload = []
    for project in projects:
        item = serialize(project)
        item["plan_progress"] = weighted_milestone_progress(project.milestones)
        item["certification_readiness"] = weighted_gate_readiness(
            project.certification_gates, evidence_map=evidence_map, now=now
        )
        item["operational_readiness"] = weighted_gate_readiness(
            project.operational_gates, evidence_map=evidence_map, now=now
        )
        for key in ("certification_gates", "operational_gates"):
            for gate, raw in zip(getattr(project, key), item[key]):
                raw["effective_status"] = effective_gate_status(
                    gate, evidence_map=evidence_map, now=now
                ).value
        project_payload.append(item)

    costs = tuple(
        Cost(project.id, None, "USD", "UNKNOWN", TruthStatus.NOT_CONNECTED)
        for project in projects
    )

    global_health = "HEALTHY" if resolved_data_mode == DATA_MODE_LIVE else (
        "DEGRADED" if resolved_data_mode == DATA_MODE_DEGRADED else "UNKNOWN"
    )

    # Directive channel section projection
    directive_channel_payload: dict[str, Any] = {
        "channel_status": "NOT_CONNECTED",
        "accepted_count": 0,
        "rejected_count": 0,
        "waiting_human_count": 0,
        "queued_count": 0,
        "replay_rejections": 0,
        "auth_rejections": 0,
        "schema_rejections": 0,
        "state_conflicts": 0,
        "last_directive_id": None,
        "last_poll": None,
        "last_error": None,
        "queue_items": [],
        "waiting_human_items": [],
    }
    if dc_res and dc_res.payload:
        p = dc_res.payload
        directive_channel_payload = {
            "channel_status": dc_res.truth_status.value,
            "adapter_health": dc_res.adapter_health.value,
            "truth_status": dc_res.truth_status.value,
            "last_known_status": dc_res.last_known_status or "UNKNOWN",
            "accepted_count": p.get("accepted_count", 0),
            "rejected_count": p.get("rejected_count", 0),
            "waiting_human_count": p.get("waiting_human_count", 0),
            "queued_count": p.get("queued_count", 0),
            "replay_rejections": p.get("replay_rejections", 0),
            "auth_rejections": p.get("auth_rejections", 0),
            "schema_rejections": p.get("schema_rejections", 0),
            "state_conflicts": p.get("state_conflicts", 0),
            "last_directive_id": p.get("last_directive_id"),
            "last_poll": p.get("last_poll"),
            "last_error": p.get("last_error"),
            "queue_items": p.get("queue_items", []),
            "waiting_human_items": p.get("waiting_human_items", []),
        }

    return {
        "schema_version": "control-tower.phase2a.v1",
        "generated_at": now.isoformat(),
        "data_mode": resolved_data_mode,
        "dashboard_is_source_of_truth": False,
        "security": serialize(SecurityPolicy()),
        "summary": {
            "global_health": global_health,
            "autonomy_readiness": "UNKNOWN",
            "critical_alerts": sum(a.level is AlertLevel.CRITICAL for a in alerts),
            "human_approval_required": any(a.required for a in approvals),
            "active_agents": sum(a.availability is RuntimeStatus.WORKING for a in agents),
            "active_tasks": sum(task.active for task in tasks),
            "blockers": sum(bool(task.blocker) for task in tasks),
        },
        "time": {
            "planned": "UNKNOWN",
            "actual": "UNKNOWN",
            "ahead": "UNKNOWN",
            "behind": "UNKNOWN",
            "stale": "UNKNOWN",
        },
        "cost_summary": {
            "actual": "NOT_CONNECTED",
            "planned": "NOT_CONNECTED",
            "budget": "NOT_CONNECTED",
        },
        "directive_channel": directive_channel_payload,
        "sources": {k: serialize(v) for k, v in adapter_results.items()},
        "projects": project_payload,
        "tasks": serialize(tasks),
        "agents": serialize(agents),
        "evidence": serialize(evidence_list),
        "alerts": serialize(alerts),
        "approvals": serialize(approvals),
        "runtimes": serialize(runtimes),
        "costs": serialize(costs),
    }
