"""Deterministic Phase 0 fixtures; none represent production telemetry."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from control_tower.calculations import (
    effective_gate_status,
    weighted_gate_readiness,
    weighted_milestone_progress,
)
from control_tower.models import (
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
    Task,
    TruthStatus,
    serialize,
)

FIXTURE_NOW = datetime(2026, 8, 23, 15, 0, tzinfo=timezone.utc)
DATA_MODE = "DETERMINISTIC_FIXTURE"


def _projects() -> tuple[Project, ...]:
    return (
        Project(
            "control-plane",
            "AI-CONTROL-PLANE",
            "Governance and orchestration control plane",
            (
                Milestone("ct-contract", "Canonical contract", 35, 100),
                Milestone("ct-ui", "Operations console", 40, 72),
                Milestone("ct-review", "Independent review", 25, 0),
            ),
            (
                Gate("ct-evidence", "Test evidence", 60, TruthStatus.PENDING),
                Gate("ct-review-gate", "Independent review", 40, TruthStatus.PENDING),
            ),
            (
                Gate("ct-readonly", "Read-only verification", 70, TruthStatus.PENDING),
                Gate("ct-runtime", "Runtime verification", 30, TruthStatus.UNKNOWN),
            ),
            "Complete verification and request ChatGPT review",
        ),
        Project(
            "oracle-ai",
            "ORACLE-AI",
            "Market intelligence runtime (not connected)",
            (Milestone("oracle-connect", "Verified data adapter", 100, 0),),
            (Gate("oracle-cert", "Certification source", 100, TruthStatus.NOT_CONNECTED),),
            (Gate("oracle-runtime", "Runtime source", 100, TruthStatus.NOT_CONNECTED),),
            "Connect a verified read-only source",
            {
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
            },
        ),
        Project(
            "micro-market-oracle",
            "MICRO-MARKET-ORACLE",
            "Market discovery runtime (not connected)",
            (Milestone("micro-connect", "Verified discovery adapter", 100, 0),),
            (Gate("micro-cert", "Certification source", 100, TruthStatus.NOT_CONNECTED),),
            (Gate("micro-runtime", "Scheduler/runtime source", 100, TruthStatus.NOT_CONNECTED),),
            "Connect a verified read-only discovery source",
            {
                "discovery_runtime": "NOT_CONNECTED",
                "markets_scanned": "UNKNOWN",
                "opportunities": "UNKNOWN",
                "candidate_count": "UNKNOWN",
                "gates": "NOT_CONNECTED",
                "scheduler": "NOT_CONNECTED",
                "last_run": "UNKNOWN",
                "blockers": "UNKNOWN",
            },
        ),
    )


def build_dashboard(now: datetime = FIXTURE_NOW) -> dict[str, object]:
    """Build the same explicit fixture for the same supplied timestamp."""
    projects = _projects()
    evidence = (
        Evidence(
            "ev-issue-16",
            "Canonical issue #16 is available",
            TruthStatus.PASS,
            "github:issue/16",
            now - timedelta(hours=1),
        ),
        Evidence(
            "ev-tests",
            "CONTROL TOWER test result is not runtime-connected",
            TruthStatus.UNKNOWN,
            "NOT_CONNECTED",
        ),
    )
    tasks = (
        Task("task-ct-00", "control-plane", "CONTROL TOWER 00 foundation", "REVIEW", 72, True),
        Task(
            "task-oracle-connect",
            "oracle-ai",
            "Verified adapter",
            "NOT_CONNECTED",
            None,
            False,
            "No verified source",
        ),
    )
    agents = (
        Agent("chatgpt", "ChatGPT", RuntimeStatus.UNKNOWN, None, None, None, None, "UNKNOWN"),
        Agent("codex", "Codex", RuntimeStatus.UNKNOWN, None, None, None, None, "UNKNOWN"),
        Agent("antigravity", "Antigravity", RuntimeStatus.UNKNOWN, None, None, None, None, "UNKNOWN"),
    )
    alerts = (
        Alert(
            "alert-review",
            AlertLevel.HUMAN_APPROVAL,
            "Review required",
            "ChatGPT review is required before any commit.",
            "control-plane",
        ),
        Alert(
            "alert-oracle",
            AlertLevel.ORACLE,
            "ORACLE not connected",
            "Runtime and market fields remain UNKNOWN/NOT_CONNECTED.",
            "oracle-ai",
        ),
        Alert(
            "alert-micro",
            AlertLevel.WARNING,
            "MICRO not connected",
            "Discovery telemetry is unavailable.",
            "micro-market-oracle",
        ),
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
    runtimes = tuple(
        Runtime(project.id, None, RuntimeStatus.UNKNOWN, None, "NOT_CONNECTED")
        for project in projects
    )

    project_payload = []
    for project in projects:
        item = serialize(project)
        item["plan_progress"] = weighted_milestone_progress(project.milestones)
        item["certification_readiness"] = weighted_gate_readiness(project.certification_gates)
        item["operational_readiness"] = weighted_gate_readiness(project.operational_gates)
        for key in ("certification_gates", "operational_gates"):
            for gate, raw in zip(getattr(project, key), item[key]):
                raw["effective_status"] = effective_gate_status(gate).value
        project_payload.append(item)

    costs = tuple(
        Cost(project.id, None, "USD", "UNKNOWN", TruthStatus.NOT_CONNECTED)
        for project in projects
    )
    return {
        "schema_version": "control-tower.phase0.v1",
        "generated_at": now.isoformat(),
        "data_mode": DATA_MODE,
        "dashboard_is_source_of_truth": False,
        "security": serialize(SecurityPolicy()),
        "summary": {
            "global_health": "UNKNOWN",
            "autonomy_readiness": "UNKNOWN",
            "critical_alerts": sum(a.level is AlertLevel.CRITICAL for a in alerts),
            "human_approval_required": any(a.required for a in approvals),
            "active_agents": sum(a.availability is RuntimeStatus.WORKING for a in agents),
            "active_tasks": sum(task.active for task in tasks),
            "blockers": sum(bool(task.blocker) for task in tasks),
        },
        "projects": project_payload,
        "tasks": serialize(tasks),
        "agents": serialize(agents),
        "evidence": serialize(evidence),
        "alerts": serialize(alerts),
        "approvals": serialize(approvals),
        "runtimes": serialize(runtimes),
        "costs": serialize(costs),
    }
