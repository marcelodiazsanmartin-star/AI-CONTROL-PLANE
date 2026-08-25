"""Deterministic fixtures and live adapter dashboard builders for CONTROL TOWER CT-02A."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
from typing import Any

from control_tower.schema import CURRENT_SCHEMA_VERSION
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

    # Canonical verified evidence records with semantic invariant verification
    import hashlib
    resolved_root = (root_dir or Path.cwd()).resolve()

    def _resolve_evidence(
        ev_id: str,
        label: str,
        rel_path: str,
        verifier_id: str,
        check_fn: Any,
        verified_time: datetime | None,
    ) -> Evidence:
        target = (resolved_root / rel_path).resolve()
        if not target.exists() or not target.is_file():
            return Evidence(
                id=ev_id,
                label=label,
                status=TruthStatus.UNKNOWN,
                source=rel_path,
                verified_at=None,
                provenance=None,
                verifier_id=verifier_id,
                code_identity=None,
                verification_result="UNKNOWN",
            )
        file_bytes = target.read_bytes()
        file_hash = hashlib.sha256(file_bytes).hexdigest()
        try:
            passed = check_fn(target)
        except Exception:
            passed = False

        if passed:
            return Evidence(
                id=ev_id,
                label=label,
                status=TruthStatus.PASS,
                source=rel_path,
                verified_at=verified_time or now,
                provenance=f"sha256:{file_hash}",
                verifier_id=verifier_id,
                code_identity=file_hash,
                verification_result="PASS",
            )
        else:
            return Evidence(
                id=ev_id,
                label=label,
                status=TruthStatus.UNKNOWN,
                source=rel_path,
                verified_at=verified_time or now,
                provenance=f"sha256:{file_hash}",
                verifier_id=verifier_id,
                code_identity=file_hash,
                verification_result="FAIL",
            )

    def _verify_gov_baseline(p: Path) -> bool:
        text = p.read_text(encoding="utf-8")
        return (
            "AI-CONTROL-PLANE — CODEX GOVERNANCE RULES" in text
            and "Authority Hierarchy" in text
            and "Separation of Duties" in text
            and "Fail-Closed Rule" in text
        )

    def _verify_crypto_report(p: Path) -> bool:
        try:
            d = json.loads(p.read_text(encoding="utf-8"))
            return isinstance(d, dict) and d.get("status") == "PASS"
        except Exception:
            return False

    def _verify_auth_syntax(p: Path) -> bool:
        try:
            from src.directive.schema_validator import DirectiveSchemaValidator
            schema_val = DirectiveSchemaValidator()
            valid_empty, _ = schema_val.validate({})
            valid_none, _ = schema_val.validate(None)
            valid_bad, _ = schema_val.validate("bad")
            return (not valid_empty) and (not valid_none) and (not valid_bad)
        except Exception:
            return False

    def _verify_read_only_sec(p: Path) -> bool:
        from control_tower.security import validate_host_header
        from control_tower.api import DashboardHandler
        host_ok = not validate_host_header("external-evil.com") and validate_host_header("127.0.0.1:8000")
        if not host_ok:
            return False

        import io
        mutating_methods = ("do_POST", "do_PUT", "do_PATCH", "do_DELETE")
        for m in mutating_methods:
            handler_fn = getattr(DashboardHandler, m, None)
            if not callable(handler_fn):
                return False
            wfile = io.BytesIO()
            handler = DashboardHandler.__new__(DashboardHandler)
            handler.rfile = io.BytesIO()
            handler.wfile = wfile
            handler.headers = {}
            handler.close_connection = True
            handler.requestline = f"{m[3:]} /api/v1/dashboard HTTP/1.1"
            handler.request_version = "HTTP/1.1"
            try:
                handler_fn(handler)
                raw_bytes = wfile.getvalue()
                if b"\r\n\r\n" in raw_bytes:
                    header_bytes, body_bytes = raw_bytes.split(b"\r\n\r\n", 1)
                elif b"\n\n" in raw_bytes:
                    header_bytes, body_bytes = raw_bytes.split(b"\n\n", 1)
                else:
                    return False

                status_line = header_bytes.decode("utf-8", errors="replace").splitlines()[0]
                status_parts = status_line.strip().split()
                if len(status_parts) < 2 or status_parts[1] != "405":
                    return False

                body_json = json.loads(body_bytes.decode("utf-8"))
                if not isinstance(body_json, dict):
                    return False
                err_val = str(body_json.get("error", ""))
                if not err_val.startswith("READ_ONLY"):
                    return False
            except Exception:
                return False

        return True

    def _verify_adapter_isolation(p: Path) -> bool:
        from control_tower.resilience import resilient_executor
        dummy_res = resilient_executor.execute_adapter(
            lambda t: 1 / 0,
            "test-iso",
            "TEST",
            "none",
            300.0,
            now,
        )
        return dummy_res.truth_status is SourceStatus.UNKNOWN

    def _verify_host_header_sec(p: Path) -> bool:
        from control_tower.security import validate_host_header
        return (
            validate_host_header("127.0.0.1")
            and validate_host_header("localhost")
            and not validate_host_header("attacker.com")
            and not validate_host_header("192.168.1.50")
        )

    def _verify_safe_dom(p: Path) -> bool:
        text = p.read_text(encoding="utf-8")
        forbidden = (".innerHTML", ".outerHTML", "document.write", "eval(")
        return not any(f in text for f in forbidden) and "textContent" in text

    def _verify_queue_projection(p: Path) -> bool:
        from control_tower.adapters.directive_channel import DirectiveChannelAdapter
        adapter = DirectiveChannelAdapter(root_dir=resolved_root)
        res = adapter.fetch(now=now)
        if res.truth_status is not SourceStatus.HEALTHY or not isinstance(res.payload, dict):
            return False
        payload = res.payload
        required_fields = ("accepted_count", "rejected_count", "queued_count", "queue_items")
        return all(k in payload for k in required_fields) and isinstance(payload.get("queue_items"), list)

    evidence_list = [
        _resolve_evidence(
            "ev-gov-01",
            "AGENTS.md and governance rule baseline active",
            "AGENTS.md",
            "verifier:gov_baseline_rules",
            _verify_gov_baseline,
            now - timedelta(hours=2),
        ),
        _resolve_evidence(
            "ev-cert-01",
            "Red Team Engine certification evidence verified",
            "reports/crypto_test_evidence.json",
            "verifier:crypto_test_report_check",
            _verify_crypto_report,
            now - timedelta(hours=1),
        ),
        _resolve_evidence(
            "ev-auth-01",
            "Directive schema and syntax validation verified",
            "src/directive/schema_validator.py",
            "verifier:multi_priority_auth_check",
            _verify_auth_syntax,
            now - timedelta(hours=1),
        ),
        _resolve_evidence(
            "ev-ct-sec-01",
            "CONTROL TOWER loopback & read-only policy verified",
            "control_tower/api.py",
            "verifier:read_only_loopback_policy",
            _verify_read_only_sec,
            now,
        ),
        _resolve_evidence(
            "ev-ct-iso-01",
            "Adapter failure isolation verified",
            "control_tower/adapters/base.py",
            "verifier:adapter_failure_isolation",
            _verify_adapter_isolation,
            now,
        ),
        _resolve_evidence(
            "ev-ct-host-01",
            "Strict Host header validation active",
            "control_tower/security.py",
            "verifier:strict_host_header_validation",
            _verify_host_header_sec,
            now,
        ),
        _resolve_evidence(
            "ev-ct-dom-01",
            "Safe DOM rendering without innerHTML verified",
            "control_tower/frontend/app.js",
            "verifier:safe_dom_no_innerhtml",
            _verify_safe_dom,
            now,
        ),
        _resolve_evidence(
            "ev-ct-queue-01",
            "Canonical execution queue read-only projection verified",
            "control_tower/adapters/directive_channel.py",
            "verifier:queue_read_only_projection",
            _verify_queue_projection,
            now,
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
                Gate("cp-auth-gate", "Directive Schema and Syntax Validation", 60, TruthStatus.PASS, ("ev-auth-01",), True),
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
        "schema_version": CURRENT_SCHEMA_VERSION,
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
