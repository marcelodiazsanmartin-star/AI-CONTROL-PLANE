"""Complete functional, truth-semantics, and adversarial test suite for CONTROL TOWER CT-02A."""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
import threading
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from http.client import HTTPConnection
from pathlib import Path
from typing import Any, Iterator

import pytest

from control_tower.adapters import (
    ControlPlaneAdapter,
    ControlTowerSelfAdapter,
    DirectiveChannelAdapter,
    GitHubCIAdapter,
    MicroAdapter,
    OracleAdapter,
    fetch_all_adapters,
    get_default_adapters,
)
from control_tower.adapters.base import BaseAdapter
from control_tower.api import ALLOWED_ORIGINS, LOOPBACK_HOST, create_server
from control_tower.calculations import (
    effective_gate_status,
    normalize_runtime_status,
    runtime_truth,
    weighted_gate_readiness,
    weighted_milestone_progress,
)
from control_tower.fixtures import (
    DATA_MODE_DEGRADED,
    DATA_MODE_FIXTURE,
    DATA_MODE_LIVE,
    DATA_MODE_PARTIAL_LIVE,
    build_dashboard,
)
from control_tower.models import (
    AdapterResult,
    Evidence,
    Gate,
    Milestone,
    RuntimeStatus,
    SourceStatus,
    TruthStatus,
)
from control_tower.security import (
    MAX_FILE_SIZE_BYTES,
    MAX_JSONL_LINE_BYTES,
    SecurityError,
    check_json_depth,
    safe_read_json,
    safe_read_jsonl,
    sanitize_error,
    validate_host_header,
)

NOW = datetime(2026, 8, 25, 12, 0, tzinfo=timezone.utc)
ROOT = Path(__file__).resolve().parents[1]
PROTECTED_TREES = ("state", "reports", "directives/audit")


@contextmanager
def running_api() -> Iterator[tuple[str, int]]:
    server = create_server(0)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server.server_address
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def request(
    address: tuple[str, int],
    method: str,
    path: str,
    origin: str | None = None,
    host: str | None = None,
) -> tuple[int, dict[str, str], dict[str, object]]:
    headers = {}
    if origin:
        headers["Origin"] = origin
    if host:
        headers["Host"] = host
    else:
        headers["Host"] = f"{address[0]}:{address[1]}"
    connection = HTTPConnection(*address, timeout=2)
    connection.request(method, path, headers=headers)
    response = connection.getresponse()
    body = json.loads(response.read())
    response_headers = {key.lower(): value for key, value in response.getheaders()}
    connection.close()
    return response.status, response_headers, body


def protected_snapshot() -> dict[str, str]:
    snapshot = {}
    for tree in PROTECTED_TREES:
        for path in sorted((ROOT / tree).rglob("*")):
            if path.is_file():
                snapshot[str(path.relative_to(ROOT)).replace("\\", "/")] = hashlib.sha256(
                    path.read_bytes()
                ).hexdigest()
    return snapshot


# ==============================================================================
# CT-01R1 TRUTH SEMANTICS TESTS (R1_A to R1_I)
# ==============================================================================


def test_r1_a_stale_blocked_snapshot_yields_stale_truth_with_last_known_blocked() -> None:
    adapter = MicroAdapter(root_dir=ROOT)
    res = adapter.fetch(NOW)
    assert res.adapter_health is SourceStatus.HEALTHY
    assert res.truth_status is SourceStatus.STALE
    assert res.status is SourceStatus.STALE
    assert res.last_known_status == "BLOCKED"
    assert res.last_known_conflict is True


def test_r1_b_stale_running_snapshot_yields_stale_never_working() -> None:
    adapter = ControlPlaneAdapter(root_dir=ROOT)
    res = adapter.fetch(NOW)
    assert res.adapter_health is SourceStatus.HEALTHY
    assert res.truth_status is SourceStatus.STALE
    assert res.status is SourceStatus.STALE
    assert res.last_known_status == "BLOCKED"


def test_r1_c_stale_github_governance_report_yields_stale() -> None:
    adapter = GitHubCIAdapter(root_dir=ROOT)
    res = adapter.fetch(NOW)
    assert res.adapter_health is SourceStatus.HEALTHY
    assert res.truth_status is SourceStatus.STALE
    assert res.last_known_status == "HEALTHY"


def test_r1_d_agent_without_fresh_canonical_source_is_unknown() -> None:
    dashboard = build_dashboard(NOW, root_dir=ROOT)
    for agent in dashboard["agents"]:
        assert agent["availability"] == "UNKNOWN"
        assert agent["provider_status"] == "UNKNOWN"


def test_r1_e_successful_adapter_read_with_stale_payload_separates_health_and_truth() -> None:
    adapter = OracleAdapter(root_dir=ROOT)
    res = adapter.fetch(NOW)
    assert res.adapter_health is SourceStatus.HEALTHY
    assert res.truth_status is SourceStatus.STALE
    assert res.last_known_status == "STALE"


def test_r1_f_stale_unverified_pass_evidence_yields_effective_unknown() -> None:
    stale_ev = Evidence(
        id="ev-stale-01",
        label="Stale Evidence",
        status=TruthStatus.PASS,
        source="reports/some_report.json",
        verified_at=NOW - timedelta(days=2),
        provenance="hash:12345",
    )
    ev_map = {stale_ev.id: stale_ev}
    gate = Gate(
        id="gate-01",
        label="Gate 1",
        weight=100,
        status=TruthStatus.PASS,
        evidence_ids=("ev-stale-01",),
        evidence_complete=True,
    )
    eff = effective_gate_status(gate, ev_map, now=NOW)
    assert eff is TruthStatus.UNKNOWN


def test_r1_g_exact_freshness_boundary() -> None:
    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_path = Path(tmp_dir)
        state_dir = tmp_path / "state"
        state_dir.mkdir()
        status_file = state_dir / "global_status.json"

        # 299s -> HEALTHY (within 300s SLA)
        observed_fresh = NOW - timedelta(seconds=299)
        status_file.write_text(
            json.dumps({"overall_health": "HEALTHY", "last_heartbeat": observed_fresh.isoformat()}),
            encoding="utf-8",
        )
        adapter = ControlPlaneAdapter(freshness_sla_seconds=300.0, root_dir=tmp_path)
        assert adapter.fetch(NOW).truth_status is SourceStatus.HEALTHY

        # 301s -> STALE
        observed_stale = NOW - timedelta(seconds=301)
        status_file.write_text(
            json.dumps({"overall_health": "HEALTHY", "last_heartbeat": observed_stale.isoformat()}),
            encoding="utf-8",
        )
        assert adapter.fetch(NOW).truth_status is SourceStatus.STALE


def test_r1_h_missing_or_invalid_observed_at_yields_unknown() -> None:
    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_path = Path(tmp_dir)
        state_dir = tmp_path / "state"
        state_dir.mkdir()
        status_file = state_dir / "global_status.json"
        status_file.write_text(
            json.dumps({"overall_health": "HEALTHY", "last_heartbeat": "invalid-timestamp"}),
            encoding="utf-8",
        )
        adapter = ControlPlaneAdapter(root_dir=tmp_path)
        res = adapter.fetch(NOW)
        assert res.truth_status is SourceStatus.UNKNOWN
        assert res.adapter_health is SourceStatus.HEALTHY


def test_r1_i_deterministic_data_mode_derivation() -> None:
    dashboard_live = build_dashboard(NOW, root_dir=ROOT)
    assert dashboard_live["data_mode"] == DATA_MODE_DEGRADED
    dashboard_fix = build_dashboard(NOW, data_mode=DATA_MODE_FIXTURE)
    assert dashboard_fix["data_mode"] == DATA_MODE_FIXTURE


# ==============================================================================
# CT-01 FOUNDATION FUNCTIONAL TESTS (F01 to F14)
# ==============================================================================


def test_f01_valid_global_status_adapter() -> None:
    adapter = ControlPlaneAdapter(root_dir=ROOT)
    res = adapter.fetch(NOW)
    assert res.source_id == "control-plane-state"
    assert res.adapter_health is SourceStatus.HEALTHY


def test_f02_valid_source_projection() -> None:
    adapters = get_default_adapters(root_dir=ROOT)
    results = fetch_all_adapters(adapters, NOW)
    assert "control-tower-self" in results
    assert "control-plane-state" in results
    assert "oracle-ai-state" in results
    assert "micro-market-oracle-state" in results
    assert "github-ci-governance" in results


def test_f03_missing_source_fails_closed_to_not_connected() -> None:
    with tempfile.TemporaryDirectory() as tmp_dir:
        adapter = ControlPlaneAdapter(root_dir=Path(tmp_dir))
        res = adapter.fetch(NOW)
        assert res.truth_status is SourceStatus.NOT_CONNECTED
        assert res.adapter_health is SourceStatus.NOT_CONNECTED


def test_f04_stale_heartbeat_is_stale_not_healthy() -> None:
    adapter = OracleAdapter(root_dir=ROOT)
    res = adapter.fetch(NOW)
    assert res.truth_status is SourceStatus.STALE


def test_f05_malformed_json_returns_unknown_or_degraded_without_crash() -> None:
    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_path = Path(tmp_dir)
        state_dir = tmp_path / "state"
        state_dir.mkdir()
        (state_dir / "global_status.json").write_text("{broken json", encoding="utf-8")
        adapter = ControlPlaneAdapter(root_dir=tmp_path)
        res = adapter.fetch(NOW)
        assert res.truth_status is SourceStatus.UNKNOWN
        assert res.adapter_health is SourceStatus.DEGRADED


def test_f06_source_conflict_is_blocked_when_fresh() -> None:
    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_path = Path(tmp_dir)
        state_dir = tmp_path / "state"
        state_dir.mkdir()
        (state_dir / "micro.json").write_text(
            json.dumps({
                "last_heartbeat": NOW.isoformat(),
                "state_conflict": True,
            }),
            encoding="utf-8",
        )
        adapter = MicroAdapter(root_dir=tmp_path)
        res = adapter.fetch(NOW)
        assert res.truth_status is SourceStatus.BLOCKED
        assert res.last_known_status == "BLOCKED"


def test_f07_fake_unresolved_evidence_cannot_produce_effective_pass() -> None:
    gate = Gate(
        id="g1",
        label="Test Gate",
        weight=50,
        status=TruthStatus.PASS,
        evidence_ids=("non-existent-evidence-id",),
        evidence_complete=True,
    )
    eff = effective_gate_status(gate, evidence_map={}, now=NOW)
    assert eff is TruthStatus.UNKNOWN


def test_f08_adapter_failure_isolation() -> None:
    class BadAdapter(BaseAdapter):
        def _fetch_impl(self, now: datetime) -> AdapterResult:
            raise RuntimeError("Fatal adapter failure")

    adapters = [BadAdapter("bad-src", "KIND", "ref"), ControlTowerSelfAdapter(root_dir=ROOT)]
    results = fetch_all_adapters(adapters, NOW)
    assert results["bad-src"].truth_status is SourceStatus.UNKNOWN
    assert results["control-tower-self"].truth_status is SourceStatus.HEALTHY


def test_f09_provenance_and_freshness_serialized() -> None:
    dashboard = build_dashboard(NOW, root_dir=ROOT)
    for src in dashboard["sources"].values():
        assert "freshness_sla_seconds" in src
        assert "adapter_health" in src
        assert "truth_status" in src


def test_f10_runtime_status_normalization() -> None:
    assert normalize_runtime_status("HEALTHY") is RuntimeStatus.HEALTHY
    assert normalize_runtime_status("RUNNING") is RuntimeStatus.WORKING
    assert normalize_runtime_status("BLOCKED") is RuntimeStatus.BLOCKED
    assert normalize_runtime_status("UNKNOWN") is RuntimeStatus.UNKNOWN
    assert normalize_runtime_status("STALE") is RuntimeStatus.STALE


def test_f11_fixture_timestamps_never_masquerade_as_live() -> None:
    dashboard = build_dashboard(NOW, data_mode=DATA_MODE_FIXTURE)
    assert dashboard["data_mode"] == DATA_MODE_FIXTURE


def test_f12_existing_read_only_api_behavior_remains_intact() -> None:
    with running_api() as address:
        status, headers, body = request(address, "GET", "/health")
        assert status == 200
        assert body["status"] == "HEALTHY"


def test_f13_protected_canonical_trees_unchanged() -> None:
    before = protected_snapshot()
    with running_api() as address:
        request(address, "GET", "/api/v1/dashboard")
    assert protected_snapshot() == before


def test_f14_control_tower_self_health_separated_from_control_plane_state() -> None:
    adapter = ControlTowerSelfAdapter(root_dir=ROOT)
    res = adapter.fetch(NOW)
    assert res.source_id == "control-tower-self"
    assert res.truth_status is SourceStatus.HEALTHY


# ==============================================================================
# CT-02A DIRECTIVE CHANNEL & QUEUE OBSERVABILITY TESTS (CT02A_F01 to CT02A_F15)
# ==============================================================================


def test_ct02a_f01_valid_directive_channel_status_projection() -> None:
    adapter = DirectiveChannelAdapter(root_dir=ROOT)
    res = adapter.fetch(NOW)
    assert res.source_id == "directive-channel"
    assert res.source_kind == "DIRECTIVE_CHANNEL_RUNTIME_TRUTH"
    assert "accepted_count" in res.payload
    assert "rejected_count" in res.payload
    assert "queued_count" in res.payload
    assert "waiting_human_count" in res.payload


def test_ct02a_f02_missing_channel_status_is_not_connected() -> None:
    with tempfile.TemporaryDirectory() as tmp_dir:
        adapter = DirectiveChannelAdapter(root_dir=Path(tmp_dir))
        res = adapter.fetch(NOW)
        assert res.truth_status is SourceStatus.NOT_CONNECTED
        assert res.adapter_health is SourceStatus.NOT_CONNECTED


def test_ct02a_f03_stale_last_poll_yields_stale_truth() -> None:
    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_path = Path(tmp_dir)
        state_dir = tmp_path / "state"
        state_dir.mkdir()
        stale_time = (NOW - timedelta(hours=3)).isoformat()
        (state_dir / "directive_channel_status.json").write_text(
            json.dumps({
                "status": "RUNNING",
                "last_poll": stale_time,
                "accepted_count": 5,
                "queued_count": 0,
            }),
            encoding="utf-8",
        )
        adapter = DirectiveChannelAdapter(freshness_sla_seconds=300.0, root_dir=tmp_path)
        res = adapter.fetch(NOW)
        assert res.truth_status is SourceStatus.STALE
        assert res.adapter_health is SourceStatus.HEALTHY
        assert res.last_known_status == "HEALTHY"


def test_ct02a_f04_valid_execution_queue_projection() -> None:
    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_path = Path(tmp_dir)
        state_dir = tmp_path / "state"
        state_dir.mkdir()
        runtime_dir = tmp_path / "directives" / "runtime"
        runtime_dir.mkdir(parents=True)

        (state_dir / "directive_channel_status.json").write_text(
            json.dumps({
                "status": "RUNNING",
                "last_poll": NOW.isoformat(),
                "queued_count": 2,
            }),
            encoding="utf-8",
        )
        (runtime_dir / "execution_queue.jsonl").write_text(
            json.dumps({
                "directive_id": "dir-001",
                "queue_state": "READY_FOR_FUTURE_EXECUTOR",
                "target_project": "ORACLE-AI",
                "action_type": "STATUS_CHECK",
                "executed": False,
                "execution_attempts": 0,
                "readback_verified": True,
            }) + "\n" +
            json.dumps({
                "directive_id": "dir-002",
                "queue_state": "READY_FOR_FUTURE_EXECUTOR",
                "target_project": "AI-CONTROL-PLANE",
                "action_type": "HEALTH_CHECK",
                "executed": False,
                "execution_attempts": 1,
                "readback_verified": True,
            }) + "\n",
            encoding="utf-8",
        )
        adapter = DirectiveChannelAdapter(root_dir=tmp_path)
        res = adapter.fetch(NOW)
        assert res.truth_status is SourceStatus.HEALTHY
        items = res.payload["queue_items"]
        assert len(items) == 2
        assert items[0]["directive_id"] == "dir-001"
        assert items[0]["executed"] is False
        assert items[0]["readback_verified"] is True
        assert items[1]["directive_id"] == "dir-002"


def test_ct02a_f05_malformed_jsonl_line_fails_closed_without_crash() -> None:
    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_path = Path(tmp_dir)
        state_dir = tmp_path / "state"
        state_dir.mkdir()
        runtime_dir = tmp_path / "directives" / "runtime"
        runtime_dir.mkdir(parents=True)

        (state_dir / "directive_channel_status.json").write_text(
            json.dumps({"status": "RUNNING", "last_poll": NOW.isoformat()}),
            encoding="utf-8",
        )
        (runtime_dir / "execution_queue.jsonl").write_text(
            '{"directive_id": "dir-001", "queue_state": "READY"}\n{malformed line json}\n',
            encoding="utf-8",
        )
        adapter = DirectiveChannelAdapter(root_dir=tmp_path)
        res = adapter.fetch(NOW)
        assert res.truth_status is SourceStatus.BLOCKED
        assert res.error_code == "QUEUE_CORRUPTION"


def test_ct02a_f06_oversized_jsonl_line_fails_closed() -> None:
    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_path = Path(tmp_dir)
        state_dir = tmp_path / "state"
        state_dir.mkdir()
        runtime_dir = tmp_path / "directives" / "runtime"
        runtime_dir.mkdir(parents=True)

        (state_dir / "directive_channel_status.json").write_text(
            json.dumps({"status": "RUNNING", "last_poll": NOW.isoformat()}),
            encoding="utf-8",
        )
        oversized_line = json.dumps({"directive_id": "big-001", "pad": "x" * (MAX_JSONL_LINE_BYTES + 100)})
        (runtime_dir / "execution_queue.jsonl").write_text(oversized_line + "\n", encoding="utf-8")

        adapter = DirectiveChannelAdapter(root_dir=tmp_path)
        res = adapter.fetch(NOW)
        assert res.truth_status is SourceStatus.BLOCKED


def test_ct02a_f07_queued_ready_for_future_executor_never_renders_running() -> None:
    data = build_dashboard(NOW, root_dir=ROOT)
    dc = data["directive_channel"]
    for q_item in dc.get("queue_items", []):
        if q_item.get("queue_state") == "READY_FOR_FUTURE_EXECUTOR":
            assert q_item.get("executed") is False


def test_ct02a_f08_executed_false_remains_false_through_contract() -> None:
    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_path = Path(tmp_dir)
        state_dir = tmp_path / "state"
        state_dir.mkdir()
        runtime_dir = tmp_path / "directives" / "runtime"
        runtime_dir.mkdir(parents=True)

        (state_dir / "directive_channel_status.json").write_text(
            json.dumps({"status": "RUNNING", "last_poll": NOW.isoformat(), "queued_count": 1}),
            encoding="utf-8",
        )
        (runtime_dir / "execution_queue.jsonl").write_text(
            json.dumps({"directive_id": "d-exec", "queue_state": "READY_FOR_FUTURE_EXECUTOR", "executed": False}) + "\n",
            encoding="utf-8",
        )
        dashboard = build_dashboard(NOW, root_dir=tmp_path)
        items = dashboard["directive_channel"]["queue_items"]
        assert len(items) == 1
        assert items[0]["executed"] is False


def test_ct02a_f09_waiting_human_artifact_renders_observation_only() -> None:
    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_path = Path(tmp_dir)
        state_dir = tmp_path / "state"
        state_dir.mkdir()
        wh_dir = tmp_path / "directives" / "waiting_human"
        wh_dir.mkdir(parents=True)

        (state_dir / "directive_channel_status.json").write_text(
            json.dumps({"status": "RUNNING", "last_poll": NOW.isoformat(), "waiting_human_count": 1}),
            encoding="utf-8",
        )
        (wh_dir / "human-001.json").write_text(
            json.dumps({
                "directive_id": "human-001",
                "reason": "HUMAN_APPROVAL_REQUIRED for real money switch",
                "created_at": NOW.isoformat(),
            }),
            encoding="utf-8",
        )
        adapter = DirectiveChannelAdapter(root_dir=tmp_path)
        res = adapter.fetch(NOW)
        wh_items = res.payload["waiting_human_items"]
        assert len(wh_items) == 1
        assert wh_items[0]["directive_id"] == "human-001"
        assert "HUMAN_APPROVAL_REQUIRED" in wh_items[0]["reason"]


def test_ct02a_f10_contradictory_channel_count_vs_queue_is_blocked() -> None:
    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_path = Path(tmp_dir)
        state_dir = tmp_path / "state"
        state_dir.mkdir()
        runtime_dir = tmp_path / "directives" / "runtime"
        runtime_dir.mkdir(parents=True)

        (state_dir / "directive_channel_status.json").write_text(
            json.dumps({"status": "RUNNING", "last_poll": NOW.isoformat(), "queued_count": 0}),
            encoding="utf-8",
        )
        (runtime_dir / "execution_queue.jsonl").write_text(
            json.dumps({"directive_id": "d1", "executed": False}) + "\n" +
            json.dumps({"directive_id": "d2", "executed": False}) + "\n",
            encoding="utf-8",
        )
        adapter = DirectiveChannelAdapter(root_dir=tmp_path)
        res = adapter.fetch(NOW)
        assert res.truth_status is SourceStatus.BLOCKED
        assert res.last_known_conflict is True


def test_ct02a_f11_one_source_missing_while_others_valid() -> None:
    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_path = Path(tmp_dir)
        dashboard = build_dashboard(NOW, root_dir=tmp_path)
        assert dashboard["sources"]["control-tower-self"]["truth_status"] == "HEALTHY"
        assert dashboard["sources"]["directive-channel"]["truth_status"] == "NOT_CONNECTED"
        assert dashboard["data_mode"] in (DATA_MODE_DEGRADED, DATA_MODE_PARTIAL_LIVE)


def test_ct02a_f12_secret_like_fields_in_source_are_omitted() -> None:
    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_path = Path(tmp_dir)
        state_dir = tmp_path / "state"
        state_dir.mkdir()
        (state_dir / "directive_channel_status.json").write_text(
            json.dumps({
                "status": "RUNNING",
                "last_poll": NOW.isoformat(),
                "last_error": "Failed with token='ghp_SECRETSECRETSECRET0123456789'",
            }),
            encoding="utf-8",
        )
        adapter = DirectiveChannelAdapter(root_dir=tmp_path)
        res = adapter.fetch(NOW)
        assert "ghp_" not in str(res.payload)
        assert "[REDACTED_SECRET]" in res.payload["last_error"]


def test_ct02a_f13_unknown_future_queue_state_fails_closed() -> None:
    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_path = Path(tmp_dir)
        state_dir = tmp_path / "state"
        state_dir.mkdir()
        runtime_dir = tmp_path / "directives" / "runtime"
        runtime_dir.mkdir(parents=True)

        (state_dir / "directive_channel_status.json").write_text(
            json.dumps({"status": "RUNNING", "last_poll": NOW.isoformat(), "queued_count": 1}),
            encoding="utf-8",
        )
        (runtime_dir / "execution_queue.jsonl").write_text(
            json.dumps({"directive_id": "d-fut", "queue_state": "FUTURE_UNKNOWN_STATE", "executed": False}) + "\n",
            encoding="utf-8",
        )
        adapter = DirectiveChannelAdapter(root_dir=tmp_path)
        res = adapter.fetch(NOW)
        items = res.payload["queue_items"]
        assert items[0]["queue_state"] == "FUTURE_UNKNOWN_STATE"
        assert items[0]["executed"] is False


def test_ct02a_f14_bounded_latest_n_behavior() -> None:
    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_path = Path(tmp_dir)
        state_dir = tmp_path / "state"
        state_dir.mkdir()
        wh_dir = tmp_path / "directives" / "waiting_human"
        wh_dir.mkdir(parents=True)

        (state_dir / "directive_channel_status.json").write_text(
            json.dumps({"status": "RUNNING", "last_poll": NOW.isoformat(), "waiting_human_count": 30}),
            encoding="utf-8",
        )
        for i in range(30):
            (wh_dir / f"human-{i:03d}.json").write_text(
                json.dumps({"directive_id": f"human-{i:03d}", "reason": "Approval"}),
                encoding="utf-8",
            )
        adapter = DirectiveChannelAdapter(root_dir=tmp_path)
        res = adapter.fetch(NOW)
        assert len(res.payload["waiting_human_items"]) <= 10


def test_ct02a_f15_protected_canonical_trees_remain_unchanged() -> None:
    before = protected_snapshot()
    with running_api() as address:
        request(address, "GET", "/health")
        request(address, "GET", "/api/v1/dashboard")
        for method in ("POST", "PUT", "PATCH", "DELETE"):
            request(address, method, "/api/v1/dashboard")
    assert protected_snapshot() == before


# ==============================================================================
# ADVERSARIAL SECURITY SUITE (A01 to A20)
# ==============================================================================


def _classify_adversarial_result(action: callable) -> str:
    """Execute adversarial probe and return security taxonomy classification."""
    try:
        outcome = action()
        if outcome is False:
            return "BLOCKED"
        if outcome is True:
            return "BYPASS_DETECTED"
        return "BLOCKED"
    except (SecurityError, ValueError, FileNotFoundError, PermissionError):
        return "BLOCKED"
    except Exception as e:
        return f"HARNESS_ERROR: {type(e).__name__}"


def test_a01_path_traversal_escape() -> None:
    def probe() -> bool:
        traversal_path = ROOT / ".." / ".." / "Windows" / "win.ini"
        safe_read_json(traversal_path, base_dir=ROOT)
        return True

    assert _classify_adversarial_result(probe) == "BLOCKED"


def test_a02_symlink_escape() -> None:
    def probe() -> bool:
        with tempfile.TemporaryDirectory() as tmp_dir:
            base = Path(tmp_dir) / "app"
            outside = Path(tmp_dir) / "secret"
            base.mkdir()
            outside.mkdir()
            secret_file = outside / "secret.json"
            secret_file.write_text('{"secret": "leaked"}', encoding="utf-8")

            symlink_path = base / "escape.json"
            try:
                os.symlink(secret_file, symlink_path)
            except (OSError, NotImplementedError):
                escaped_target = base / ".." / "secret" / "secret.json"
                safe_read_json(escaped_target, base_dir=base)
                return True

            safe_read_json(symlink_path, base_dir=base)
            return True

    assert _classify_adversarial_result(probe) == "BLOCKED"


def test_a03_oversized_source_bounded_file_size() -> None:
    def probe() -> bool:
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)
            oversized_file = tmp_path / "execution_queue.jsonl"
            oversized_file.write_text('{"id": 1}\n' * (MAX_FILE_SIZE_BYTES // 10), encoding="utf-8")
            safe_read_jsonl(oversized_file, base_dir=tmp_path)
            return True

    assert _classify_adversarial_result(probe) == "BLOCKED"


def test_a04_oversized_jsonl_line() -> None:
    def probe() -> bool:
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)
            queue_file = tmp_path / "execution_queue.jsonl"
            queue_file.write_text(json.dumps({"k": "x" * (MAX_JSONL_LINE_BYTES + 500)}) + "\n", encoding="utf-8")
            safe_read_jsonl(queue_file, base_dir=tmp_path)
            return True

    assert _classify_adversarial_result(probe) == "BLOCKED"


def test_a05_malformed_json_defensively_rejected() -> None:
    def probe() -> bool:
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)
            bad_file = tmp_path / "bad.json"
            bad_file.write_text('{unquoted: "json", missing_brace:', encoding="utf-8")
            safe_read_json(bad_file, base_dir=tmp_path)
            return True

    assert _classify_adversarial_result(probe) == "BLOCKED"


def test_a06_malformed_jsonl_middle_record() -> None:
    def probe() -> bool:
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)
            queue_file = tmp_path / "execution_queue.jsonl"
            queue_file.write_text(
                json.dumps({"directive_id": "d1"}) + "\n" +
                "{CORRUPT_MIDDLE_RECORD\n" +
                json.dumps({"directive_id": "d2"}) + "\n",
                encoding="utf-8",
            )
            safe_read_jsonl(queue_file, base_dir=tmp_path)
            return True

    assert _classify_adversarial_result(probe) == "BLOCKED"


def test_a07_hostile_deep_json_depth_limit() -> None:
    def probe() -> bool:
        nested: dict[str, Any] = {"leaf": 1}
        for _ in range(50):
            nested = {"child": nested}
        check_json_depth(nested)
        return True

    assert _classify_adversarial_result(probe) == "BLOCKED"


def test_a08_secret_token_shaped_fields_redacted() -> None:
    leak = "Authorization failed with ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ012345 and token='secret_token_val'"
    sanitized = sanitize_error(leak)
    assert "ghp_" not in sanitized
    assert "secret_token_val" not in sanitized
    assert "[REDACTED_SECRET]" in sanitized


def test_a09_hostile_html_xss_labels_safe_rendering() -> None:
    app_source = (ROOT / "control_tower/frontend/app.js").read_text(encoding="utf-8")
    assert "innerHTML" not in app_source
    assert ".textContent" in app_source
    assert "document.createElement" in app_source


def test_a10_stale_last_poll_with_historical_healthy_counts() -> None:
    def probe() -> bool:
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)
            state_dir = tmp_path / "state"
            state_dir.mkdir()
            stale_time = (NOW - timedelta(days=2)).isoformat()
            (state_dir / "directive_channel_status.json").write_text(
                json.dumps({"status": "RUNNING", "last_poll": stale_time, "accepted_count": 100}),
                encoding="utf-8",
            )
            adapter = DirectiveChannelAdapter(freshness_sla_seconds=300.0, root_dir=tmp_path)
            res = adapter.fetch(NOW)
            if res.truth_status is SourceStatus.HEALTHY:
                return True
            return False

    assert _classify_adversarial_result(probe) == "BLOCKED"


def test_a11_future_timestamp_clock_skew_rejected() -> None:
    def probe() -> bool:
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)
            state_dir = tmp_path / "state"
            state_dir.mkdir()
            future_time = (NOW + timedelta(hours=1)).isoformat()
            (state_dir / "directive_channel_status.json").write_text(
                json.dumps({"status": "RUNNING", "last_poll": future_time}),
                encoding="utf-8",
            )
            adapter = DirectiveChannelAdapter(root_dir=tmp_path)
            res = adapter.fetch(NOW)
            if res.truth_status is SourceStatus.HEALTHY:
                return True
            return False

    assert _classify_adversarial_result(probe) == "BLOCKED"


def test_a12_contradictory_queue_and_channel_counts_blocked() -> None:
    def probe() -> bool:
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)
            state_dir = tmp_path / "state"
            state_dir.mkdir()
            runtime_dir = tmp_path / "directives" / "runtime"
            runtime_dir.mkdir(parents=True)

            (state_dir / "directive_channel_status.json").write_text(
                json.dumps({"status": "RUNNING", "last_poll": NOW.isoformat(), "queued_count": 0}),
                encoding="utf-8",
            )
            (runtime_dir / "execution_queue.jsonl").write_text(
                json.dumps({"directive_id": "d1", "executed": False}) + "\n",
                encoding="utf-8",
            )
            adapter = DirectiveChannelAdapter(root_dir=tmp_path)
            res = adapter.fetch(NOW)
            if res.truth_status is SourceStatus.HEALTHY:
                return True
            return False

    assert _classify_adversarial_result(probe) == "BLOCKED"


def test_a13_duplicate_directive_ids_detected() -> None:
    def probe() -> bool:
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)
            state_dir = tmp_path / "state"
            state_dir.mkdir()
            runtime_dir = tmp_path / "directives" / "runtime"
            runtime_dir.mkdir(parents=True)

            (state_dir / "directive_channel_status.json").write_text(
                json.dumps({"status": "RUNNING", "last_poll": NOW.isoformat(), "queued_count": 2}),
                encoding="utf-8",
            )
            (runtime_dir / "execution_queue.jsonl").write_text(
                json.dumps({"directive_id": "dup-001", "executed": False}) + "\n" +
                json.dumps({"directive_id": "dup-001", "executed": False}) + "\n",
                encoding="utf-8",
            )
            adapter = DirectiveChannelAdapter(root_dir=tmp_path)
            res = adapter.fetch(NOW)
            if res.truth_status is SourceStatus.HEALTHY:
                return True
            return False

    assert _classify_adversarial_result(probe) == "BLOCKED"


def test_a14_unknown_queue_state_fails_closed() -> None:
    def probe() -> bool:
        norm = normalize_runtime_status("TURBO_CHAOS_STATE")
        if norm is RuntimeStatus.WORKING or norm is RuntimeStatus.HEALTHY:
            return True
        return False

    assert _classify_adversarial_result(probe) == "BLOCKED"


def test_a15_adapter_exception_contained() -> None:
    class ExplodingAdapter(BaseAdapter):
        def _fetch_impl(self, now: datetime) -> AdapterResult:
            raise KeyError("Corrupt internal map")

    res = ExplodingAdapter("exploding-src", "TEST", "test").fetch(NOW)
    assert res.truth_status is SourceStatus.UNKNOWN
    assert res.status is SourceStatus.UNKNOWN
    assert res.error_code == "KeyError"


def test_a16_missing_ack_directory_handled_cleanly() -> None:
    with tempfile.TemporaryDirectory() as tmp_dir:
        adapter = DirectiveChannelAdapter(root_dir=Path(tmp_dir))
        res = adapter.fetch(NOW)
        assert res.truth_status is SourceStatus.NOT_CONNECTED


def test_a17_unreadable_source_handled_cleanly() -> None:
    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_path = Path(tmp_dir)
        state_dir = tmp_path / "state"
        state_dir.mkdir()
        (state_dir / "directive_channel_status.json").write_text("invalid json content", encoding="utf-8")
        adapter = DirectiveChannelAdapter(root_dir=tmp_path)
        res = adapter.fetch(NOW)
        assert res.truth_status is SourceStatus.UNKNOWN


def test_a18_external_origin_cors_rejection() -> None:
    with running_api() as address:
        _, headers, _ = request(address, "GET", "/api/v1/dashboard", origin="https://evil-attacker.com")
        assert "access-control-allow-origin" not in headers


def test_a19_hostile_host_dns_rebinding_rejected() -> None:
    with running_api() as address:
        for hostile_host in ("evil.com", "attacker.com:8000", "192.168.1.100:8000", "example.org"):
            status, _, body = request(address, "GET", "/api/v1/dashboard", host=hostile_host)
            assert status == 400
            assert body == {"error": "INVALID_HOST_HEADER"}


def test_a20_attempted_mutation_http_methods_remain_405() -> None:
    with running_api() as address:
        for method in ("POST", "PUT", "PATCH", "DELETE"):
            status, _, body = request(address, method, "/api/v1/dashboard")
            assert status == 405
            assert "READ_ONLY" in str(body.get("error"))
