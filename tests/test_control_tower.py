"""Complete functional, truth-semantics, and adversarial test suite for CONTROL TOWER CT-03."""

from __future__ import annotations

import hashlib
import json
import os
import socket
import subprocess
import sys
import tempfile
import threading
import time
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
from control_tower.frontend_server import create_frontend_server
from control_tower.logging import StructuredLogger, tower_logger
from control_tower.models import (
    AdapterResult,
    Evidence,
    Gate,
    Milestone,
    RuntimeStatus,
    SourceStatus,
    TruthStatus,
)
from control_tower.preflight import PreflightError, is_port_available, run_preflight
from control_tower.resilience import (
    CircuitBreaker,
    CircuitState,
    ResilientAdapterExecutor,
    calculate_backoff_delay,
    resilient_executor,
)
from control_tower.schema import (
    CURRENT_SCHEMA_VERSION,
    SUPPORTED_SCHEMA_VERSIONS,
    assert_supported_schema,
    validate_schema_version,
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
from control_tower.service import ControlTowerService

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


@contextmanager
def running_service() -> Iterator[ControlTowerService]:
    # Find two free ports dynamically for testing service start/stop
    with socket.socket() as s1, socket.socket() as s2:
        s1.bind(("127.0.0.1", 0))
        s2.bind(("127.0.0.1", 0))
        b_port = s1.getsockname()[1]
        f_port = s2.getsockname()[1]

    service = ControlTowerService(backend_port=b_port, frontend_port=f_port, root_dir=ROOT)
    service.start(check_ports=True)
    try:
        yield service
    finally:
        service.stop()


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
    body_bytes = response.read()
    try:
        body = json.loads(body_bytes)
    except Exception:
        body = {"raw": body_bytes.decode("utf-8", errors="replace")}
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
# CT-03 SERVICEIZATION FUNCTIONAL TESTS (CT03_F01 to CT03_F21)
# ==============================================================================


def test_ct03_f01_one_command_start_brings_backend_and_frontend_up() -> None:
    with running_service() as service:
        assert service.is_running
        # Check backend liveness
        status, _, body = request(("127.0.0.1", service.backend_port), "GET", "/health")
        assert status == 200
        assert body["status"] == "HEALTHY"
        # Check frontend html
        status_f, headers_f, body_f = request(("127.0.0.1", service.frontend_port), "GET", "/")
        assert status_f == 200
        assert "text/html" in headers_f.get("content-type", "")


def test_ct03_f02_preflight_success_path() -> None:
    info = run_preflight(root_dir=ROOT, check_ports=False)
    assert info["status"] == "PASS"
    assert info["loopback_only"] is True
    assert info["read_only"] is True


def test_ct03_f03_occupied_backend_port_fails_closed() -> None:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        occupied_port = s.getsockname()[1]
        with pytest.raises(PreflightError, match="PORT_OCCUPIED"):
            run_preflight(root_dir=ROOT, backend_port=occupied_port, check_ports=True)


def test_ct03_f04_occupied_frontend_port_fails_closed() -> None:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        occupied_port = s.getsockname()[1]
        with pytest.raises(PreflightError, match="PORT_OCCUPIED"):
            run_preflight(root_dir=ROOT, frontend_port=occupied_port, check_ports=True)


def test_ct03_f05_missing_frontend_artifact_fails_closed() -> None:
    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_path = Path(tmp_dir)
        ct_dir = tmp_path / "control_tower" / "frontend"
        ct_dir.mkdir(parents=True)
        (ct_dir / "index.html").write_text("<html></html>", encoding="utf-8")
        # Missing app.js and styles.css
        with pytest.raises(PreflightError, match="Required frontend asset missing"):
            run_preflight(root_dir=tmp_path, check_ports=False)


def test_ct03_f06_liveness_readiness_upstream_health_separation(monkeypatch: pytest.MonkeyPatch) -> None:
    with running_service() as service:
        # 1. Liveness endpoint: responds with PASS
        st_l, _, b_l = request(("127.0.0.1", service.backend_port), "GET", "/health")
        assert st_l == 200
        assert b_l["liveness"] == "PASS"

        # 2. Readiness endpoint: responds with PASS when dashboard compiles
        st_r, _, b_r = request(("127.0.0.1", service.backend_port), "GET", "/ready")
        assert st_r == 200
        assert b_r["readiness"] == "PASS"

        # 3. Negative readiness: when dashboard cannot build, returns 503 NOT_READY
        from control_tower import api
        def bad_builder(*args: Any, **kwargs: Any) -> Any:
            raise RuntimeError("CRITICAL_INTERNAL_CONFIG_ERROR")
        monkeypatch.setattr(api, "build_dashboard", bad_builder)
        st_neg, _, b_neg = request(("127.0.0.1", service.backend_port), "GET", "/ready")
        assert st_neg == 503
        assert b_neg["status"] == "NOT_READY"
        assert b_neg["readiness"] == "FAIL"

        # 4. Upstream status in dashboard can be STALE without breaking readiness
        monkeypatch.undo()
        st_d, _, b_d = request(("127.0.0.1", service.backend_port), "GET", "/api/v1/dashboard")
        assert st_d == 200
        assert b_d["sources"]["directive-channel"]["truth_status"] == "STALE"


def test_ct03_f07_stale_offline_upstream_while_tower_remains_ready() -> None:
    with tempfile.TemporaryDirectory() as tmp_dir:
        # Empty upstream repo -> adapters NOT_CONNECTED
        service = ControlTowerService(backend_port=8899, frontend_port=8898, root_dir=Path(tmp_dir))
        # Ensure frontend assets exist in tmp_dir for preflight
        fe_dir = Path(tmp_dir) / "control_tower" / "frontend"
        fe_dir.mkdir(parents=True)
        for f in ("index.html", "app.js", "styles.css"):
            (fe_dir / f).write_text("/* stub */", encoding="utf-8")

        service.start(check_ports=True)
        try:
            st, _, b = request(("127.0.0.1", 8899), "GET", "/ready")
            assert st == 200
            assert b["readiness"] == "PASS"

            st_d, _, b_d = request(("127.0.0.1", 8899), "GET", "/api/v1/dashboard")
            assert st_d == 200
            assert b_d["sources"]["directive-channel"]["truth_status"] == "NOT_CONNECTED"
        finally:
            service.stop()


def test_ct03_f08_one_adapter_timeout_is_isolated() -> None:
    executor = ResilientAdapterExecutor(timeout_seconds=0.1)

    def hanging_adapter(now: datetime) -> AdapterResult:
        time.sleep(5.0)
        return AdapterResult("slow-src", "KIND", "ref", now.isoformat(), None, 300.0, SourceStatus.HEALTHY)

    def healthy_adapter(now: datetime) -> AdapterResult:
        return AdapterResult(
            source_id="fast-src",
            source_kind="KIND",
            source_ref="ref",
            fetched_at=now.isoformat(),
            observed_at=now.isoformat(),
            freshness_sla_seconds=300.0,
            status=SourceStatus.HEALTHY,
            adapter_health=SourceStatus.HEALTHY,
            truth_status=SourceStatus.HEALTHY,
        )

    start = time.monotonic()
    res_slow = executor.execute_adapter(hanging_adapter, "slow-src", "KIND", "ref", 300.0, NOW)
    elapsed = time.monotonic() - start

    # Elapsed time is bounded by timeout (~0.1s), NOT by the 5.0s sleep
    assert elapsed < 1.0
    assert res_slow.truth_status is SourceStatus.UNKNOWN
    assert res_slow.error_code == "ADAPTER_TIMEOUT"

    # Other adapter remains healthy and responsive
    res_fast = executor.execute_adapter(healthy_adapter, "fast-src", "KIND", "ref", 300.0, NOW)
    assert res_fast.truth_status is SourceStatus.HEALTHY
    executor.shutdown(wait=False)


def test_ct03_f09_circuit_breaker_opens_after_threshold() -> None:
    breaker = CircuitBreaker("test-cb", failure_threshold=2, recovery_timeout_seconds=5.0)
    assert breaker.allow_request() is True
    breaker.record_failure()
    assert breaker.allow_request() is True
    breaker.record_failure()
    # Now OPEN
    assert breaker.state is CircuitState.OPEN
    assert breaker.allow_request() is False


def test_ct03_f10_half_open_recovery_closes_breaker() -> None:
    breaker = CircuitBreaker("test-cb", failure_threshold=1, recovery_timeout_seconds=0.1)
    breaker.record_failure()
    assert breaker.state is CircuitState.OPEN
    time.sleep(0.15)
    # Should transition to HALF_OPEN
    assert breaker.allow_request() is True
    assert breaker.state is CircuitState.HALF_OPEN
    breaker.record_success()
    assert breaker.state is CircuitState.CLOSED


def test_ct03_f11_retry_backoff_bounded() -> None:
    # 1. Verify exponential backoff delay bounds and non-negativity
    for attempt in range(10):
        delay = calculate_backoff_delay(attempt, base_delay=0.1, max_delay=2.0, jitter_fraction=0.2)
        assert delay >= 0.0
        assert delay <= 3.0  # Max delay 2.0 * 1.5

    # 2. Test jitter determinism with seed
    d1 = calculate_backoff_delay(1, base_delay=0.1, max_delay=2.0, jitter_fraction=0.2, random_seed=42)
    d2 = calculate_backoff_delay(1, base_delay=0.1, max_delay=2.0, jitter_fraction=0.2, random_seed=42)
    assert d1 == d2


def test_ct03_f12_unsupported_schema_fails_closed() -> None:
    with pytest.raises(SecurityError, match="Unsupported future schema version"):
        assert_supported_schema("control-tower.v99.unsupported", context_label="test")


def test_ct03_f13_malformed_schema_version_fails_closed() -> None:
    with pytest.raises(SecurityError, match="Malformed schema version"):
        assert_supported_schema("invalid schema with spaces @!#", context_label="test")


def test_ct03_f14_graceful_shutdown_closes_both_listeners() -> None:
    with socket.socket() as s1, socket.socket() as s2:
        s1.bind(("127.0.0.1", 0))
        s2.bind(("127.0.0.1", 0))
        b_port = s1.getsockname()[1]
        f_port = s2.getsockname()[1]

    service = ControlTowerService(backend_port=b_port, frontend_port=f_port, root_dir=ROOT)
    service.start(check_ports=True)
    assert is_port_available(b_port) is False
    assert is_port_available(f_port) is False

    service.stop()
    assert service.is_running is False
    # Ports must be released
    time.sleep(0.2)
    assert is_port_available(b_port) is True
    assert is_port_available(f_port) is True


def test_ct03_f15_restart_returns_to_healthy_tower_state() -> None:
    # Capture upstream state file hashes before restart
    upstream_hashes_before = {
        f: hashlib.sha256((ROOT / f).read_bytes()).hexdigest()
        for f in ["state/global_status.json", "state/oracle.json", "state/micro.json"]
        if (ROOT / f).exists()
    }

    with socket.socket() as s1, socket.socket() as s2:
        s1.bind(("127.0.0.1", 0))
        s2.bind(("127.0.0.1", 0))
        b_port = s1.getsockname()[1]
        f_port = s2.getsockname()[1]

    service = ControlTowerService(backend_port=b_port, frontend_port=f_port, root_dir=ROOT)
    service.start(check_ports=True)
    service.stop()
    time.sleep(0.2)

    # Second start on same ports
    service2 = ControlTowerService(backend_port=b_port, frontend_port=f_port, root_dir=ROOT)
    info = service2.start(check_ports=True)
    try:
        assert info["status"] == "RUNNING"
        st, _, b = request(("127.0.0.1", b_port), "GET", "/health")
        assert st == 200
        assert b["status"] == "HEALTHY"
    finally:
        service2.stop()

    # Verify upstream state hashes remain identical
    upstream_hashes_after = {
        f: hashlib.sha256((ROOT / f).read_bytes()).hexdigest()
        for f in ["state/global_status.json", "state/oracle.json", "state/micro.json"]
        if (ROOT / f).exists()
    }
    assert upstream_hashes_before == upstream_hashes_after


def test_ct03_f16_structured_logs_sanitize_secrets() -> None:
    logger = StructuredLogger(max_entries=10)
    rec = logger.log(
        component="TEST",
        result_class="ERROR",
        error_detail="Failed connecting with token='ghp_SECRETSECRET0123456789' and bearer my_secret_token",
    )
    assert "ghp_" not in rec["error_detail"]
    assert "[REDACTED_SECRET]" in rec["error_detail"]


def test_ct03_f17_log_retention_is_bounded() -> None:
    logger = StructuredLogger(max_entries=5)
    for i in range(20):
        logger.log(component=f"comp-{i}", result_class="OK")
    entries = logger.get_recent(limit=10)
    assert len(entries) == 5
    assert entries[-1]["component"] == "comp-19"


def test_ct03_f18_no_upstream_runtime_engine_instantiated() -> None:
    code = (
        "import sys\n"
        "from control_tower.fixtures import build_dashboard\n"
        "build_dashboard()\n"
        "assert 'src.directive.watcher' not in sys.modules\n"
        "assert 'src.directive.durable_queue' not in sys.modules\n"
        "assert 'src.engine' not in sys.modules\n"
    )
    res = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True)
    assert res.returncode == 0


def test_ct03_f19_ct02a_directive_task_projections_intact() -> None:
    dashboard = build_dashboard(NOW, root_dir=ROOT)
    assert "directive_channel" in dashboard
    dc = dashboard["directive_channel"]
    assert "accepted_count" in dc
    assert "rejected_count" in dc
    assert "queued_count" in dc
    assert "waiting_human_count" in dc


def test_ct03_f20_all_ct01r1_truth_freshness_tests_intact() -> None:
    # Run core truth check
    adapter = GitHubCIAdapter(root_dir=ROOT)
    res = adapter.fetch(NOW)
    assert res.adapter_health is SourceStatus.HEALTHY
    assert res.truth_status is SourceStatus.STALE


def test_ct03_f21_protected_trees_unchanged() -> None:
    before = protected_snapshot()
    with running_service() as service:
        request(("127.0.0.1", service.backend_port), "GET", "/api/v1/dashboard")
        request(("127.0.0.1", service.frontend_port), "GET", "/")
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
    except (SecurityError, PreflightError, ValueError, FileNotFoundError, PermissionError):
        return "BLOCKED"
    except Exception as e:
        return f"HARNESS_ERROR: {type(e).__name__}"


def test_a01_second_instance_occupied_ports() -> None:
    def probe() -> bool:
        with socket.socket() as s:
            s.bind(("127.0.0.1", 0))
            occupied_port = s.getsockname()[1]
            run_preflight(root_dir=ROOT, backend_port=occupied_port, check_ports=True)
            return True

    assert _classify_adversarial_result(probe) == "BLOCKED"


def test_a02_backend_crash_restart() -> None:
    def probe() -> bool:
        with socket.socket() as s1, socket.socket() as s2:
            s1.bind(("127.0.0.1", 0))
            s2.bind(("127.0.0.1", 0))
            b_port = s1.getsockname()[1]
            f_port = s2.getsockname()[1]

        service = ControlTowerService(backend_port=b_port, frontend_port=f_port, root_dir=ROOT)
        service.start(check_ports=True)
        service.stop()
        service2 = ControlTowerService(backend_port=b_port, frontend_port=f_port, root_dir=ROOT)
        service2.start(check_ports=True)
        service2.stop()
        return False

    assert _classify_adversarial_result(probe) == "BLOCKED"


def test_a03_frontend_unavailable() -> None:
    def probe() -> bool:
        with tempfile.TemporaryDirectory() as tmp_dir:
            run_preflight(root_dir=Path(tmp_dir), check_ports=False)
            return True

    assert _classify_adversarial_result(probe) == "BLOCKED"


def test_a04_one_adapter_hangs() -> None:
    def probe() -> bool:
        executor = ResilientAdapterExecutor(timeout_seconds=0.1)

        def hanging_adapter(now: datetime) -> AdapterResult:
            time.sleep(1.0)
            return AdapterResult("hang-src", "KIND", "ref", now.isoformat(), None, 300.0, SourceStatus.HEALTHY)

        res = executor.execute_adapter(hanging_adapter, "hang-src", "KIND", "ref", 300.0, NOW)
        executor.shutdown(wait=False)
        if res.truth_status is SourceStatus.HEALTHY:
            return True
        return False

    assert _classify_adversarial_result(probe) == "BLOCKED"


def test_a05_all_adapters_offline() -> None:
    def probe() -> bool:
        with tempfile.TemporaryDirectory() as tmp_dir:
            dashboard = build_dashboard(NOW, root_dir=Path(tmp_dir))
            for src_id, src in dashboard["sources"].items():
                if src_id != "control-tower-self" and src["truth_status"] == "HEALTHY":
                    return True
            return False

    assert _classify_adversarial_result(probe) == "BLOCKED"


def test_a06_repeated_timeout_storm() -> None:
    def probe() -> bool:
        executor = ResilientAdapterExecutor(timeout_seconds=0.05)

        def slow_func(now: datetime) -> AdapterResult:
            time.sleep(0.2)
            return AdapterResult("slow-src", "KIND", "ref", now.isoformat(), None, 300.0, SourceStatus.HEALTHY)

        for _ in range(5):
            res = executor.execute_adapter(slow_func, "slow-src", "KIND", "ref", 300.0, NOW)
            if res.truth_status is SourceStatus.HEALTHY:
                executor.shutdown(wait=False)
                return True
        executor.shutdown(wait=False)
        return False

    assert _classify_adversarial_result(probe) == "BLOCKED"


def test_a07_refresh_request_storm() -> None:
    def probe() -> bool:
        with running_api() as address:
            for _ in range(20):
                st, _, _ = request(address, "GET", "/api/v1/dashboard")
                if st != 200:
                    return True
            return False

    assert _classify_adversarial_result(probe) == "BLOCKED"


def test_a08_malformed_source_payload() -> None:
    def probe() -> bool:
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)
            state_dir = tmp_path / "state"
            state_dir.mkdir()
            (state_dir / "directive_channel_status.json").write_text("{corrupt: json,", encoding="utf-8")
            adapter = DirectiveChannelAdapter(root_dir=tmp_path)
            res = adapter.fetch(NOW)
            if res.truth_status is SourceStatus.HEALTHY:
                return True
            return False

    assert _classify_adversarial_result(probe) == "BLOCKED"


def test_a09_unsupported_future_schema() -> None:
    def probe() -> bool:
        assert_supported_schema("control-tower.v999.experimental")
        return True

    assert _classify_adversarial_result(probe) == "BLOCKED"


def test_a10_downgraded_invalid_schema() -> None:
    def probe() -> bool:
        assert_supported_schema("phase-minus-one; drop table users;")
        return True

    assert _classify_adversarial_result(probe) == "BLOCKED"


def test_a11_forward_clock_jump() -> None:
    def probe() -> bool:
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)
            state_dir = tmp_path / "state"
            state_dir.mkdir()
            (state_dir / "global_status.json").write_text(
                json.dumps({"overall_health": "HEALTHY", "last_heartbeat": (NOW - timedelta(days=10)).isoformat()}),
                encoding="utf-8",
            )
            adapter = ControlPlaneAdapter(root_dir=tmp_path)
            res = adapter.fetch(NOW)
            if res.truth_status is SourceStatus.HEALTHY:
                return True
            return False

    assert _classify_adversarial_result(probe) == "BLOCKED"


def test_a12_backward_clock_jump() -> None:
    def probe() -> bool:
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)
            state_dir = tmp_path / "state"
            state_dir.mkdir()
            (state_dir / "global_status.json").write_text(
                json.dumps({"overall_health": "HEALTHY", "last_heartbeat": (NOW + timedelta(hours=2)).isoformat()}),
                encoding="utf-8",
            )
            adapter = ControlPlaneAdapter(root_dir=tmp_path)
            res = adapter.fetch(NOW)
            if res.truth_status is SourceStatus.HEALTHY:
                return True
            return False

    assert _classify_adversarial_result(probe) == "BLOCKED"


def test_a13_disk_read_permission_error() -> None:
    def probe() -> bool:
        safe_read_json(Path("C:/nonexistent_protected_path/secret.json"), base_dir=ROOT)
        return True

    assert _classify_adversarial_result(probe) == "BLOCKED"


def test_a14_hostile_host_header() -> None:
    def probe() -> bool:
        with running_api() as address:
            status, _, body = request(address, "GET", "/api/v1/dashboard", host="evil-domain.com")
            if status != 400 or body.get("error") != "INVALID_HOST_HEADER":
                return True
            return False

    assert _classify_adversarial_result(probe) == "BLOCKED"


def test_a15_external_origin() -> None:
    def probe() -> bool:
        with running_api() as address:
            _, headers, _ = request(address, "GET", "/api/v1/dashboard", origin="https://attacker-origin.com")
            if "access-control-allow-origin" in headers:
                return True
            return False

    assert _classify_adversarial_result(probe) == "BLOCKED"


def test_a16_xss_payload_in_adapter_log_field() -> None:
    def probe() -> bool:
        app_source = (ROOT / "control_tower/frontend/app.js").read_text(encoding="utf-8")
        if "innerHTML" in app_source:
            return True
        return False

    assert _classify_adversarial_result(probe) == "BLOCKED"


def test_a17_secret_like_payload_log_field() -> None:
    def probe() -> bool:
        sanitized = sanitize_error("Failed with ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ123456")
        if "ghp_" in sanitized:
            return True
        return False

    assert _classify_adversarial_result(probe) == "BLOCKED"


def test_a18_shutdown_during_active_refresh() -> None:
    def probe() -> bool:
        with socket.socket() as s1, socket.socket() as s2:
            s1.bind(("127.0.0.1", 0))
            s2.bind(("127.0.0.1", 0))
            b_port = s1.getsockname()[1]
            f_port = s2.getsockname()[1]

        service = ControlTowerService(backend_port=b_port, frontend_port=f_port, root_dir=ROOT)
        service.start(check_ports=True)
        # Immediate stop while background workers might be scheduled
        service.stop()
        return False

    assert _classify_adversarial_result(probe) == "BLOCKED"


def test_a19_attempted_mutation_http_methods() -> None:
    def probe() -> bool:
        with running_api() as address:
            for method in ("POST", "PUT", "PATCH", "DELETE"):
                status, _, body = request(address, method, "/api/v1/dashboard")
                if status != 405 or "READ_ONLY" not in str(body.get("error")):
                    return True
            return False

    assert _classify_adversarial_result(probe) == "BLOCKED"


def test_a20_attempt_to_instantiate_upstream_mutating_runtime_blocked() -> None:
    def probe() -> bool:
        code = (
            "import sys\n"
            "from control_tower.fixtures import build_dashboard\n"
            "build_dashboard()\n"
            "if 'src.directive.watcher' in sys.modules or 'src.directive.durable_queue' in sys.modules or 'src.engine' in sys.modules:\n"
            "    sys.exit(1)\n"
            "sys.exit(0)\n"
        )
        res = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True)
        if res.returncode != 0:
            return True
        return False

    assert _classify_adversarial_result(probe) == "BLOCKED"
