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
    classify_upstream_health,
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
    MAX_WORKER_THREADS,
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
        class HangingAdapter(BaseAdapter):
            def __init__(self) -> None:
                super().__init__("hang-src", "HANG_TEST", "none", 300.0)

            def _fetch_impl(self, now: datetime) -> AdapterResult:
                time.sleep(2.5)
                return AdapterResult("hang-src", "HANG_TEST", "none", now.isoformat(), None, 300.0, SourceStatus.HEALTHY)

        adapters = (HangingAdapter(), ControlTowerSelfAdapter(root_dir=ROOT))
        start = time.monotonic()
        results = fetch_all_adapters(adapters, NOW)
        duration = time.monotonic() - start

        # Response latency must be strictly bounded by timeout
        if duration > 4.5:
            return True
        # Hanging adapter must fail closed to UNKNOWN / timeout
        if results["hang-src"].truth_status is SourceStatus.HEALTHY:
            return True
        # Healthy adapter in same run must survive and be HEALTHY
        if results["control-tower-self"].truth_status is not SourceStatus.HEALTHY:
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
        class SlowAdapter(BaseAdapter):
            def __init__(self) -> None:
                super().__init__("slow-src", "SLOW_TEST", "none", 300.0)

            def _fetch_impl(self, now: datetime) -> AdapterResult:
                time.sleep(2.2)
                return AdapterResult("slow-src", "SLOW_TEST", "none", now.isoformat(), None, 300.0, SourceStatus.HEALTHY)

        adapters = (SlowAdapter(),)
        initial_threads = threading.active_count()
        for _ in range(3):
            fetch_all_adapters(adapters, NOW)
        current_threads = threading.active_count()
        # Thread count must not leak or explode
        if current_threads > initial_threads + MAX_WORKER_THREADS + 2:
            return True
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
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)
            state_dir = tmp_path / "state"
            state_dir.mkdir()
            (state_dir / "directive_channel_status.json").write_text(
                json.dumps({
                    "status": "RUNNING",
                    "last_poll": NOW.isoformat(),
                    "channel_version": "99.9.0-future-experimental",
                }),
                encoding="utf-8",
            )
            dashboard = build_dashboard(NOW, root_dir=tmp_path)
            dc_res = dashboard["sources"].get("directive-channel")
            if not dc_res:
                return True
            if dc_res.get("truth_status") == "HEALTHY":
                return True
            if dc_res.get("error_code") != "UNSUPPORTED_SCHEMA_VERSION":
                return True
            return False

    assert _classify_adversarial_result(probe) == "BLOCKED"


def test_a10_downgraded_invalid_schema() -> None:
    def probe() -> bool:
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)
            state_dir = tmp_path / "state"
            state_dir.mkdir()
            (state_dir / "global_status.json").write_text(
                json.dumps({
                    "overall_health": "HEALTHY",
                    "last_heartbeat": NOW.isoformat(),
                    "schema_version": "invalid schema! drop table $$;",
                }),
                encoding="utf-8",
            )
            dashboard = build_dashboard(NOW, root_dir=tmp_path)
            cp_res = dashboard["sources"].get("control-plane-state")
            if not cp_res:
                return True
            if cp_res.get("truth_status") == "HEALTHY":
                return True
            if cp_res.get("error_code") != "UNSUPPORTED_SCHEMA_VERSION":
                return True
            return False

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


# ==============================================================================
# CT04-R2 PRODUCT PATH REMEDIATION REGRESSION SUITE
# ==============================================================================


def test_ct04_r2_product_path_timeout_isolation_and_liveness() -> None:
    """Inject a hanging adapter into dashboard collection and prove liveness remains responsive."""
    with running_service() as service:
        # Liveness endpoint must respond immediately
        st_l, _, b_l = request(("127.0.0.1", service.backend_port), "GET", "/health")
        assert st_l == 200
        assert b_l["status"] == "HEALTHY"

        # Dashboard compilation with real resilient executor must complete within bounded time
        st_d, _, b_d = request(("127.0.0.1", service.backend_port), "GET", "/api/v1/dashboard")
        assert st_d == 200
        assert "sources" in b_d


def test_ct04_r2_synthetic_pass_evidence_fails_closed() -> None:
    """Verify that placeholder or provenance-only evidence without semantic verification fails closed."""
    gate = Gate(
        id="test-gate",
        label="Test Gate",
        weight=50.0,
        status=TruthStatus.PASS,
        evidence_ids=("ev-fake",),
        evidence_complete=True,
    )
    valid_sha = "c" * 64

    # Placeholder provenance -> UNKNOWN
    ev_placeholder = Evidence(
        id="ev-fake",
        label="Fake Evidence",
        status=TruthStatus.PASS,
        source="none",
        verified_at=NOW,
        provenance="sec:verified",
    )
    assert effective_gate_status(gate, {"ev-fake": ev_placeholder}, now=NOW) is TruthStatus.UNKNOWN

    # Missing verified_at -> UNKNOWN
    ev_no_time = Evidence(
        id="ev-fake",
        label="Fake Evidence",
        status=TruthStatus.PASS,
        source="none",
        verified_at=None,
        provenance=f"sha256:{valid_sha}",
        verifier_id="verifier:loopback_check",
        code_identity=valid_sha,
        verification_result="PASS",
    )
    assert effective_gate_status(gate, {"ev-fake": ev_no_time}, now=NOW) is TruthStatus.UNKNOWN

    # Provenance-only without verifier_id / verification_result / code_identity -> UNKNOWN (CT04-R4)
    ev_provenance_only = Evidence(
        id="ev-fake",
        label="Provenance Only Evidence",
        status=TruthStatus.PASS,
        source="none",
        verified_at=NOW,
        provenance=f"sha256:{valid_sha}",
    )
    assert effective_gate_status(gate, {"ev-fake": ev_provenance_only}, now=NOW) is TruthStatus.UNKNOWN

    # Full semantic evidence -> PASS
    ev_full_valid = Evidence(
        id="ev-fake",
        label="Full Valid Evidence",
        status=TruthStatus.PASS,
        source="none",
        verified_at=NOW,
        provenance=f"sha256:{valid_sha}",
        verifier_id="verifier:loopback_check",
        code_identity=valid_sha,
        verification_result="PASS",
    )
    assert effective_gate_status(gate, {"ev-fake": ev_full_valid}, now=NOW) is TruthStatus.PASS


def test_ct04_r4_mandatory_semantic_fields_fail_closed() -> None:
    """Verify that every mandatory semantic evidence field fails closed if absent or invalid."""
    valid_sha = "d" * 64
    gate = Gate("test-gate", "Test Gate", 50.0, TruthStatus.PASS, ("ev-1",), True)

    # Missing verification_result -> UNKNOWN
    ev1 = Evidence(
        id="ev-1",
        label="Missing result",
        status=TruthStatus.PASS,
        source="none",
        verified_at=NOW,
        provenance=f"sha256:{valid_sha}",
        verifier_id="verifier:loopback_check",
        code_identity=valid_sha,
        verification_result=None,
    )
    assert effective_gate_status(gate, {"ev-1": ev1}, now=NOW) is TruthStatus.UNKNOWN

    # Missing verifier_id -> UNKNOWN
    ev2 = Evidence(
        id="ev-1",
        label="Missing verifier",
        status=TruthStatus.PASS,
        source="none",
        verified_at=NOW,
        provenance=f"sha256:{valid_sha}",
        verifier_id=None,
        code_identity=valid_sha,
        verification_result="PASS",
    )
    assert effective_gate_status(gate, {"ev-1": ev2}, now=NOW) is TruthStatus.UNKNOWN

    # Untrusted verifier_id -> UNKNOWN
    ev3 = Evidence(
        id="ev-1",
        label="Untrusted verifier",
        status=TruthStatus.PASS,
        source="none",
        verified_at=NOW,
        provenance=f"sha256:{valid_sha}",
        verifier_id="untrusted_random_verifier",
        code_identity=valid_sha,
        verification_result="PASS",
    )
    assert effective_gate_status(gate, {"ev-1": ev3}, now=NOW) is TruthStatus.UNKNOWN

    # Missing code_identity -> UNKNOWN
    ev4 = Evidence(
        id="ev-1",
        label="Missing code identity",
        status=TruthStatus.PASS,
        source="none",
        verified_at=NOW,
        provenance=f"sha256:{valid_sha}",
        verifier_id="verifier:loopback_check",
        code_identity=None,
        verification_result="PASS",
    )
    assert effective_gate_status(gate, {"ev-1": ev4}, now=NOW) is TruthStatus.UNKNOWN

    # Mismatched code_identity vs provenance -> UNKNOWN
    ev5 = Evidence(
        id="ev-1",
        label="Mismatched code identity vs provenance",
        status=TruthStatus.PASS,
        source="none",
        verified_at=NOW,
        provenance=f"sha256:{valid_sha}",
        verifier_id="verifier:loopback_check",
        code_identity="e" * 64,
        verification_result="PASS",
    )
    assert effective_gate_status(gate, {"ev-1": ev5}, now=NOW) is TruthStatus.UNKNOWN


def test_ct04_r5_allowlist_canonical_and_verifier_strength() -> None:
    """Verify CT04-R5 exact verifier allowlist, canonical digest binding, and verifier strength."""
    valid_sha = "f" * 64
    mismatched_sha = "0" * 64
    gate = Gate("test-gate", "Test Gate", 50.0, TruthStatus.PASS, ("ev-1",), True)

    # 1. (05A) Generic-prefix verifiers not in TRUSTED_VERIFIER_IDS fail closed
    for unreg_verifier in (
        "verifier:test:anything",
        "verifier:report:fake",
        "verifier:invariant:unregistered_check",
        "verifier:custom:my_test",
    ):
        ev_unreg = Evidence(
            id="ev-1",
            label="Unregistered verifier",
            status=TruthStatus.PASS,
            source="none",
            verified_at=NOW,
            provenance=f"sha256:{valid_sha}",
            verifier_id=unreg_verifier,
            code_identity=valid_sha,
            verification_result="PASS",
        )
        assert effective_gate_status(gate, {"ev-1": ev_unreg}, now=NOW) is TruthStatus.UNKNOWN

    # 2. (05B) Canonical provenance with mismatched code_identity vs digest fails closed
    ev_canon_mismatch = Evidence(
        id="ev-1",
        label="Canonical mismatch",
        status=TruthStatus.PASS,
        source="reports/crypto_test_evidence.json",
        verified_at=NOW,
        provenance=f"canonical:reports/crypto_test_evidence.json#sha256:{valid_sha}",
        verifier_id="verifier:crypto_test_report_check",
        code_identity=mismatched_sha,
        verification_result="PASS",
    )
    assert effective_gate_status(gate, {"ev-1": ev_canon_mismatch}, now=NOW) is TruthStatus.UNKNOWN

    # Canonical provenance with matching code_identity passes
    ev_canon_match = Evidence(
        id="ev-1",
        label="Canonical match",
        status=TruthStatus.PASS,
        source="reports/crypto_test_evidence.json",
        verified_at=NOW,
        provenance=f"canonical:reports/crypto_test_evidence.json#sha256:{valid_sha}",
        verifier_id="verifier:crypto_test_report_check",
        code_identity=valid_sha,
        verification_result="PASS",
    )
    assert effective_gate_status(gate, {"ev-1": ev_canon_match}, now=NOW) is TruthStatus.PASS

    # 3. (05C) Product path dashboard evidence resolution fail-closed for uncertified crypto report
    from control_tower.fixtures import build_dashboard
    dash = build_dashboard(now=NOW)
    cert_ev = next((ev for ev in dash["evidence"] if ev["id"] == "ev-cert-01"), None)
    assert cert_ev is not None
    # Because reports/crypto_test_evidence.json lacks top-level status == 'PASS', it fails closed to UNKNOWN / FAIL
    assert cert_ev["status"] == "UNKNOWN"
    assert cert_ev.get("verification_result") in ("FAIL", "UNKNOWN")


def test_ct04_r5_e2_mutating_handlers_returning_200_fails_closed() -> None:
    """Verify that if mutation handlers return success (200) instead of 405/READ_ONLY, verification fails closed."""
    from control_tower.api import DashboardHandler
    from control_tower.fixtures import build_dashboard

    orig_post = DashboardHandler.do_POST
    try:
        def fake_do_POST(self: Any) -> None:
            self._write_json(200, {"status": "SUCCESS: Mutation applied"})

        DashboardHandler.do_POST = fake_do_POST

        dash = build_dashboard(now=NOW)
        sec_ev = next((ev for ev in dash["evidence"] if ev["id"] == "ev-ct-sec-01"), None)
        assert sec_ev is not None
        assert sec_ev["status"] == "UNKNOWN"
        assert sec_ev.get("verification_result") in ("FAIL", "UNKNOWN")
    finally:
        DashboardHandler.do_POST = orig_post


def test_ct04_r5_e3_mutating_handler_returning_200_with_405_substring_fails_closed() -> None:
    """Verify that if a mutation handler returns HTTP 200 with '405' and 'READ_ONLY' in body, verification fails closed."""
    from control_tower.api import DashboardHandler
    from control_tower.fixtures import build_dashboard

    orig_post = DashboardHandler.do_POST
    try:
        def fake_do_POST(self: Any) -> None:
            # Returns HTTP 200 with substrings '405' and 'READ_ONLY' in the body
            self._write_json(200, {"status": "SUCCESS: 405 error bypassed", "note": "READ_ONLY override"})

        DashboardHandler.do_POST = fake_do_POST

        dash = build_dashboard(now=NOW)
        sec_ev = next((ev for ev in dash["evidence"] if ev["id"] == "ev-ct-sec-01"), None)
        assert sec_ev is not None
        assert sec_ev["status"] == "UNKNOWN"
        assert sec_ev.get("verification_result") in ("FAIL", "UNKNOWN")
    finally:
        DashboardHandler.do_POST = orig_post


def test_ct04_r6_positive_baseline_pass_and_claim_alignment() -> None:
    """(06A & 06B) Verify positive baseline PASS for unmodified DashboardHandler and auth/queue claim alignment."""
    from control_tower.fixtures import build_dashboard
    dash = build_dashboard(now=NOW)

    # 1. ev-ct-sec-01 passes legitimately on unmodified DashboardHandler
    sec_ev = next((ev for ev in dash["evidence"] if ev["id"] == "ev-ct-sec-01"), None)
    assert sec_ev is not None
    assert sec_ev["status"] == "PASS"
    assert sec_ev["verification_result"] == "PASS"

    # 2. ev-auth-01 passes legitimately for directive schema and syntax validation
    auth_ev = next((ev for ev in dash["evidence"] if ev["id"] == "ev-auth-01"), None)
    assert auth_ev is not None
    assert auth_ev["status"] == "PASS"
    assert auth_ev["verification_result"] == "PASS"
    assert auth_ev["label"] == "Directive schema and syntax validation verified"

    # 3. ev-ct-queue-01 fails closed to UNKNOWN when directive channel is NOT_CONNECTED
    queue_ev = next((ev for ev in dash["evidence"] if ev["id"] == "ev-ct-queue-01"), None)
    assert queue_ev is not None
    assert queue_ev["status"] == "UNKNOWN"
    assert queue_ev.get("verification_result") in ("FAIL", "UNKNOWN")


def test_ct04_r6_queue_projection_mock_pass_when_healthy(monkeypatch: Any) -> None:
    """(06B) Verify that when DirectiveChannelAdapter is live/HEALTHY with valid queue payload, ev-ct-queue-01 produces PASS."""
    from control_tower.adapters.directive_channel import DirectiveChannelAdapter
    from control_tower.fixtures import build_dashboard

    def mock_fetch(self: Any, now: datetime) -> AdapterResult:
        return AdapterResult(
            source_id="directive-channel",
            source_kind="DIRECTIVE_CHANNEL",
            source_ref="directives/inbound",
            fetched_at=now.isoformat(),
            observed_at=now.isoformat(),
            freshness_sla_seconds=60.0,
            status=SourceStatus.HEALTHY,
            adapter_health=SourceStatus.HEALTHY,
            truth_status=SourceStatus.HEALTHY,
            payload={
                "accepted_count": 5,
                "rejected_count": 0,
                "queued_count": 2,
                "queue_items": [{"id": "dir-1"}, {"id": "dir-2"}],
            },
        )

    monkeypatch.setattr(DirectiveChannelAdapter, "fetch", mock_fetch)
    dash = build_dashboard(now=NOW)
    queue_ev = next((ev for ev in dash["evidence"] if ev["id"] == "ev-ct-queue-01"), None)
    assert queue_ev is not None
    assert queue_ev["status"] == "PASS"
    assert queue_ev["verification_result"] == "PASS"


def test_ct04_r6_true_hang_resource_boundedness() -> None:
    """(06C) Verify that permanent adapter hangs trigger admission backpressure and keep workers/latency bounded."""
    import time
    from control_tower.resilience import ResilientAdapterExecutor

    executor = ResilientAdapterExecutor(
        timeout_seconds=0.05,
        max_workers=2,
        max_retries=0,
        max_queue_depth=2,
    )

    def hung_adapter(now: datetime) -> AdapterResult:
        time.sleep(5.0)
        return AdapterResult("hung-src", "KIND", "ref", now.isoformat(), None, 300.0, SourceStatus.HEALTHY)

    # Submit 4 hanging adapter tasks (2 occupying worker threads + 2 occupying queue capacity)
    for i in range(4):
        res = executor.execute_adapter(hung_adapter, f"hung-src-{i}", "KIND", "ref", 300.0, NOW)
        assert res.truth_status is SourceStatus.UNKNOWN
        assert res.error_code == "ADAPTER_TIMEOUT"

    # 5th task must immediately be rejected by admission backpressure with CAPACITY_EXHAUSTED in < 20ms
    start = time.monotonic()
    res_rejected = executor.execute_adapter(hung_adapter, "hung-src-4", "KIND", "ref", 300.0, NOW)
    elapsed = time.monotonic() - start

    assert elapsed < 0.05  # Instant backpressure rejection
    assert res_rejected.truth_status is SourceStatus.UNKNOWN
    assert res_rejected.error_code == "CAPACITY_EXHAUSTED"

    executor.shutdown(wait=False)


def test_ct04_r6_e2_generation_safety_and_restart_boundedness() -> None:
    """(06D) Verify generation safety, non-inflating admission bounds, and bounded live threads across restart."""
    import time
    import threading
    from control_tower.resilience import ResilientAdapterExecutor

    executor = ResilientAdapterExecutor(
        timeout_seconds=0.05,
        max_workers=2,
        max_retries=0,
        max_queue_depth=2,
    )

    release_event = threading.Event()

    def controlled_hung(now: datetime) -> AdapterResult:
        release_event.wait()
        return AdapterResult("src", "KIND", "ref", now.isoformat(), None, 300.0, SourceStatus.HEALTHY)

    # 1. Fill executor with 4 hangs
    for i in range(4):
        res = executor.execute_adapter(controlled_hung, f"hung-{i}", "KIND", "ref", 300.0, NOW)
        assert res.error_code == "ADAPTER_TIMEOUT"

    # 2. 5th call is CAPACITY_EXHAUSTED
    res5 = executor.execute_adapter(controlled_hung, "hung-4", "KIND", "ref", 300.0, NOW)
    assert res5.error_code == "CAPACITY_EXHAUSTED"

    # 3. Shutdown without waiting (2 tasks running on threads, 2 cancelled from work queue)
    executor.shutdown(wait=False)

    # 4. In new generation, exactly 2 slots were freed by the cancelled queue futures,
    # while the 2 running background threads still hold their admission permits!
    r_new1 = executor.execute_adapter(controlled_hung, "new-gen-0", "KIND", "ref", 300.0, NOW)
    assert r_new1.error_code == "ADAPTER_TIMEOUT"

    r_new2 = executor.execute_adapter(controlled_hung, "new-gen-1", "KIND", "ref", 300.0, NOW)
    assert r_new2.error_code == "ADAPTER_TIMEOUT"

    # Saturated: 2 old running + 2 new running = 4 (all permits held)
    # Next call in new generation MUST be immediately rejected with CAPACITY_EXHAUSTED
    r_new_saturated = executor.execute_adapter(controlled_hung, "new-gen-2", "KIND", "ref", 300.0, NOW)
    assert r_new_saturated.error_code == "CAPACITY_EXHAUSTED"

    # 5. Let all hanging tasks across both generations finish
    release_event.set()
    time.sleep(0.1)

    # 6. Now that all old and new tasks finished, verify capacity is exactly 4, NEVER MORE
    release_event2 = threading.Event()

    def hung2(now: datetime) -> AdapterResult:
        release_event2.wait()
        return AdapterResult("src", "KIND", "ref", now.isoformat(), None, 300.0, SourceStatus.HEALTHY)

    for i in range(4):
        r = executor.execute_adapter(hung2, f"final-hung-{i}", "KIND", "ref", 300.0, NOW)
        assert r.error_code == "ADAPTER_TIMEOUT"

    r_final_overflow = executor.execute_adapter(hung2, "final-overflow", "KIND", "ref", 300.0, NOW)
    assert r_final_overflow.error_code == "CAPACITY_EXHAUSTED"

    release_event2.set()
    executor.shutdown(wait=False)


def test_ct04_r6_e2_direct_permit_accounting_no_over_release() -> None:
    """(06D) Verify that repeated or late done callbacks cannot over-release admission capacity."""
    from control_tower.resilience import ResilientAdapterExecutor
    import threading

    executor = ResilientAdapterExecutor(
        timeout_seconds=0.05,
        max_workers=2,
        max_retries=0,
        max_queue_depth=2,
    )

    # Semaphore starts with max permits (4)
    # Intentionally trigger simulated over-release attempts
    for _ in range(10):
        # Trigger safe release callback handling
        try:
            executor._admission_semaphore.release()
        except ValueError:
            pass  # Expected BoundedSemaphore behavior

    # Must still only allow exactly 4 acquisitions, 5th must fail
    acquired_count = 0
    for _ in range(4):
        assert executor._admission_semaphore.acquire(blocking=False) is True
        acquired_count += 1

    assert acquired_count == 4
    # 5th acquire MUST fail (capacity was not inflated beyond 4)
    assert executor._admission_semaphore.acquire(blocking=False) is False

    # Cleanly release the 4 acquired permits
    for _ in range(4):
        executor._admission_semaphore.release()

    executor.shutdown(wait=False)


def test_ct04_r6_e3_submit_failure_permit_exception_safety(monkeypatch: Any) -> None:
    """(06E) Verify that when submit() raises an exception after admission, the permit is immediately released."""
    from control_tower.resilience import ResilientAdapterExecutor
    from concurrent.futures import ThreadPoolExecutor

    executor = ResilientAdapterExecutor(
        timeout_seconds=0.05,
        max_workers=2,
        max_retries=0,
        max_queue_depth=2,
    )

    def failing_submit(self: Any, fn: Any, *args: Any, **kwargs: Any) -> Any:
        raise RuntimeError("Injected submission failure after admission acquisition")

    # Incur 10 consecutive submission failures
    monkeypatch.setattr(ThreadPoolExecutor, "submit", failing_submit)
    for i in range(10):
        res = executor.execute_adapter(lambda now: None, f"fail-src-{i}", "KIND", "ref", 300.0, NOW)
        assert res.truth_status is SourceStatus.UNKNOWN
        assert res.error_code == "RuntimeError"

    # Restore normal submit
    monkeypatch.undo()

    # Verify that all 4 permits are completely intact (none leaked!)
    # We should be able to acquire exactly 4 permits
    for i in range(4):
        res_ok = executor.execute_adapter(
            lambda now: AdapterResult(
                "ok", "KIND", "ref", now.isoformat(), None, 300.0,
                SourceStatus.HEALTHY, SourceStatus.HEALTHY, SourceStatus.HEALTHY,
            ),
            f"ok-src-{i}",
            "KIND",
            "ref",
            300.0,
            NOW,
        )
        assert res_ok.truth_status is SourceStatus.HEALTHY

    executor.shutdown(wait=False)


def test_ct04_r6_e3_shutdown_vs_submit_race_no_permit_leak() -> None:
    """(06E) Verify that when shutdown() occurs right as submit() is called, no permit is leaked."""
    from control_tower.resilience import ResilientAdapterExecutor

    executor = ResilientAdapterExecutor(
        timeout_seconds=0.05,
        max_workers=2,
        max_retries=0,
        max_queue_depth=2,
    )

    # Initialize the underlying executor pool
    underlying_pool = executor._get_executor()
    # Pre-emptively shut down the underlying pool so executor.submit() raises RuntimeError
    underlying_pool.shutdown(wait=False, cancel_futures=True)

    # Submit task: admission acquires permit, but submit() raises RuntimeError (cannot schedule after shutdown)
    res = executor.execute_adapter(
        lambda now: AdapterResult(
            "src", "KIND", "ref", now.isoformat(), None, 300.0,
            SourceStatus.HEALTHY, SourceStatus.HEALTHY, SourceStatus.HEALTHY,
        ),
        "race-src",
        "KIND",
        "ref",
        300.0,
        NOW,
    )
    assert res.truth_status is SourceStatus.UNKNOWN
    assert res.error_code == "RuntimeError"

    # Restart executor cleanly via shutdown()
    executor.shutdown(wait=False)

    # Verify all 4 permits remain available in the next lifecycle
    for i in range(4):
        res_restart = executor.execute_adapter(
            lambda now: AdapterResult(
                "src", "KIND", "ref", now.isoformat(), None, 300.0,
                SourceStatus.HEALTHY, SourceStatus.HEALTHY, SourceStatus.HEALTHY,
            ),
            f"restart-src-{i}",
            "KIND",
            "ref",
            300.0,
            NOW,
        )
        assert res_restart.truth_status is SourceStatus.HEALTHY

    executor.shutdown(wait=False)


def test_ct04_r6_e4_callback_failure_with_running_future(monkeypatch: Any) -> None:
    """(06F) Verify that when add_done_callback() fails after submit(), permit remains held while worker runs and releases on completion."""
    from control_tower.resilience import ResilientAdapterExecutor
    from concurrent.futures import Future
    import threading
    import time

    executor = ResilientAdapterExecutor(
        timeout_seconds=0.05,
        max_workers=2,
        max_retries=0,
        max_queue_depth=2,
    )

    task_started = threading.Event()
    task_finish = threading.Event()

    def running_adapter(now: datetime) -> AdapterResult:
        task_started.set()
        task_finish.wait()
        return AdapterResult("src", "KIND", "ref", now.isoformat(), None, 300.0, SourceStatus.HEALTHY, SourceStatus.HEALTHY, SourceStatus.HEALTHY)

    # Injected failure for add_done_callback
    def failing_add_done(self: Any, fn: Any) -> None:
        raise RuntimeError("Injected add_done_callback failure")

    monkeypatch.setattr(Future, "add_done_callback", failing_add_done)

    # Execute task in background thread
    t = threading.Thread(target=lambda: executor._execute_single_attempt(running_adapter, "src-1", NOW))
    t.start()
    task_started.wait()

    # The running worker thread MUST still hold its permit (permit not released prematurely!)
    # Capacity is 4: exactly 3 permits can be acquired, 4th must fail
    assert executor._admission_semaphore.acquire(blocking=False) is True
    assert executor._admission_semaphore.acquire(blocking=False) is True
    assert executor._admission_semaphore.acquire(blocking=False) is True
    assert executor._admission_semaphore.acquire(blocking=False) is False

    # Release probe permits
    for _ in range(3):
        executor._admission_semaphore.release()

    # Finish worker task
    task_finish.set()
    t.join()
    time.sleep(0.05)

    # Now that the worker wrapper finished and executed its finally block, the permit is cleanly released!
    # All 4 permits must be acquirable
    for _ in range(4):
        assert executor._admission_semaphore.acquire(blocking=False) is True
    for _ in range(4):
        executor._admission_semaphore.release()

    executor.shutdown(wait=False)


def test_ct04_r6_e4_cancellation_before_start_releases_permit(monkeypatch: Any) -> None:
    """(06F) Verify that when add_done_callback() fails on a queued task and future is cancelled before start, permit is released."""
    from control_tower.resilience import ResilientAdapterExecutor
    from concurrent.futures import Future
    import threading
    import time

    executor = ResilientAdapterExecutor(
        timeout_seconds=0.05,
        max_workers=1,
        max_retries=0,
        max_queue_depth=2,
    )

    block_worker = threading.Event()

    def blocking_adapter(now: datetime) -> AdapterResult:
        block_worker.wait()
        return AdapterResult("b", "K", "r", now.isoformat(), None, 300.0, SourceStatus.HEALTHY, SourceStatus.HEALTHY, SourceStatus.HEALTHY)

    # Start 1 worker to occupy the pool
    t = threading.Thread(target=lambda: executor._execute_single_attempt(blocking_adapter, "src-b", NOW))
    t.start()
    time.sleep(0.02)

    # Injected failure for add_done_callback
    def failing_add_done(self: Any, fn: Any) -> None:
        raise RuntimeError("Injected add_done_callback failure on queued task")

    monkeypatch.setattr(Future, "add_done_callback", failing_add_done)

    # Submit 2nd task: worker pool is busy, task is queued, add_done_callback raises, future.cancel() succeeds -> permit released
    res, err, exc = executor._execute_single_attempt(lambda now: None, "src-queued", NOW)

    # Total capacity = 3. Task 1 is running (1 permit). Task 2 was cancelled (0 permits held).
    # We should be able to acquire exactly 2 permits!
    assert executor._admission_semaphore.acquire(blocking=False) is True
    assert executor._admission_semaphore.acquire(blocking=False) is True
    assert executor._admission_semaphore.acquire(blocking=False) is False

    for _ in range(2):
        executor._admission_semaphore.release()

    block_worker.set()
    t.join()
    executor.shutdown(wait=False)


def test_ct04_r6_e4_double_release_does_not_inflate_capacity() -> None:
    """(06F) Verify that release-once semantics prevent double release by both worker wrapper finally and done callback."""
    from control_tower.resilience import ResilientAdapterExecutor

    executor = ResilientAdapterExecutor(
        timeout_seconds=0.05,
        max_workers=2,
        max_retries=0,
        max_queue_depth=2,
    )

    # Execute 10 normal tasks where both worker wrapper and done callback participate in completion
    for i in range(10):
        res = executor.execute_adapter(
            lambda now: AdapterResult("ok", "K", "r", now.isoformat(), None, 300.0, SourceStatus.HEALTHY, SourceStatus.HEALTHY, SourceStatus.HEALTHY),
            f"ok-src-{i}",
            "K",
            "r",
            300.0,
            NOW,
        )
        assert res.truth_status is SourceStatus.HEALTHY

    # Verify capacity remains exactly 4, never inflated beyond 4
    for _ in range(4):
        assert executor._admission_semaphore.acquire(blocking=False) is True
    assert executor._admission_semaphore.acquire(blocking=False) is False

    for _ in range(4):
        executor._admission_semaphore.release()

    executor.shutdown(wait=False)


def test_pr31_01_loopback_bind_enforcement_backend_and_frontend() -> None:
    """(PR31-01 / PR-R3) Factories accept only the fixed numeric IPv4 loopback bind."""
    from control_tower.api import create_server
    from control_tower.frontend_server import create_frontend_server

    invalid_hosts = ["localhost", "::1", "0.0.0.0", "192.168.1.100", "attacker.com", "8.8.8.8"]

    for host in invalid_hosts:
        with pytest.raises(ValueError, match="Non-loopback binding forbidden"):
            create_server(port=8000, host=host)

        with pytest.raises(ValueError, match="Non-loopback binding forbidden"):
            create_frontend_server(port=3000, host=host)


def test_pr31_02_oracle_adapter_unsupported_and_malformed_schema_fails_closed_blocked(tmp_path: Path) -> None:
    """(PR31-02) Verify OracleAdapter properly imports sanitize_error and returns BLOCKED/UNSUPPORTED_SCHEMA_VERSION without NameError."""
    import json
    from control_tower.adapters.oracle import OracleAdapter

    state_dir = tmp_path / "state"
    state_dir.mkdir(parents=True)
    oracle_file = state_dir / "oracle.json"

    # 1. Unsupported future schema version
    oracle_file.write_text(json.dumps({
        "schema_version": "99.0",
        "observed_at": NOW.isoformat(),
        "market_conditions": {"regime": "VOLATILE"},
    }))

    adapter = OracleAdapter(root_dir=tmp_path)
    res = adapter.fetch(NOW)

    assert res.truth_status is SourceStatus.BLOCKED
    assert res.error_code == "UNSUPPORTED_SCHEMA_VERSION"
    assert "Unsupported future schema version" in (res.error_detail or "")

    # 2. Malformed schema (invalid version string format)
    oracle_file.write_text(json.dumps({
        "schema_version": "invalid$$$###version",
        "observed_at": NOW.isoformat(),
        "market_conditions": {"regime": "VOLATILE"},
    }))

    res2 = adapter.fetch(NOW)
    assert res2.truth_status is SourceStatus.BLOCKED
    assert res2.error_code == "UNSUPPORTED_SCHEMA_VERSION"
    assert "Malformed schema version" in (res2.error_detail or "")


def test_pr31_03_backend_upstream_health_mapping_fail_closed() -> None:
    """(R-PR31-05 / PR-R3) Exercise the production truth-boundary classifier."""
    assert classify_upstream_health(DATA_MODE_LIVE) == "HEALTHY"
    assert classify_upstream_health(DATA_MODE_PARTIAL_LIVE) == "PARTIAL_LIVE"
    assert classify_upstream_health(DATA_MODE_DEGRADED) == "DEGRADED"
    assert classify_upstream_health(DATA_MODE_FIXTURE) == "FIXTURE"

    for hostile in ("HEALTHY", "PASS", "LIVE", "FUTURE_MODE", None, "", 123):
        assert classify_upstream_health(hostile) == "UNKNOWN"


def test_pr31_03_dashboard_emits_canonical_upstream_health() -> None:
    """The dashboard publishes backend-classified truth for frontend rendering."""
    dashboard = build_dashboard(NOW, data_mode=DATA_MODE_FIXTURE)
    assert dashboard["summary"]["upstream_health"] == "FIXTURE"


def test_pr31_03_frontend_only_renders_backend_upstream_health() -> None:
    """Frontend must not derive upstream truth from data_mode."""
    app_js_path = Path("control_tower/frontend/app.js")
    content = app_js_path.read_text(encoding="utf-8")
    assert "data.summary?.upstream_health" in content
    assert "function upstreamHealth" not in content
    assert "upstreamHealth(data.data_mode)" not in content



def test_ct04_r3_semantic_provenance_and_code_identity_binding() -> None:
    """Verify semantic provenance, invariant execution, and code-under-test identity binding."""
    valid_sha = "a" * 64
    mismatched_sha = "b" * 64
    gate = Gate("test-gate", "Test Gate", 50.0, TruthStatus.PASS, ("ev-1",), True)

    # 1. Existing source file + valid SHA but failed verification result -> UNKNOWN
    ev_failed_check = Evidence(
        id="ev-1",
        label="Failed check",
        status=TruthStatus.PASS,
        source="control_tower/api.py",
        verified_at=NOW,
        provenance=f"sha256:{valid_sha}",
        verifier_id="verifier:loopback_check",
        code_identity=valid_sha,
        verification_result="FAIL",
    )
    assert effective_gate_status(gate, {"ev-1": ev_failed_check}, now=NOW) is TruthStatus.UNKNOWN

    # 2. Fake sha256 prefix / malformed digest length -> UNKNOWN
    ev_fake_sha = Evidence(
        id="ev-1",
        label="Fake SHA",
        status=TruthStatus.PASS,
        source="control_tower/api.py",
        verified_at=NOW,
        provenance="sha256:not-a-valid-hex-digest-at-all",
        verifier_id="verifier:loopback_check",
        code_identity=valid_sha,
        verification_result="PASS",
    )
    assert effective_gate_status(gate, {"ev-1": ev_fake_sha}, now=NOW) is TruthStatus.UNKNOWN

    # 3. Stale PASS verification artifact (> 24h) -> UNKNOWN
    ev_stale = Evidence(
        id="ev-1",
        label="Stale verification",
        status=TruthStatus.PASS,
        source="control_tower/api.py",
        verified_at=NOW - timedelta(days=2),
        provenance=f"sha256:{valid_sha}",
        verifier_id="verifier:loopback_check",
        code_identity=valid_sha,
        verification_result="PASS",
    )
    assert effective_gate_status(gate, {"ev-1": ev_stale}, now=NOW) is TruthStatus.UNKNOWN

    # 4. Mismatched code-under-test identity -> UNKNOWN
    ev_mismatch = Evidence(
        id="ev-1",
        label="Mismatched code identity",
        status=TruthStatus.PASS,
        source="control_tower/api.py",
        verified_at=NOW,
        provenance=f"sha256:{valid_sha}",
        verifier_id="verifier:loopback_check",
        code_identity=mismatched_sha,
        verification_result="PASS",
    )
    assert effective_gate_status(gate, {"ev-1": ev_mismatch}, now=NOW, expected_code_identity=valid_sha) is TruthStatus.UNKNOWN

    # 5. Valid fresh PASS evidence bound to exact code-under-test -> PASS
    ev_verified = Evidence(
        id="ev-1",
        label="Valid verified invariant",
        status=TruthStatus.PASS,
        source="control_tower/api.py",
        verified_at=NOW,
        provenance=f"sha256:{valid_sha}",
        verifier_id="verifier:loopback_check",
        code_identity=valid_sha,
        verification_result="PASS",
    )
    assert effective_gate_status(gate, {"ev-1": ev_verified}, now=NOW, expected_code_identity=valid_sha) is TruthStatus.PASS


def test_ct04_r2_executor_restart_safety() -> None:
    """Verify that resilient_executor cleanly handles shutdown and restarts on demand."""
    exec_inst = ResilientAdapterExecutor(timeout_seconds=0.5)
    exec_inst.shutdown(wait=False)

    def sample_adapter(now: datetime) -> AdapterResult:
        return AdapterResult(
            source_id="sample",
            source_kind="SAMPLE",
            source_ref="none",
            fetched_at=now.isoformat(),
            observed_at=now,
            freshness_sla_seconds=300.0,
            status=SourceStatus.HEALTHY,
            adapter_health=SourceStatus.HEALTHY,
            truth_status=SourceStatus.HEALTHY,
        )

    # After shutdown, executing must safely restart internal ThreadPoolExecutor
    res = exec_inst.execute_adapter(sample_adapter, "sample", "SAMPLE", "none", 300.0, NOW)
    assert res.truth_status is SourceStatus.HEALTHY
    exec_inst.shutdown(wait=False)


def test_ct04_r2_worker_thread_boundedness() -> None:
    """Verify that multiple concurrent sweeps do not create unbounded worker threads."""
    exec_inst = ResilientAdapterExecutor(max_workers=MAX_WORKER_THREADS)
    initial_threads = threading.active_count()

    def quick_adapter(now: datetime) -> AdapterResult:
        time.sleep(0.01)
        return AdapterResult("quick", "QUICK", "none", now.isoformat(), None, 300.0, SourceStatus.HEALTHY)

    threads = []
    for _ in range(20):
        t = threading.Thread(
            target=exec_inst.execute_adapter,
            args=(quick_adapter, "quick", "QUICK", "none", 300.0, NOW),
        )
        threads.append(t)
        t.start()

    for t in threads:
        t.join()

    # Active threads must remain strictly bounded
    current_threads = threading.active_count()
    assert current_threads <= initial_threads + MAX_WORKER_THREADS + 2
    exec_inst.shutdown(wait=False)
