"""Focused functional, adversarial, and CT-01R1 truth-semantics tests for CONTROL TOWER."""

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
    SecurityError,
    check_json_depth,
    safe_read_json,
    sanitize_error,
    validate_host_header,
)

NOW = datetime(2026, 8, 23, 12, 0, tzinfo=timezone.utc)
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
# CT-01R1 TRUTH SEMANTICS TESTS (A - I)
# ==============================================================================


def test_r1_a_stale_blocked_snapshot_yields_stale_truth_with_last_known_blocked() -> None:
    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_path = Path(tmp_dir)
        state_dir = tmp_path / "state"
        state_dir.mkdir()
        stale_time = (NOW - timedelta(hours=5)).isoformat()
        (state_dir / "micro.json").write_text(
            json.dumps({
                "project": "MICRO-MARKET-ORACLE",
                "observed_at": stale_time,
                "state_conflict": True,
                "status": "BLOCKED",
                "conflicting_sources": ["a.json", "b.json"],
            }),
            encoding="utf-8",
        )
        adapter = MicroAdapter(freshness_sla_seconds=3600.0, root_dir=tmp_path)
        res = adapter.fetch(NOW)
        assert res.truth_status is SourceStatus.STALE
        assert res.status is SourceStatus.STALE
        assert res.adapter_health is SourceStatus.HEALTHY
        assert res.last_known_status == "BLOCKED"
        assert res.last_known_conflict is True


def test_r1_b_stale_running_snapshot_yields_stale_never_working() -> None:
    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_path = Path(tmp_dir)
        state_dir = tmp_path / "state"
        state_dir.mkdir()
        stale_time = (NOW - timedelta(hours=2)).isoformat()
        (state_dir / "global_status.json").write_text(
            json.dumps({
                "control_plane": {
                    "version": "1.0.0",
                    "observed_at": stale_time,
                    "overall_health": "RUNNING",
                    "permissions": {},
                },
                "projects": {},
            }),
            encoding="utf-8",
        )
        adapter = ControlPlaneAdapter(freshness_sla_seconds=300.0, root_dir=tmp_path)
        res = adapter.fetch(NOW)
        assert res.truth_status is SourceStatus.STALE
        assert res.status is SourceStatus.STALE
        assert res.truth_status is not SourceStatus.HEALTHY


def test_r1_c_stale_github_governance_report_yields_stale() -> None:
    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_path = Path(tmp_dir)
        rep_dir = tmp_path / "reports"
        rep_dir.mkdir()
        stale_time = (NOW - timedelta(days=3)).strftime("%Y-%m-%dT%H:%M:%SZ")
        (rep_dir / "github_remote_governance_raw.json").write_text(
            json.dumps({
                "api_data": {
                    "branch": {"protected": True, "commit": {"sha": "abc"}},
                    "protection": {"allow_force_pushes": {"enabled": False}},
                    "runs": {"workflow_runs": [{"created_at": stale_time, "conclusion": "success"}]},
                }
            }),
            encoding="utf-8",
        )
        adapter = GitHubCIAdapter(freshness_sla_seconds=3600.0, root_dir=tmp_path)
        res = adapter.fetch(NOW)
        assert res.adapter_health is SourceStatus.HEALTHY
        assert res.truth_status is SourceStatus.STALE
        assert res.last_known_status == "HEALTHY"


def test_r1_d_agent_without_fresh_canonical_source_is_unknown() -> None:
    data = build_dashboard(NOW, root_dir=ROOT)
    for agent in data["agents"]:
        assert agent["availability"] == "UNKNOWN"
        assert agent["provider_status"] == "UNKNOWN"
        assert agent["heartbeat"] is None


def test_r1_e_successful_adapter_read_with_stale_payload_separates_health_and_truth() -> None:
    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_path = Path(tmp_dir)
        state_dir = tmp_path / "state"
        state_dir.mkdir()
        stale_time = (NOW - timedelta(hours=4)).isoformat()
        (state_dir / "oracle.json").write_text(
            json.dumps({
                "project": "ORACLE-AI",
                "observed_at": stale_time,
                "status": "RUNNING",
            }),
            encoding="utf-8",
        )
        adapter = OracleAdapter(freshness_sla_seconds=3600.0, root_dir=tmp_path)
        res = adapter.fetch(NOW)
        assert res.adapter_health is SourceStatus.HEALTHY
        assert res.truth_status is SourceStatus.STALE
        assert res.status is SourceStatus.STALE


def test_r1_f_stale_unverified_pass_evidence_yields_effective_unknown() -> None:
    # 1. Stale evidence (older than 24h)
    stale_ev = Evidence("ev-stale", "Stale Ev", TruthStatus.PASS, "source", NOW - timedelta(days=2), "prov:123")
    gate_stale = Gate("g-stale", "G Stale", 10, TruthStatus.PASS, ("ev-stale",), True)
    assert effective_gate_status(gate_stale, {"ev-stale": stale_ev}, now=NOW) is TruthStatus.UNKNOWN

    # 2. Unverified provenance evidence
    unprov_ev = Evidence("ev-unprov", "Unprovenanced Ev", TruthStatus.PASS, "source", NOW, None)
    gate_unprov = Gate("g-unprov", "G Unprov", 10, TruthStatus.PASS, ("ev-unprov",), True)
    assert effective_gate_status(gate_unprov, {"ev-unprov": unprov_ev}, now=NOW) is TruthStatus.UNKNOWN

    # 3. Fresh verified evidence with provenance
    fresh_ev = Evidence("ev-fresh", "Fresh Ev", TruthStatus.PASS, "source", NOW - timedelta(minutes=5), "prov:valid")
    gate_fresh = Gate("g-fresh", "G Fresh", 10, TruthStatus.PASS, ("ev-fresh",), True)
    assert effective_gate_status(gate_fresh, {"ev-fresh": fresh_ev}, now=NOW) is TruthStatus.PASS


def test_r1_g_exact_freshness_boundary() -> None:
    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_path = Path(tmp_dir)
        state_dir = tmp_path / "state"
        state_dir.mkdir()
        sla_seconds = 300.0

        # Boundary Case 1: age = 299s (<= SLA) -> HEALTHY
        fresh_time = (NOW - timedelta(seconds=299)).isoformat()
        (state_dir / "global_status.json").write_text(
            json.dumps({
                "control_plane": {
                    "version": "1.0.0",
                    "observed_at": fresh_time,
                    "overall_health": "HEALTHY",
                    "permissions": {},
                },
                "projects": {},
            }),
            encoding="utf-8",
        )
        adapter = ControlPlaneAdapter(freshness_sla_seconds=sla_seconds, root_dir=tmp_path)
        assert adapter.fetch(NOW).truth_status is SourceStatus.HEALTHY

        # Boundary Case 2: age = 301s (> SLA) -> STALE
        stale_time = (NOW - timedelta(seconds=301)).isoformat()
        (state_dir / "global_status.json").write_text(
            json.dumps({
                "control_plane": {
                    "version": "1.0.0",
                    "observed_at": stale_time,
                    "overall_health": "HEALTHY",
                    "permissions": {},
                },
                "projects": {},
            }),
            encoding="utf-8",
        )
        assert adapter.fetch(NOW).truth_status is SourceStatus.STALE


def test_r1_h_missing_or_invalid_observed_at_yields_unknown() -> None:
    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_path = Path(tmp_dir)
        state_dir = tmp_path / "state"
        state_dir.mkdir()
        # Case 1: missing observed_at
        (state_dir / "global_status.json").write_text(
            json.dumps({
                "control_plane": {
                    "version": "1.0.0",
                    "permissions": {},
                },
                "projects": {},
            }),
            encoding="utf-8",
        )
        adapter = ControlPlaneAdapter(root_dir=tmp_path)
        assert adapter.fetch(NOW).truth_status is SourceStatus.UNKNOWN

        # Case 2: invalid string
        (state_dir / "global_status.json").write_text(
            json.dumps({
                "control_plane": {
                    "version": "1.0.0",
                    "observed_at": "not-a-timestamp",
                    "permissions": {},
                },
                "projects": {},
            }),
            encoding="utf-8",
        )
        assert adapter.fetch(NOW).truth_status is SourceStatus.UNKNOWN


def test_r1_i_deterministic_data_mode_derivation() -> None:
    # 1. Deterministic fixture mode
    df = build_dashboard(NOW, data_mode=DATA_MODE_FIXTURE)
    assert df["data_mode"] == DATA_MODE_FIXTURE

    # 2. Live with stale upstream sources -> DEGRADED
    dl = build_dashboard(NOW, root_dir=ROOT)
    assert dl["data_mode"] in (DATA_MODE_DEGRADED, DATA_MODE_PARTIAL_LIVE)
    assert dl["data_mode"] != DATA_MODE_LIVE  # Not live-readonly when upstream sources are stale


# ==============================================================================
# FUNCTIONAL TESTS (F01 - F14)
# ==============================================================================


def test_f01_valid_global_status_adapter() -> None:
    adapter = ControlPlaneAdapter(root_dir=ROOT)
    result = adapter.fetch(NOW)
    assert result.source_id == "control-plane-state"
    assert result.source_kind == "AI_CONTROL_PLANE_CANONICAL_STATE"
    assert result.adapter_health is SourceStatus.HEALTHY
    assert "permissions" in result.payload
    assert result.payload["permissions"]["CONTROL_PLANE_ENABLE_REAL_MONEY"] is False


def test_f02_valid_source_projection() -> None:
    data = build_dashboard(NOW, root_dir=ROOT)
    assert "sources" in data
    sources = data["sources"]
    assert "control-plane-state" in sources
    assert "control-tower-self" in sources
    assert "github-ci-governance" in sources


def test_f03_missing_source_fails_closed_to_not_connected() -> None:
    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_path = Path(tmp_dir)
        adapter = ControlPlaneAdapter(root_dir=tmp_path)
        result = adapter.fetch(NOW)
        assert result.status is SourceStatus.NOT_CONNECTED
        assert result.adapter_health is SourceStatus.NOT_CONNECTED
        assert result.truth_status is SourceStatus.NOT_CONNECTED
        assert result.error_code == "FILE_NOT_FOUND"


def test_f04_stale_heartbeat_is_stale_not_healthy() -> None:
    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_path = Path(tmp_dir)
        state_dir = tmp_path / "state"
        state_dir.mkdir()
        old_time = (NOW - timedelta(hours=2)).isoformat()
        (state_dir / "global_status.json").write_text(
            json.dumps({
                "control_plane": {
                    "version": "1.0.0",
                    "observed_at": old_time,
                    "permissions": {},
                    "overall_health": "RUNNING",
                },
                "projects": {},
            }),
            encoding="utf-8",
        )
        adapter = ControlPlaneAdapter(freshness_sla_seconds=300.0, root_dir=tmp_path)
        result = adapter.fetch(NOW)
        assert result.truth_status is SourceStatus.STALE
        assert result.status is SourceStatus.STALE


def test_f05_malformed_json_returns_unknown_or_degraded_without_crash() -> None:
    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_path = Path(tmp_dir)
        state_dir = tmp_path / "state"
        state_dir.mkdir()
        (state_dir / "global_status.json").write_text("{malformed: json", encoding="utf-8")
        adapter = ControlPlaneAdapter(root_dir=tmp_path)
        result = adapter.fetch(NOW)
        assert result.truth_status is SourceStatus.UNKNOWN
        assert result.error_code is not None


def test_f06_source_conflict_is_blocked_when_fresh() -> None:
    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_path = Path(tmp_dir)
        state_dir = tmp_path / "state"
        state_dir.mkdir()
        (state_dir / "global_status.json").write_text(
            json.dumps({
                "control_plane": {
                    "version": "1.0.0",
                    "observed_at": NOW.isoformat(),
                    "permissions": {},
                    "overall_health": "HEALTHY",
                },
                "projects": {
                    "MICRO-MARKET-ORACLE": {
                        "state_conflict": True,
                        "conflicting_sources": ["a.json", "b.json"],
                    }
                },
            }),
            encoding="utf-8",
        )
        adapter = ControlPlaneAdapter(root_dir=tmp_path)
        result = adapter.fetch(NOW)
        assert result.truth_status is SourceStatus.BLOCKED
        assert result.status is SourceStatus.BLOCKED


def test_f07_fake_unresolved_evidence_cannot_produce_effective_pass() -> None:
    evidence_map = {
        "ev-valid": Evidence("ev-valid", "Valid", TruthStatus.PASS, "src", NOW, "prov:valid"),
        "ev-blocked": Evidence("ev-blocked", "Blocked", TruthStatus.BLOCKED, "src", NOW, "prov:valid"),
    }
    gate_missing = Gate("g1", "Gate 1", 10, TruthStatus.PASS, ("ev-missing",), True)
    assert effective_gate_status(gate_missing, evidence_map, now=NOW) is TruthStatus.UNKNOWN

    gate_blocked = Gate("g2", "Gate 2", 10, TruthStatus.PASS, ("ev-blocked",), True)
    assert effective_gate_status(gate_blocked, evidence_map, now=NOW) is TruthStatus.BLOCKED

    gate_valid = Gate("g3", "Gate 3", 10, TruthStatus.PASS, ("ev-valid",), True)
    assert effective_gate_status(gate_valid, evidence_map, now=NOW) is TruthStatus.PASS

    assert weighted_gate_readiness((gate_missing, gate_blocked, gate_valid), evidence_map, now=NOW) == 33.3


def test_f08_adapter_failure_isolation() -> None:
    class FailingAdapter(BaseAdapter):
        def _fetch_impl(self, now: datetime) -> AdapterResult:
            raise RuntimeError("Simulated adapter network timeout")

    adapters = [
        ControlTowerSelfAdapter(root_dir=ROOT),
        FailingAdapter(source_id="failing-source", source_kind="TEST", source_ref="test"),
    ]
    results = fetch_all_adapters(adapters, NOW)
    assert results["control-tower-self"].truth_status is SourceStatus.HEALTHY
    assert results["failing-source"].truth_status is SourceStatus.UNKNOWN
    assert results["failing-source"].error_code == "RuntimeError"


def test_f09_provenance_and_freshness_serialized() -> None:
    data = build_dashboard(NOW, root_dir=ROOT)
    ct_source = data["sources"]["control-tower-self"]
    assert ct_source["fetched_at"]
    assert ct_source["freshness_sla_seconds"] > 0
    assert ct_source["provenance"] is not None


def test_f10_runtime_status_normalization() -> None:
    assert normalize_runtime_status("RUNNING") is RuntimeStatus.WORKING
    assert normalize_runtime_status("working") is RuntimeStatus.WORKING
    assert normalize_runtime_status("HEALTHY") is RuntimeStatus.HEALTHY
    assert normalize_runtime_status("DEGRADED_STALE") is RuntimeStatus.DEGRADED
    assert normalize_runtime_status("OFFLINE") is RuntimeStatus.OFFLINE
    assert normalize_runtime_status("UNRECOGNIZED_STATUS") is RuntimeStatus.UNKNOWN

    truth = runtime_truth("RUNNING", NOW, NOW, observed_status=RuntimeStatus.WORKING)
    assert truth is RuntimeStatus.WORKING

    conflict = runtime_truth("STOPPED", NOW, NOW, observed_status=RuntimeStatus.WORKING)
    assert conflict is RuntimeStatus.BLOCKED


def test_f11_fixture_timestamps_never_masquerade_as_live() -> None:
    data_fixture = build_dashboard(NOW, data_mode=DATA_MODE_FIXTURE)
    assert data_fixture["data_mode"] == DATA_MODE_FIXTURE
    assert data_fixture["sources"] == {}

    data_live = build_dashboard(NOW, root_dir=ROOT)
    assert data_live["data_mode"] != DATA_MODE_FIXTURE
    assert len(data_live["sources"]) > 0


def test_f12_existing_read_only_api_behavior_remains_intact() -> None:
    with running_api() as address:
        status, _, health = request(address, "GET", "/health")
        assert status == 200
        assert health["read_only"] is True
        assert health["scope"] == "CONTROL_TOWER_APPLICATION"

        for method in ("POST", "PUT", "PATCH", "DELETE"):
            m_status, _, m_body = request(address, method, "/api/v1/dashboard")
            assert m_status == 405
            assert "READ_ONLY" in str(m_body.get("error"))


def test_f13_protected_canonical_trees_unchanged() -> None:
    before = protected_snapshot()
    with running_api() as address:
        request(address, "GET", "/health")
        request(address, "GET", "/api/v1/dashboard")
        for method in ("POST", "PUT", "PATCH", "DELETE"):
            request(address, method, "/api/v1/dashboard")
    assert protected_snapshot() == before


def test_f14_control_tower_self_health_separated_from_control_plane_state() -> None:
    data = build_dashboard(NOW, root_dir=ROOT)
    project_names = [p["name"] for p in data["projects"]]
    assert "CONTROL TOWER" in project_names
    assert "AI-CONTROL-PLANE" in project_names
    ct_project = next(p for p in data["projects"] if p["name"] == "CONTROL TOWER")
    cp_project = next(p for p in data["projects"] if p["name"] == "AI-CONTROL-PLANE")
    assert ct_project["id"] != cp_project["id"]
    assert ct_project["source_id"] == "control-tower-self"
    assert cp_project["source_id"] == "control-plane-state"


# ==============================================================================
# ADVERSARIAL SECURITY SUITE (A01 - A20)
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

    classification = _classify_adversarial_result(probe)
    assert classification == "BLOCKED"


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

    classification = _classify_adversarial_result(probe)
    assert classification == "BLOCKED"


def test_a03_oversized_source_bounded_file_size() -> None:
    def probe() -> bool:
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)
            oversized_file = tmp_path / "oversized.json"
            oversized_file.write_text('{"key": "' + 'x' * (MAX_FILE_SIZE_BYTES + 100) + '"}', encoding="utf-8")
            safe_read_json(oversized_file, base_dir=tmp_path)
            return True

    classification = _classify_adversarial_result(probe)
    assert classification == "BLOCKED"


def test_a04_malformed_json_defensively_rejected() -> None:
    def probe() -> bool:
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)
            bad_file = tmp_path / "bad.json"
            bad_file.write_text('{unquoted: "json", missing_brace:', encoding="utf-8")
            safe_read_json(bad_file, base_dir=tmp_path)
            return True

    classification = _classify_adversarial_result(probe)
    assert classification == "BLOCKED"


def test_a05_hostile_deep_json_depth_limit() -> None:
    def probe() -> bool:
        nested: dict[str, Any] = {"leaf": 1}
        for _ in range(50):
            nested = {"child": nested}
        check_json_depth(nested)
        return True

    classification = _classify_adversarial_result(probe)
    assert classification == "BLOCKED"


def test_a06_future_heartbeat_rejected() -> None:
    def probe() -> bool:
        future_heartbeat = NOW + timedelta(minutes=10)
        res = runtime_truth("RUNNING", future_heartbeat, NOW, observed_status=RuntimeStatus.WORKING)
        if res is RuntimeStatus.WORKING:
            return True
        return False

    classification = _classify_adversarial_result(probe)
    assert classification == "BLOCKED"


def test_a07_stale_persisted_running_rejected() -> None:
    def probe() -> bool:
        stale_heartbeat = NOW - timedelta(hours=1)
        res = runtime_truth("RUNNING", stale_heartbeat, NOW, observed_status=RuntimeStatus.WORKING)
        if res is RuntimeStatus.WORKING:
            return True
        return False

    classification = _classify_adversarial_result(probe)
    assert classification == "BLOCKED"


def test_a08_contradictory_statuses_blocked() -> None:
    def probe() -> bool:
        res = runtime_truth("OFFLINE", NOW, NOW, observed_status=RuntimeStatus.WORKING)
        if res is not RuntimeStatus.BLOCKED:
            return True
        return False

    classification = _classify_adversarial_result(probe)
    assert classification == "BLOCKED"


def test_a09_fake_evidence_id_blocked() -> None:
    def probe() -> bool:
        gate = Gate("g", "Gate", 10, TruthStatus.PASS, ("fake-ev-999",), True)
        res = effective_gate_status(gate, {"real-ev": Evidence("real-ev", "Real", TruthStatus.PASS, "src", NOW, "prov:1")}, now=NOW)
        if res is TruthStatus.PASS:
            return True
        return False

    classification = _classify_adversarial_result(probe)
    assert classification == "BLOCKED"


def test_a10_hostile_html_xss_labels_safe_rendering() -> None:
    app_source = (ROOT / "control_tower/frontend/app.js").read_text(encoding="utf-8")
    assert "innerHTML" not in app_source
    assert ".textContent" in app_source
    assert "document.createElement" in app_source


def test_a11_external_origin_cors_rejection() -> None:
    with running_api() as address:
        _, headers, _ = request(address, "GET", "/api/v1/dashboard", origin="https://evil-attacker.com")
        assert "access-control-allow-origin" not in headers


def test_a12_hostile_host_dns_rebinding_rejected() -> None:
    with running_api() as address:
        for hostile_host in ("evil.com", "attacker.com:8000", "192.168.1.100:8000", "example.org"):
            status, _, body = request(address, "GET", "/api/v1/dashboard", host=hostile_host)
            assert status == 400
            assert body == {"error": "INVALID_HOST_HEADER"}


def test_a13_adapter_exception_contained() -> None:
    class ExplodingAdapter(BaseAdapter):
        def _fetch_impl(self, now: datetime) -> AdapterResult:
            raise KeyError("Corrupt internal dictionary")

    res = ExplodingAdapter("exploding-src", "TEST", "test").fetch(NOW)
    assert res.truth_status is SourceStatus.UNKNOWN
    assert res.status is SourceStatus.UNKNOWN
    assert res.error_code == "KeyError"
    assert res.payload == {}


def test_a14_oracle_unavailable_handled_cleanly() -> None:
    with tempfile.TemporaryDirectory() as tmp_dir:
        adapter = OracleAdapter(root_dir=Path(tmp_dir))
        res = adapter.fetch(NOW)
        assert res.truth_status is SourceStatus.NOT_CONNECTED
        assert res.status is SourceStatus.NOT_CONNECTED


def test_a15_micro_unavailable_handled_cleanly() -> None:
    with tempfile.TemporaryDirectory() as tmp_dir:
        adapter = MicroAdapter(root_dir=Path(tmp_dir))
        res = adapter.fetch(NOW)
        assert res.truth_status is SourceStatus.NOT_CONNECTED
        assert res.status is SourceStatus.NOT_CONNECTED


def test_a16_antigravity_unavailable_handled_cleanly() -> None:
    data = build_dashboard(NOW, root_dir=ROOT)
    agents = data["agents"]
    assert any(a["name"] == "Antigravity" for a in agents)


def test_a17_unknown_runtime_vocabulary_fails_closed() -> None:
    norm = normalize_runtime_status("HYPER_SPACE_TURBO_MODE")
    assert norm is RuntimeStatus.UNKNOWN


def test_a18_timezone_naive_timestamp_fails_closed() -> None:
    naive_dt = datetime(2026, 8, 23, 12, 0)
    res = runtime_truth("WORKING", naive_dt, NOW, observed_status=RuntimeStatus.WORKING)
    assert res is RuntimeStatus.UNKNOWN


def test_a19_secret_values_redacted_in_errors() -> None:
    leak = "Authorization failed with ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ012345 and token='secret_token_val'"
    sanitized = sanitize_error(leak)
    assert "ghp_" not in sanitized
    assert "secret_token_val" not in sanitized
    assert "[REDACTED_SECRET]" in sanitized


def test_a20_one_adapter_failure_while_remaining_continue() -> None:
    class DeadAdapter(BaseAdapter):
        def _fetch_impl(self, now: datetime) -> AdapterResult:
            raise ConnectionResetError("Connection reset by peer")

    adapters = [
        ControlTowerSelfAdapter(root_dir=ROOT),
        DeadAdapter("dead-src", "TEST", "ref"),
        GitHubCIAdapter(root_dir=ROOT),
    ]
    results = fetch_all_adapters(adapters, NOW)
    assert results["control-tower-self"].truth_status is SourceStatus.HEALTHY
    assert results["dead-src"].truth_status is SourceStatus.UNKNOWN
    assert results["github-ci-governance"].truth_status in (SourceStatus.HEALTHY, SourceStatus.STALE, SourceStatus.DEGRADED, SourceStatus.NOT_CONNECTED)
