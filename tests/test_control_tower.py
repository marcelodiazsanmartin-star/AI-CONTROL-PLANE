"""Focused functional and adversarial tests for CONTROL TOWER Phase 0."""

from __future__ import annotations

import hashlib
import json
import threading
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from http.client import HTTPConnection
from pathlib import Path
from typing import Iterator

from control_tower.api import ALLOWED_ORIGINS, LOOPBACK_HOST, create_server
from control_tower.calculations import (
    effective_gate_status,
    runtime_truth,
    weighted_gate_readiness,
    weighted_milestone_progress,
)
from control_tower.fixtures import DATA_MODE, build_dashboard
from control_tower.models import Gate, Milestone, RuntimeStatus, TruthStatus

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
) -> tuple[int, dict[str, str], dict[str, object]]:
    headers = {"Origin": origin} if origin else {}
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
                snapshot[str(path.relative_to(ROOT))] = hashlib.sha256(path.read_bytes()).hexdigest()
    return snapshot


def test_weighted_progress_calculation() -> None:
    milestones = (Milestone("a", "A", 1, 100), Milestone("b", "B", 3, 0))
    assert weighted_milestone_progress(milestones) == 25.0


def test_no_milestones_is_unknown() -> None:
    assert weighted_milestone_progress(()) is None


def test_zero_and_negative_weights_fail_closed() -> None:
    assert weighted_milestone_progress((Milestone("a", "A", 0, 100),)) is None
    assert weighted_gate_readiness((Gate("g", "G", -1, TruthStatus.PASS),)) is None


def test_malformed_progress_fails_closed() -> None:
    malformed = Milestone("a", "A", 1, "not-a-number")  # type: ignore[arg-type]
    assert weighted_milestone_progress((malformed,)) is None


def test_incomplete_evidence_and_false_pass_are_unknown() -> None:
    gate = Gate("g", "Gate", 1, TruthStatus.PASS, ("ev",), False)
    assert weighted_gate_readiness((gate,)) == 0.0
    assert effective_gate_status(gate) is TruthStatus.UNKNOWN


def test_unknown_gate_earns_no_readiness() -> None:
    gate = Gate("g", "Gate", 1, TruthStatus.UNKNOWN)
    assert weighted_gate_readiness((gate,)) == 0.0


def test_gate_blocker_propagates() -> None:
    gate = Gate("g", "Gate", 1, TruthStatus.PASS, ("ev",), True, "review")
    assert effective_gate_status(gate) is TruthStatus.BLOCKED
    assert weighted_gate_readiness((gate,)) == 0.0


def test_stale_heartbeat_never_working() -> None:
    result = runtime_truth(
        "WORKING", NOW - timedelta(minutes=6), NOW, observed_status=RuntimeStatus.WORKING
    )
    assert result is RuntimeStatus.STALE


def test_missing_and_invalid_heartbeat_are_unknown() -> None:
    assert runtime_truth("WORKING", None, NOW, observed_status=RuntimeStatus.WORKING) is RuntimeStatus.UNKNOWN
    assert runtime_truth("WORKING", "invalid", NOW, observed_status=RuntimeStatus.WORKING) is RuntimeStatus.UNKNOWN  # type: ignore[arg-type]


def test_future_heartbeat_is_unknown() -> None:
    result = runtime_truth(
        "WORKING", NOW + timedelta(minutes=1), NOW, observed_status=RuntimeStatus.WORKING
    )
    assert result is RuntimeStatus.UNKNOWN


def test_persisted_running_without_observation_is_unknown() -> None:
    result = runtime_truth("RUNNING", NOW - timedelta(seconds=1), NOW)
    assert result is RuntimeStatus.UNKNOWN


def test_conflicting_state_is_blocked() -> None:
    result = runtime_truth(
        "HEALTHY", NOW - timedelta(seconds=1), NOW, observed_status=RuntimeStatus.DEGRADED
    )
    assert result is RuntimeStatus.BLOCKED


def test_explicit_runtime_blocker_propagates() -> None:
    result = runtime_truth(None, NOW, NOW, observed_status=RuntimeStatus.HEALTHY, blocker="approval")
    assert result is RuntimeStatus.BLOCKED


def test_fixture_mode_and_source_of_truth_are_explicit() -> None:
    data = build_dashboard(NOW)
    assert data["data_mode"] == DATA_MODE == "DETERMINISTIC_FIXTURE"
    assert data["dashboard_is_source_of_truth"] is False


def test_human_approval_is_visible_but_not_executable() -> None:
    data = build_dashboard(NOW)
    approval = data["approvals"][0]
    assert data["summary"]["human_approval_required"] is True
    assert approval["reason"]
    assert approval["requested_at"]
    assert approval["execution_enabled"] is False


def test_security_policy_is_strictly_read_only() -> None:
    security = build_dashboard(NOW)["security"]
    assert security["read_only"] is True
    assert not any(value for key, value in security.items() if key != "read_only")


def test_no_fabricated_pass_for_project_gates() -> None:
    for project in build_dashboard(NOW)["projects"]:
        for gate in project["certification_gates"] + project["operational_gates"]:
            assert gate["effective_status"] != "PASS"


def test_unconnected_projects_expose_required_unknown_contract() -> None:
    data = build_dashboard(NOW)
    oracle = data["projects"][1]["domain"]
    micro = data["projects"][2]["domain"]
    assert oracle["collector_status"] == "NOT_CONNECTED"
    assert oracle["realized_pnl"] == oracle["slippage"] == "UNKNOWN"
    assert micro["discovery_runtime"] == micro["scheduler"] == "NOT_CONNECTED"
    assert micro["last_run"] == "UNKNOWN"


def test_api_get_endpoints_and_health_scope() -> None:
    with running_api() as address:
        health_status, _, health = request(address, "GET", "/health")
        api_status, _, dashboard = request(address, "GET", "/api/v1/dashboard?local=1")
    assert health_status == api_status == 200
    assert health == {
        "status": "HEALTHY",
        "scope": "CONTROL_TOWER_APPLICATION",
        "read_only": True,
        "upstream_systems_included": False,
    }
    assert dashboard["schema_version"] == "control-tower.phase0.v1"


def test_all_mutations_are_rejected_on_valid_and_invalid_paths() -> None:
    with running_api() as address:
        for method in ("POST", "PUT", "PATCH", "DELETE"):
            for path in ("/api/v1/dashboard", "/not-a-route"):
                status, _, body = request(address, method, path)
                assert status == 405
                assert body == {"error": "READ_ONLY_PHASE_0"}


def test_cors_allowlist_and_external_origin_rejection() -> None:
    assert ALLOWED_ORIGINS == {
        "http://localhost:3000",
        "http://127.0.0.1:3000",
    }
    with running_api() as address:
        for origin in ALLOWED_ORIGINS:
            status, headers, _ = request(address, "GET", "/api/v1/dashboard", origin)
            assert status == 200
            assert headers["access-control-allow-origin"] == origin
        _, external_headers, _ = request(
            address, "GET", "/api/v1/dashboard", "https://external.example"
        )
    assert "access-control-allow-origin" not in external_headers


def test_backend_is_hardcoded_to_ipv4_loopback() -> None:
    with running_api() as address:
        assert address[0] == LOOPBACK_HOST == "127.0.0.1"


def test_frontend_uses_safe_dom_text_rendering_for_untrusted_data() -> None:
    source = (ROOT / "control_tower/frontend/app.js").read_text(encoding="utf-8")
    hostile = ("<script>alert(1)</script>", "<img src=x onerror=alert(1)>")
    assert "innerHTML" not in source
    assert ".textContent" in source
    assert "document.createElement" in source
    for value in hostile:
        assert value not in source


def test_frontend_api_and_fixture_banner_are_explicit() -> None:
    app = (ROOT / "control_tower/frontend/app.js").read_text(encoding="utf-8")
    html = (ROOT / "control_tower/frontend/index.html").read_text(encoding="utf-8")
    assert 'http://127.0.0.1:8000/api/v1/dashboard' in app
    assert "DATA MODE:" in app
    assert 'connect-src http://127.0.0.1:8000' in html
    for forbidden in (">APPROVE<", ">REJECT<", ">EXECUTE<", ">LIVE<", ">CHANGE RISK<"):
        assert forbidden not in html.upper()


def test_api_requests_do_not_mutate_protected_trees() -> None:
    before = protected_snapshot()
    with running_api() as address:
        request(address, "GET", "/health")
        request(address, "GET", "/api/v1/dashboard")
        for method in ("POST", "PUT", "PATCH", "DELETE"):
            request(address, method, "/api/v1/dashboard")
    assert protected_snapshot() == before
