"""AF-02 required functional verification on disposable SQLite stores."""
import hashlib
import inspect
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier

import pytest

from src.autonomy import (
    AckEnvelope,
    AgentRouter,
    AutonomyStore,
    BlockedError,
    DisposableExternalSession,
    EvidenceReference,
    HeartbeatEnvelope,
    ImmutableLocalEvidenceResolver,
    LocalWorkerGateway,
    ResultEnvelope,
    SessionHello,
    WorkerProfile,
)

EVIDENCE_BYTES = b"verified AF-02 disposable evidence"
EVIDENCE_SHA256 = hashlib.sha256(EVIDENCE_BYTES).hexdigest()


def profile(worker_id="ext-a", **changes):
    values = {
        "worker_id": worker_id,
        "worker_kind": "local-disposable",
        "capabilities": ("READ",),
        "allowed_targets": ("TEST",),
        "max_capacity": 1,
        "heartbeat_sla": 10.0,
    }
    values.update(changes)
    return WorkerProfile(**values)


def environment(
    tmp_path, profiles=None, *, connect=True, now=100, evidence_resolver=None
):
    store = AutonomyStore(tmp_path / "af02.sqlite", busy_timeout_ms=10)
    configured = tuple(profiles or (profile(),))
    resolver = evidence_resolver or ImmutableLocalEvidenceResolver()
    resolver.declare("evidence-a", EVIDENCE_BYTES)
    gateway = LocalWorkerGateway(store, configured, evidence_resolver=resolver)
    sessions = []
    if connect:
        for index, item in enumerate(configured):
            session = DisposableExternalSession(
                gateway, item, session_id=f"session-{index}"
            )
            session.connect(now=now)
            sessions.append(session)
    return store, gateway, AgentRouter(store, gateway), sessions


def task(store, task_id="task-a", **changes):
    values = {
        "task_id": task_id,
        "directive_id": "directive-" + task_id,
        "target_project": "TEST",
        "capability": "READ",
        "governance_allowed": True,
        "retry_budget": 1,
        "now": 100,
    }
    values.update(changes)
    return store.create_task(**values)


def ack(dispatch, *, now=101, **changes):
    values = {
        "dispatch_id": dispatch.dispatch_id,
        "task_id": dispatch.task_id,
        "worker_id": dispatch.worker_id,
        "session_id": dispatch.session_id,
        "lease_id": dispatch.lease_id,
        "observed_at": now,
    }
    values.update(changes)
    return AckEnvelope(**values)


def result(dispatch, *, now=102, **changes):
    values = {
        "dispatch_id": dispatch.dispatch_id,
        "task_id": dispatch.task_id,
        "worker_id": dispatch.worker_id,
        "session_id": dispatch.session_id,
        "lease_id": dispatch.lease_id,
        "observed_at": now,
        "status": "SUCCEEDED",
        "evidence": (EvidenceReference("evidence-a", EVIDENCE_SHA256),),
    }
    values.update(changes)
    return ResultEnvelope(**values)


def test_f01_eligible_task_worker_routes_exactly_once(tmp_path):
    store, _, router, _ = environment(tmp_path)
    task(store)
    routed = router.route_once(now=100)
    assert len(routed) == 1
    assert router.route_once(now=100) == []
    assert store.task("task-a")["state"] == "LEASED"


def test_f02_missing_provider_truth_waits_without_dispatch(tmp_path):
    store, _, router, _ = environment(tmp_path, connect=False)
    task(store)
    assert router.route_once(now=100) == []
    assert store.task("task-a")["state"] == "WAITING_CAPACITY"


def test_f03_capability_mismatch_is_rejected(tmp_path):
    store, _, router, _ = environment(
        tmp_path, (profile(capabilities=("OBSERVE",)),)
    )
    task(store)
    assert router.route_once(now=100) == []


def test_f04_target_mismatch_is_rejected(tmp_path):
    store, _, router, _ = environment(
        tmp_path, (profile(allowed_targets=("OTHER",)),)
    )
    task(store)
    assert router.route_once(now=100) == []


def test_f05_stale_heartbeat_is_rejected(tmp_path):
    store, _, router, _ = environment(tmp_path)
    task(store)
    assert router.route_once(now=111) == []
    assert store.task("task-a")["state"] == "WAITING_CAPACITY"


def test_f06_capacity_exhaustion_is_rejected(tmp_path):
    store, _, router, _ = environment(tmp_path)
    task(store, "task-a")
    task(store, "task-b")
    routed = router.route_once(now=100)
    assert len(routed) == 1
    assert store.task("task-b")["state"] == "WAITING_CAPACITY"


def test_f06b_concurrent_routers_different_tasks_respect_capacity_one(tmp_path):
    database = tmp_path / "capacity.sqlite"
    seed = AutonomyStore(database, busy_timeout_ms=2000)
    task(seed, "task-1")
    task(seed, "task-2")
    seed.close()
    barrier = Barrier(2)

    def route(index):
        store = AutonomyStore(database, busy_timeout_ms=2000)
        gateway = LocalWorkerGateway(store, (profile(),))
        DisposableExternalSession(
            gateway, profile(), session_id="shared-session"
        ).connect(now=100)
        router = AgentRouter(store, gateway, batch_size=2)
        barrier.wait(timeout=5)
        dispatched = router.route_once(now=100)
        store.close()
        return dispatched

    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = list(pool.map(route, range(2)))
    verify = AutonomyStore(database)
    states = {verify.task(task_id)["state"] for task_id in ("task-1", "task-2")}
    status = verify.worker_status("ext-a", now=100)
    dispatch_count = sum(len(items) for items in outcomes)
    assert dispatch_count == 1
    assert states == {"LEASED", "WAITING_CAPACITY"}
    assert status["active_lease_count"] == 1
    assert len({item.task_id for items in outcomes for item in items}) == 1


def test_f06c_heartbeat_capacity_update_is_atomic_against_claim(tmp_path):
    database = tmp_path / "heartbeat-capacity.sqlite"
    heartbeat_store = AutonomyStore(database, busy_timeout_ms=2000)
    item = profile()
    gateway = LocalWorkerGateway(heartbeat_store, (item,))
    DisposableExternalSession(gateway, item, session_id="atomic-session").connect(
        now=100
    )
    task(heartbeat_store)
    claim_store = AutonomyStore(database, busy_timeout_ms=2000)
    barrier = Barrier(2)

    def publish_zero_capacity():
        barrier.wait(timeout=5)
        gateway.heartbeat(
            HeartbeatEnvelope("ext-a", "atomic-session", 1, 111, 0), now=111
        )
        return "UPDATED"

    def attempt_claim():
        barrier.wait(timeout=5)
        try:
            claim_store.claim("task-a", "ext-a", now=111)
        except BlockedError:
            return "BLOCKED"
        return "BYPASS_DETECTED"

    with ThreadPoolExecutor(max_workers=2) as pool:
        update_result = pool.submit(publish_zero_capacity)
        claim_result = pool.submit(attempt_claim)
        assert update_result.result() == "UPDATED"
        assert claim_result.result() == "BLOCKED"
    worker = heartbeat_store.worker_status("ext-a", now=111)
    assert worker["last_heartbeat"] == 111
    assert worker["capacity"] == 0
    assert heartbeat_store.task("task-a")["state"] == "QUEUED"


def test_f06d_waiting_capacity_and_audit_are_atomic_against_claim(tmp_path):
    database = tmp_path / "waiting-race.sqlite"
    seed = AutonomyStore(database, busy_timeout_ms=2000)
    item = profile()
    seed_gateway = LocalWorkerGateway(seed, (item,))
    DisposableExternalSession(
        seed_gateway, item, session_id="waiting-session"
    ).connect(now=100)
    task(seed)
    seed.close()
    barrier = Barrier(2)

    def claim_task():
        store = AutonomyStore(database, busy_timeout_ms=2000)
        barrier.wait(timeout=5)
        lease = store.claim("task-a", "ext-a", now=100)
        store.close()
        return lease

    def mark_waiting():
        store = AutonomyStore(database, busy_timeout_ms=2000)
        barrier.wait(timeout=5)
        try:
            store.mark_waiting_capacity("task-a", now=100)
            outcome = "UPDATED"
        except BlockedError:
            outcome = "BLOCKED"
        store.close()
        return outcome

    with ThreadPoolExecutor(max_workers=2) as pool:
        claim_future = pool.submit(claim_task)
        waiting_future = pool.submit(mark_waiting)
        lease = claim_future.result()
        waiting_outcome = waiting_future.result()
    verify = AutonomyStore(database)
    waiting_events = [
        event
        for event in verify.audit_events("task-a")
        if event["event"] == "WAITING_CAPACITY"
    ]
    assert lease["task_id"] == "task-a"
    assert verify.task("task-a")["state"] == "LEASED"
    assert len(waiting_events) == (1 if waiting_outcome == "UPDATED" else 0)


def test_f06e_waiting_capacity_rolls_back_if_audit_fails(tmp_path, monkeypatch):
    store = AutonomyStore(tmp_path / "waiting-rollback.sqlite")
    task(store)

    def fail_audit(*args, **kwargs):
        raise sqlite3.ProgrammingError("injected audit misuse")

    monkeypatch.setattr(store, "audit", fail_audit)
    with pytest.raises(sqlite3.ProgrammingError):
        store.mark_waiting_capacity("task-a", now=100)
    assert store.task("task-a")["state"] == "QUEUED"
    assert not store.db.in_transaction


@pytest.mark.parametrize(
    "field,value",
    (
        ("task_id", "forged-task"),
        ("worker_id", "forged-worker"),
        ("session_id", "forged-session"),
        ("lease_id", "forged-lease"),
    ),
)
def test_f07_ack_requires_exact_four_way_binding(tmp_path, field, value):
    store, gateway, router, _ = environment(tmp_path)
    task(store)
    dispatch = router.route_once(now=100)[0]
    with pytest.raises(BlockedError):
        gateway.acknowledge(ack(dispatch, **{field: value}), now=101)


def test_f08_expired_lease_cannot_ack_start_or_result(tmp_path):
    store, gateway, router, _ = environment(tmp_path)
    router.lease_seconds = 2
    task(store)
    dispatch = router.route_once(now=100)[0]
    with pytest.raises(BlockedError):
        gateway.acknowledge(ack(dispatch, now=103), now=103)
    with pytest.raises(BlockedError):
        store.start(dispatch.task_id, dispatch.worker_id, dispatch.lease_id, now=103)
    with pytest.raises(BlockedError):
        gateway.result(result(dispatch, now=103), now=103)


def test_f08b_duplicate_ack_revalidates_expiry(tmp_path):
    store, gateway, router, _ = environment(tmp_path)
    router.lease_seconds = 2
    task(store)
    dispatch = router.route_once(now=100)[0]
    gateway.acknowledge(ack(dispatch, now=101), now=101)
    with pytest.raises(BlockedError):
        gateway.acknowledge(ack(dispatch, now=103), now=103)


def test_f09_reconnect_cannot_resurrect_stale_lease(tmp_path):
    store, _, router, _ = environment(tmp_path)
    router.lease_seconds = 2
    task(store)
    dispatch = router.route_once(now=100)[0]
    replacement = LocalWorkerGateway(store, (profile(),))
    DisposableExternalSession(replacement, profile(), session_id="new-session").connect(
        now=103
    )
    with pytest.raises(BlockedError):
        replacement.acknowledge(ack(dispatch, now=103), now=103)


def test_f10_duplicate_dispatch_is_idempotent(tmp_path):
    store, gateway, router, _ = environment(tmp_path)
    original_task = task(store)
    dispatch = router.route_once(now=100)[0]
    lease = {
        "task_id": dispatch.task_id,
        "worker_id": dispatch.worker_id,
        "lease_id": dispatch.lease_id,
    }
    assert gateway.dispatch(
        original_task, lease, session_id=dispatch.session_id, now=100
    ) == dispatch
    events = [e for e in store.audit_events("task-a") if e["event"] == "DISPATCHED"]
    assert len(events) == 1


def test_f10b_selected_session_replacement_before_dispatch_is_blocked(
    tmp_path, monkeypatch
):
    store, gateway, router, _ = environment(tmp_path)
    task(store)
    monkeypatch.setattr(
        gateway,
        "eligible_sessions",
        lambda **kwargs: [("ext-a", "replaced-session")],
    )
    assert router.route_once(now=100) == []
    events = store.audit_events("task-a")
    assert [event for event in events if event["event"] == "ROUTED"]
    assert not [event for event in events if event["event"] == "DISPATCHED"]


@pytest.mark.parametrize(
    "field,value",
    (
        ("capability", "FORGED"),
        ("target_project", "FORGED"),
        ("task_id", "forged-task"),
    ),
)
def test_f10c_dispatch_rejects_caller_payload_mismatch(tmp_path, field, value):
    store, gateway, router, _ = environment(tmp_path)
    original = task(store)
    dispatch = router.route_once(now=100)[0]
    forged = {**original, field: value}
    lease = {
        "task_id": dispatch.task_id,
        "worker_id": dispatch.worker_id,
        "lease_id": dispatch.lease_id,
    }
    with pytest.raises(BlockedError):
        gateway.dispatch(
            forged, lease, session_id=dispatch.session_id, now=100
        )


def test_f10d_dispatch_audit_failure_never_publishes_projection(
    tmp_path, monkeypatch
):
    store, gateway, _, _ = environment(tmp_path)
    original_task = task(store)
    lease = store.claim("task-a", "ext-a", now=100)
    original_audit = store.audit

    def fail_dispatch_audit(task_id, event, now, details=""):
        if event == "DISPATCHED":
            raise sqlite3.ProgrammingError("injected dispatch audit failure")
        return original_audit(task_id, event, now, details)

    monkeypatch.setattr(store, "audit", fail_dispatch_audit)
    for _ in range(2):
        with pytest.raises(sqlite3.ProgrammingError):
            gateway.dispatch(
                original_task,
                lease,
                session_id="session-0",
                now=100,
            )
        assert gateway.dispatch_projection() == []
    monkeypatch.setattr(store, "audit", original_audit)
    envelope = gateway.dispatch(
        original_task, lease, session_id="session-0", now=100
    )
    assert envelope.task_id == "task-a"
    assert len(gateway.dispatch_projection()) == 1
    assert len(
        [event for event in store.audit_events("task-a") if event["event"] == "DISPATCHED"]
    ) == 1


def test_f11_out_of_order_heartbeat_ack_and_result_are_rejected(tmp_path):
    store, gateway, router, sessions = environment(tmp_path)
    task(store)
    dispatch = router.route_once(now=100)[0]
    with pytest.raises(BlockedError):
        gateway.heartbeat(
            HeartbeatEnvelope("ext-a", "session-0", 0, 100, 1), now=100
        )
    with pytest.raises(BlockedError):
        gateway.result(result(dispatch), now=102)
    gateway.acknowledge(ack(dispatch), now=101)
    sessions[0].heartbeat(now=102)


def test_f11b_result_cannot_precede_ack_observation(tmp_path):
    store, gateway, router, _ = environment(tmp_path)
    task(store)
    dispatch = router.route_once(now=100)[0]
    gateway.acknowledge(ack(dispatch, now=102), now=102)
    with pytest.raises(BlockedError):
        gateway.result(result(dispatch, now=101), now=102)


def test_f11c_ack_audit_failure_rolls_back_running_and_recovers(
    tmp_path, monkeypatch
):
    store, gateway, router, _ = environment(tmp_path)
    task(store)
    dispatch = router.route_once(now=100)[0]
    original_audit = store.audit

    def fail_ack_audit(task_id, event, now, details=""):
        if event == "ACKED":
            raise sqlite3.ProgrammingError("injected ack audit failure")
        return original_audit(task_id, event, now, details)

    monkeypatch.setattr(store, "audit", fail_ack_audit)
    with pytest.raises(sqlite3.ProgrammingError):
        gateway.acknowledge(ack(dispatch), now=101)
    assert store.task("task-a")["state"] == "LEASED"
    assert gateway.dispatch_projection()[0]["acknowledged"] is False
    monkeypatch.setattr(store, "audit", original_audit)
    gateway.acknowledge(ack(dispatch), now=101)
    gateway.acknowledge(ack(dispatch), now=101)
    assert store.task("task-a")["state"] == "RUNNING"
    assert gateway.dispatch_projection()[0]["acknowledged"] is True
    events = store.audit_events("task-a")
    assert len([event for event in events if event["event"] == "ACKED"]) == 1


def test_f11d_start_failure_cannot_create_running_unacked_split(
    tmp_path, monkeypatch
):
    store, gateway, router, _ = environment(tmp_path)
    task(store)
    dispatch = router.route_once(now=100)[0]
    original_start = store.start_with_ack
    monkeypatch.setattr(
        store,
        "start_with_ack",
        lambda *args, **kwargs: (_ for _ in ()).throw(BlockedError("injected")),
    )
    with pytest.raises(BlockedError):
        gateway.acknowledge(ack(dispatch), now=101)
    assert store.task("task-a")["state"] == "LEASED"
    assert gateway.dispatch_projection()[0]["acknowledged"] is False
    monkeypatch.setattr(store, "start_with_ack", original_start)
    gateway.acknowledge(ack(dispatch), now=101)
    assert store.task("task-a")["state"] == "RUNNING"
    assert gateway.dispatch_projection()[0]["acknowledged"] is True


def test_f12_gateway_restart_is_unknown_until_reestablished(tmp_path):
    store, _, router, _ = environment(tmp_path)
    task(store)
    dispatch = router.route_once(now=100)[0]
    restarted = LocalWorkerGateway(store, (profile(),))
    assert restarted.session_projection(now=101)[0]["status"] == "UNKNOWN"
    with pytest.raises(BlockedError):
        restarted.acknowledge(ack(dispatch), now=101)


def test_f13_waiting_human_never_routes(tmp_path):
    store, _, router, _ = environment(tmp_path)
    task(store, requires_human_approval=True)
    assert router.route_once(now=100) == []


def test_f14_terminal_task_never_routes(tmp_path):
    store, _, router, _ = environment(tmp_path)
    task(store)
    store.db.execute("UPDATE tasks SET state='COMPLETED' WHERE task_id='task-a'")
    assert router.route_once(now=100) == []


def test_f15_valid_evidence_stops_at_review_pending(tmp_path):
    store, gateway, router, _ = environment(tmp_path)
    task(store)
    dispatch = router.route_once(now=100)[0]
    gateway.acknowledge(ack(dispatch), now=101)
    gateway.result(result(dispatch), now=102)
    assert store.task("task-a")["state"] == "REVIEW_PENDING"


def test_f15b_correct_digest_is_derived_from_resolved_content(tmp_path):
    store, gateway, router, _ = environment(tmp_path)
    task(store)
    dispatch = router.route_once(now=100)[0]
    gateway.acknowledge(ack(dispatch), now=101)
    gateway.result(result(dispatch), now=102)
    assert store.task("task-a")["state"] == "REVIEW_PENDING"


def test_f15c_valid_hex_digest_mismatch_is_blocked(tmp_path):
    store, gateway, router, _ = environment(tmp_path)
    task(store)
    dispatch = router.route_once(now=100)[0]
    gateway.acknowledge(ack(dispatch), now=101)
    with pytest.raises(BlockedError):
        gateway.result(
            result(
                dispatch,
                evidence=(EvidenceReference("evidence-a", "a" * 64),),
            ),
            now=102,
        )
    assert store.task("task-a")["state"] == "RUNNING"


def test_f15d_declared_reference_with_missing_content_is_blocked(tmp_path):
    resolver = ImmutableLocalEvidenceResolver()
    store, gateway, router, _ = environment(tmp_path, evidence_resolver=resolver)
    resolver.declare("missing-content", None)
    task(store)
    dispatch = router.route_once(now=100)[0]
    gateway.acknowledge(ack(dispatch), now=101)
    with pytest.raises(BlockedError):
        gateway.result(
            result(
                dispatch,
                evidence=(EvidenceReference("missing-content", "a" * 64),),
            ),
            now=102,
        )


def test_f15e_unknown_evidence_reference_is_blocked(tmp_path):
    store, gateway, router, _ = environment(tmp_path)
    task(store)
    dispatch = router.route_once(now=100)[0]
    gateway.acknowledge(ack(dispatch), now=101)
    with pytest.raises(BlockedError):
        gateway.result(
            result(
                dispatch,
                evidence=(EvidenceReference("unknown-evidence", "a" * 64),),
            ),
            now=102,
        )


def test_f15f_same_evidence_id_with_altered_bytes_is_blocked(tmp_path):
    resolver = ImmutableLocalEvidenceResolver()
    environment(tmp_path, evidence_resolver=resolver)
    with pytest.raises(BlockedError):
        resolver.declare("evidence-a", b"altered bytes")


def test_f15g_duplicate_result_evidence_replay_is_blocked(tmp_path):
    store, gateway, router, _ = environment(tmp_path)
    task(store)
    dispatch = router.route_once(now=100)[0]
    gateway.acknowledge(ack(dispatch), now=101)
    accepted = result(dispatch)
    gateway.result(accepted, now=102)
    with pytest.raises(BlockedError):
        gateway.result(accepted, now=102)
    assert store.task("task-a")["state"] == "REVIEW_PENDING"


def test_f15h_verified_result_never_completes_automatically(tmp_path):
    store, gateway, router, _ = environment(tmp_path)
    task(store)
    dispatch = router.route_once(now=100)[0]
    gateway.acknowledge(ack(dispatch), now=101)
    gateway.result(result(dispatch), now=102)
    assert store.task("task-a")["state"] == "REVIEW_PENDING"


def test_f16_invalid_or_missing_evidence_never_completes(tmp_path):
    store, gateway, router, _ = environment(tmp_path)
    task(store)
    dispatch = router.route_once(now=100)[0]
    gateway.acknowledge(ack(dispatch), now=101)
    with pytest.raises(BlockedError):
        gateway.result(result(dispatch, evidence=()), now=102)
    assert store.task("task-a")["state"] != "COMPLETED"


@pytest.mark.parametrize("bad_sha", (None, 7, "bad"))
def test_f16b_malformed_evidence_sha_is_explicitly_blocked(tmp_path, bad_sha):
    store, gateway, router, _ = environment(tmp_path)
    task(store)
    dispatch = router.route_once(now=100)[0]
    gateway.acknowledge(ack(dispatch), now=101)
    malformed = result(
        dispatch, evidence=(EvidenceReference("evidence-a", bad_sha),)
    )
    with pytest.raises(BlockedError):
        gateway.result(malformed, now=102)


@pytest.mark.parametrize("bad_capacity", (True, "1", 1.5))
def test_f16c_malformed_capacity_is_explicitly_blocked(tmp_path, bad_capacity):
    _, gateway, _, _ = environment(tmp_path)
    with pytest.raises(BlockedError):
        gateway.heartbeat(
            HeartbeatEnvelope("ext-a", "session-0", 1, 101, bad_capacity),
            now=101,
        )


def test_f17_health_projection_never_fabricates_availability(tmp_path):
    store, _, router, _ = environment(tmp_path, connect=False)
    task(store)
    snapshot = router.health_projection(now=100)
    assert snapshot["external_workers"][0]["status"] == "UNKNOWN"
    assert snapshot["counts"]["RUNNING"] == 0


def test_f17b_health_projection_requires_usable_capacity(tmp_path):
    store, gateway, router, sessions = environment(tmp_path)
    sessions[0].heartbeat(now=101, capacity=0)
    assert router.health_projection(now=101)["external_workers"][0]["status"] == "AT_CAPACITY"
    sessions[0].heartbeat(now=102, capacity=1)
    task(store)
    router.route_once(now=102)
    assert router.health_projection(now=102)["external_workers"][0]["status"] == "AT_CAPACITY"


def test_f17c_verified_is_documented_as_local_harness_truth_only():
    documentation = inspect.getdoc(LocalWorkerGateway) or ""
    assert "local harness truth only" in documentation
    assert "not cryptographic proof" in documentation
    assert "external provider" in documentation


def test_f17d_session_hello_without_local_authority_is_blocked(tmp_path):
    _, gateway, _, _ = environment(tmp_path, connect=False)
    item = profile()
    hello = SessionHello(
        item.worker_id,
        item.worker_kind,
        item.capabilities,
        item.allowed_targets,
        "unauthorized-session",
        0,
        100,
        1,
    )
    with pytest.raises(BlockedError):
        gateway.register(hello, now=100)
    projection = gateway.session_projection(now=100)[0]
    assert projection["status"] == "UNKNOWN"
    assert projection["verification_scope"] == "UNKNOWN"


def test_f17e_self_asserted_verified_states_never_grant_authority(tmp_path):
    _, gateway, _, _ = environment(tmp_path, connect=False)
    item = profile()
    hello = SessionHello(
        item.worker_id,
        item.worker_kind,
        item.capabilities,
        item.allowed_targets,
        "self-asserted-session",
        0,
        100,
        1,
        provider_state="VERIFIED",
        transport_state="VERIFIED",
    )
    with pytest.raises(BlockedError):
        gateway.register(hello, now=100)
    with pytest.raises(BlockedError):
        gateway.register_local_harness(hello, now=100)
    assert gateway.session_projection(now=100)[0]["status"] == "UNKNOWN"


@pytest.mark.parametrize(
    "provider_state,transport_state",
    (("UNKNOWN", "VERIFIED"), ("VERIFIED", "UNKNOWN")),
)
def test_f17f_unknown_provider_or_transport_never_available(
    tmp_path, provider_state, transport_state
):
    _, gateway, _, _ = environment(tmp_path, connect=False)
    item = profile()
    hello = SessionHello(
        item.worker_id,
        item.worker_kind,
        item.capabilities,
        item.allowed_targets,
        "partial-session",
        0,
        100,
        1,
        provider_state=provider_state,
        transport_state=transport_state,
    )
    with pytest.raises(BlockedError):
        gateway.register_local_harness(hello, now=100)
    assert gateway.session_projection(now=100)[0]["status"] == "UNKNOWN"


def test_f17g_only_authorized_local_harness_becomes_available(tmp_path):
    _, gateway, _, _ = environment(tmp_path)
    projection = gateway.session_projection(now=100)[0]
    assert projection["status"] == "AVAILABLE"
    assert projection["verification_scope"] == "LOCAL_HARNESS"
    assert projection["provider_kind"] == "local-disposable"
    assert "Codex" not in repr(projection)
    assert "Antigravity" not in repr(projection)


def test_f17h_real_provider_label_without_local_authority_stays_unknown(tmp_path):
    _, gateway, _, _ = environment(
        tmp_path, profiles=(profile(worker_kind="Codex"),), connect=False
    )
    projection = gateway.session_projection(now=100)[0]
    assert projection["provider_kind"] == "Codex"
    assert projection["status"] == "UNKNOWN"
    assert projection["verification_scope"] == "UNKNOWN"


def test_f18_one_session_failure_does_not_crash_router(tmp_path, monkeypatch):
    store, gateway, router, _ = environment(
        tmp_path, (profile("ext-a"), profile("ext-b"))
    )
    task(store, "task-a")
    task(store, "task-b")
    original = gateway.dispatch

    def isolated(task_data, lease, *, session_id, now):
        if task_data["task_id"] == "task-a":
            raise BlockedError("isolated failure")
        return original(task_data, lease, session_id=session_id, now=now)

    monkeypatch.setattr(gateway, "dispatch", isolated)
    assert len(router.route_once(now=100)) == 1
    assert router.last_error == "BlockedError"


def test_f19_deterministic_route_is_stable_across_restart(tmp_path):
    store, _, router, _ = environment(
        tmp_path, (profile("worker-z"), profile("worker-a"))
    )
    task(store)
    assert router.route_once(now=100)[0].worker_id == "worker-a"
    other = AutonomyStore(tmp_path / "other.sqlite")
    profiles = (profile("worker-a"), profile("worker-z"))
    gateway = LocalWorkerGateway(other, profiles)
    for index, item in enumerate(profiles):
        DisposableExternalSession(gateway, item, session_id=f"restart-{index}").connect(
            now=100
        )
    task(other)
    assert AgentRouter(other, gateway).route_once(now=100)[0].worker_id == "worker-a"


def test_f20_protocol_version_mismatch_fails_closed(tmp_path):
    store, gateway, _, _ = environment(tmp_path, connect=False)
    item = profile()
    bad = SessionHello(
        item.worker_id,
        item.worker_kind,
        item.capabilities,
        item.allowed_targets,
        "session-bad",
        0,
        100,
        1,
        protocol_version="AF02/999",
    )
    with pytest.raises(BlockedError):
        gateway.register(bad, now=100)


@pytest.mark.parametrize("duration", (True, 0, float("nan"), float("inf"), float("-inf")))
def test_f20b_lease_duration_must_be_finite_positive(tmp_path, duration):
    store, gateway, _, _ = environment(tmp_path)
    with pytest.raises(BlockedError):
        AgentRouter(store, gateway, lease_seconds=duration)
    task(store)
    with pytest.raises(BlockedError):
        store.claim("task-a", "ext-a", lease_seconds=duration, now=100)


def test_f20c_router_propagates_unexpected_sqlite_programming_error(
    tmp_path, monkeypatch
):
    store, gateway, router, _ = environment(tmp_path)
    task(store)

    def fail_unexpected(**kwargs):
        raise sqlite3.ProgrammingError("injected route harness failure")

    monkeypatch.setattr(gateway, "eligible_sessions", fail_unexpected)
    with pytest.raises(sqlite3.ProgrammingError):
        router.route_once(now=100)
    assert router.status == "ERROR"
    assert router.last_error == "ProgrammingError"
    assert store.task("task-a")["state"] == "QUEUED"
