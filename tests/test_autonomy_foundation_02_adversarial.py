"""AF-02 A01-A20 campaign with explicit result taxonomy."""
import ast
import hashlib
import inspect
import sqlite3
from concurrent.futures import ThreadPoolExecutor

import pytest

import src.autonomy.gateway as gateway_module
import src.autonomy.protocol as protocol_module
import src.autonomy.router as router_module
from src.autonomy import (
    AckEnvelope,
    AgentRouter,
    AutonomyStore,
    BlockedError,
    DisposableExternalSession,
    EvidenceReference,
    HeartbeatEnvelope,
    ImmutableLocalEvidenceResolver,
    IntegrityBlockedError,
    LocalWorkerGateway,
    REAL_PROJECT_MUTATION_ENABLED,
    ResultEnvelope,
    SessionHello,
    Supervisor,
    WorkerProfile,
)

EVIDENCE_BYTES = b"verified AF-02 adversarial evidence"
EVIDENCE_SHA256 = hashlib.sha256(EVIDENCE_BYTES).hexdigest()

BLOCKED = "BLOCKED"
BYPASS = "BYPASS_DETECTED"
HARNESS = "HARNESS_ERROR"


def classify(action):
    try:
        action()
    except (BlockedError, IntegrityBlockedError):
        return BLOCKED
    except Exception:
        return HARNESS
    return BYPASS


def profile(worker_id="ext-a", **changes):
    values = dict(
        worker_id=worker_id,
        worker_kind="local-disposable",
        capabilities=("READ",),
        allowed_targets=("TEST",),
        max_capacity=1,
        heartbeat_sla=10.0,
    )
    values.update(changes)
    return WorkerProfile(**values)


def setup(tmp_path, *, path="af02.sqlite", profiles=None, connect=True):
    store = AutonomyStore(tmp_path / path, busy_timeout_ms=5)
    items = tuple(profiles or (profile(),))
    resolver = ImmutableLocalEvidenceResolver()
    resolver.declare("evidence-a", EVIDENCE_BYTES)
    gateway = LocalWorkerGateway(store, items, evidence_resolver=resolver)
    if connect:
        for index, item in enumerate(items):
            DisposableExternalSession(
                gateway, item, session_id=f"session-{index}"
            ).connect(now=100)
    return store, gateway, AgentRouter(store, gateway)


def task(store, task_id="task-a", **changes):
    values = dict(
        task_id=task_id,
        directive_id="directive-" + task_id,
        target_project="TEST",
        capability="READ",
        governance_allowed=True,
        retry_budget=1,
        now=100,
    )
    values.update(changes)
    return store.create_task(**values)


def ack(dispatch, **changes):
    values = dict(
        dispatch_id=dispatch.dispatch_id,
        task_id=dispatch.task_id,
        worker_id=dispatch.worker_id,
        session_id=dispatch.session_id,
        lease_id=dispatch.lease_id,
        observed_at=101,
    )
    values.update(changes)
    return AckEnvelope(**values)


def result(dispatch, **changes):
    values = dict(
        dispatch_id=dispatch.dispatch_id,
        task_id=dispatch.task_id,
        worker_id=dispatch.worker_id,
        session_id=dispatch.session_id,
        lease_id=dispatch.lease_id,
        observed_at=102,
        status="SUCCEEDED",
        evidence=(EvidenceReference("evidence-a", EVIDENCE_SHA256),),
    )
    values.update(changes)
    return ResultEnvelope(**values)


def assert_blocked(outcome):
    assert outcome == BLOCKED


def test_a01_double_router_race(tmp_path):
    first, _, _ = setup(tmp_path)
    task(first)

    def route(index):
        store, gateway, router = setup(tmp_path, connect=False)
        DisposableExternalSession(
            gateway, profile(), session_id=f"race-{index}"
        ).connect(now=100)
        return len(router.route_once(now=100))

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(route, range(2)))
    assert_blocked(BLOCKED if sum(results) == 1 else BYPASS)


def test_a02_duplicate_dispatch_replay(tmp_path):
    store, gateway, router = setup(tmp_path)
    original = task(store)
    dispatch = router.route_once(now=100)[0]
    lease = dict(task_id=dispatch.task_id, worker_id=dispatch.worker_id, lease_id=dispatch.lease_id)
    replay = gateway.dispatch(
        original, lease, session_id=dispatch.session_id, now=100
    )
    count = len([e for e in store.audit_events("task-a") if e["event"] == "DISPATCHED"])
    assert_blocked(BLOCKED if replay == dispatch and count == 1 else BYPASS)


def test_a03_forged_worker_id(tmp_path):
    store, gateway, router = setup(tmp_path); task(store); dispatch = router.route_once(now=100)[0]
    assert_blocked(classify(lambda: gateway.acknowledge(ack(dispatch, worker_id="evil"), now=101)))


def test_a04_forged_session_id(tmp_path):
    store, gateway, router = setup(tmp_path); task(store); dispatch = router.route_once(now=100)[0]
    assert_blocked(classify(lambda: gateway.acknowledge(ack(dispatch, session_id="evil"), now=101)))


def test_a05_forged_lease_id(tmp_path):
    store, gateway, router = setup(tmp_path); task(store); dispatch = router.route_once(now=100)[0]
    assert_blocked(classify(lambda: gateway.acknowledge(ack(dispatch, lease_id="evil"), now=101)))


def test_a06_ack_after_lease_expiry(tmp_path):
    store, gateway, router = setup(tmp_path); router.lease_seconds = 1; task(store); dispatch = router.route_once(now=100)[0]
    assert_blocked(classify(lambda: gateway.acknowledge(ack(dispatch, observed_at=102), now=102)))


def test_a07_result_after_lease_loss(tmp_path):
    store, gateway, router = setup(tmp_path); task(store); dispatch = router.route_once(now=100)[0]; gateway.acknowledge(ack(dispatch), now=101)
    store.fail_attempt(dispatch.task_id, dispatch.worker_id, dispatch.lease_id, reason="lost", now=102)
    assert_blocked(classify(lambda: gateway.result(result(dispatch), now=102)))


def test_a08_stale_worker_heartbeat(tmp_path):
    _, gateway, _ = setup(tmp_path)
    message = HeartbeatEnvelope("ext-a", "session-0", 1, 100, 1)
    assert_blocked(classify(lambda: gateway.heartbeat(message, now=111)))


def test_a09_future_heartbeat(tmp_path):
    _, gateway, _ = setup(tmp_path)
    message = HeartbeatEnvelope("ext-a", "session-0", 1, 999, 1)
    assert_blocked(classify(lambda: gateway.heartbeat(message, now=100)))


def test_a10_capacity_overclaim(tmp_path):
    _, gateway, _ = setup(tmp_path)
    message = HeartbeatEnvelope("ext-a", "session-0", 1, 101, 2)
    assert_blocked(classify(lambda: gateway.heartbeat(message, now=101)))


def test_a11_forged_capability_or_target(tmp_path):
    store, gateway, _ = setup(tmp_path, connect=False)
    hello = SessionHello("ext-a", "local-disposable", ("WRITE",), ("MAIN",), "evil-session", 0, 100, 1)
    assert_blocked(classify(lambda: gateway.register(hello, now=100)))


def test_a12_waiting_human_injection(tmp_path):
    store, _, router = setup(tmp_path); task(store, requires_human_approval=True)
    assert_blocked(BLOCKED if router.route_once(now=100) == [] else BYPASS)


def test_a13_terminal_task_dispatch_attempt(tmp_path):
    store, _, router = setup(tmp_path); task(store); store.db.execute("UPDATE tasks SET state='COMPLETED'")
    assert_blocked(BLOCKED if router.route_once(now=100) == [] else BYPASS)


def test_a14_gateway_restart_reconnect_replay(tmp_path):
    store, _, router = setup(tmp_path); task(store); dispatch = router.route_once(now=100)[0]
    restarted = LocalWorkerGateway(store, (profile(),))
    DisposableExternalSession(restarted, profile(), session_id="restart").connect(now=101)
    assert_blocked(classify(lambda: restarted.acknowledge(ack(dispatch), now=101)))


def test_a15_protocol_downgrade(tmp_path):
    _, gateway, _ = setup(tmp_path, connect=False); item = profile()
    hello = SessionHello(item.worker_id, item.worker_kind, item.capabilities, item.allowed_targets, "old", 0, 100, 1, protocol_version="AF01")
    assert_blocked(classify(lambda: gateway.register(hello, now=100)))


def test_a16_hostile_evidence_metadata_and_secret_shape(tmp_path):
    store, gateway, router = setup(tmp_path); task(store); dispatch = router.route_once(now=100)[0]; gateway.acknowledge(ack(dispatch), now=101)
    hostile = result(dispatch, evidence=(EvidenceReference("secret=abc<script>", "a" * 64),))
    outcome = classify(lambda: gateway.result(hostile, now=102))
    leaked = "abc" in repr(router.health_projection(now=102))
    assert_blocked(BLOCKED if outcome == BLOCKED and not leaked else HARNESS if outcome == HARNESS else BYPASS)


def test_a17_database_busy_isolated(tmp_path):
    store, _, router = setup(tmp_path); task(store)
    lock = sqlite3.connect(tmp_path / "af02.sqlite", isolation_level=None); lock.execute("BEGIN IMMEDIATE")
    try:
        routed = router.route_once(now=100)
        outcome = BLOCKED if routed == [] and router.last_error else BYPASS
    except Exception:
        outcome = HARNESS
    finally:
        lock.execute("ROLLBACK"); lock.close()
    assert_blocked(outcome)


def test_a18_corrupt_store_or_unknown_state(tmp_path):
    path = tmp_path / "corrupt.sqlite"; path.write_bytes(b"corrupt")
    assert_blocked(classify(lambda: AutonomyStore(path)))


def test_a19_health_projection_fake_running_attempt(tmp_path):
    store, _, router = setup(tmp_path, connect=False); task(store)
    snapshot = router.health_projection(now=100)
    outcome = BLOCKED if snapshot["counts"]["RUNNING"] == 0 and snapshot["external_workers"][0]["status"] == "UNKNOWN" else BYPASS
    assert_blocked(outcome)


def test_a20_default_path_has_no_mutation_surface(tmp_path):
    modules = (protocol_module, gateway_module, router_module)
    forbidden_imports = {"subprocess", "socket", "requests", "urllib", "httpx"}
    forbidden_calls = {"Popen", "system", "exec", "spawn", "kill", "terminate"}
    outcome = BLOCKED
    try:
        for module in modules:
            tree = ast.parse(inspect.getsource(module))
            for node in ast.walk(tree):
                if isinstance(node, (ast.Import, ast.ImportFrom)):
                    names = [item.name.split(".")[0] for item in node.names] if isinstance(node, ast.Import) else [(node.module or "").split(".")[0]]
                    if forbidden_imports.intersection(names): outcome = BYPASS
                if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr in forbidden_calls: outcome = BYPASS
        gateway = LocalWorkerGateway(AutonomyStore(tmp_path / "proof.sqlite"), (profile(),))
        exposed = {"write_repository", "call_provider", "place_order", "restart_process", "execute_shell"}
        if exposed.intersection(dir(gateway)) or REAL_PROJECT_MUTATION_ENABLED is not False: outcome = BYPASS
    except Exception:
        outcome = HARNESS
    assert_blocked(outcome)


def test_r01_sqlite_programming_error_is_harness_error():
    def misuse():
        raise sqlite3.ProgrammingError("injected harness misuse")

    assert classify(misuse) == HARNESS
