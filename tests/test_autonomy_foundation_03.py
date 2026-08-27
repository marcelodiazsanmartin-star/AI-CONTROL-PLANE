"""AF-03 functional acceptance tests on disposable workspaces only."""
import hashlib
import json

import pytest

from src.autonomy import (
    AckEnvelope, AgentRouter, AutonomyStore, BlockedError, IntegrityBlockedError,
    DisposableExternalSession, DisposableWorkspaceRegistry, ExecutionPlan,
    FileOperation, GovernedExecutionController, LocalWorkerGateway, WorkerProfile,
)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def environment(tmp_path, *, running=True, workspace=True):
    real = tmp_path / "canonical-repository"; real.mkdir()
    root = tmp_path / "disposable-workspace"; root.mkdir()
    store = AutonomyStore(tmp_path / "truth.sqlite", busy_timeout_ms=2000)
    profile = WorkerProfile("worker-a", "local-disposable", ("MUTATE_FILES",), ("PROJECT",), 1, 30.0)
    gateway = LocalWorkerGateway(store, (profile,))
    session = DisposableExternalSession(gateway, profile, session_id="session-a"); session.connect(now=100)
    store.create_task(task_id="task-a", directive_id="directive-a", target_project="PROJECT",
                      capability="MUTATE_FILES", governance_allowed=True, retry_budget=1, now=100)
    dispatch = AgentRouter(store, gateway).route_once(now=100)[0]
    if running:
        gateway.acknowledge(AckEnvelope(dispatch.dispatch_id, dispatch.task_id, dispatch.worker_id,
                                       dispatch.session_id, dispatch.lease_id, 101), now=101)
    registry = DisposableWorkspaceRegistry(real_repository_root=real)
    if workspace:
        registry.register_local_disposable(workspace_id="workspace-a", root=root, target_project="PROJECT")
    controller = GovernedExecutionController(store, gateway, registry, clock=lambda: 103)
    return store, gateway, registry, controller, root, real, dispatch


def grant(controller, dispatch, **changes):
    values = dict(task_id="task-a", worker_id="worker-a", session_id="session-a",
                  lease_id=dispatch.lease_id, workspace_id="workspace-a",
                  allowed_operations=("CREATE", "REPLACE", "DELETE"), now=102)
    values.update(changes)
    return controller.issue_grant(**values)


def create_plan(grant_id, path="artifact.txt", content=b"created"):
    return ExecutionPlan(grant_id, (FileOperation("CREATE", path, "ABSENT", digest(content), content),))


def force_applying(controller, plan, now=103):
    plan_hash, rows, _ = controller.canonical_plan(plan)
    manifest = [{k: row[k] for k in ("operation", "path", "preimage", "postimage", "content_sha256")} for row in rows]
    controller.store.db.execute("UPDATE execution_grants SET state='APPLYING',consumed_at=?,plan_hash=? WHERE grant_id=?", (now, plan_hash, plan.grant_id))
    controller.store.db.execute("INSERT INTO execution_transactions(grant_id,plan_hash,operations_manifest,state,started_at,finished_at,evidence_sha256,error_code,evidence_envelope) VALUES(?,?,?,?,?,?,?,?,?)",
        (plan.grant_id, plan_hash, json.dumps(manifest, sort_keys=True, separators=(",", ":")), "APPLYING", now, None, None, None, None))


def test_f01_running_truth_issues_one_execution_grant(tmp_path):
    _, _, _, controller, _, _, dispatch = environment(tmp_path)
    issued = grant(controller, dispatch)
    assert issued["state"] == "ISSUED"
    assert issued["task_id"] == "task-a" and issued["lease_id"] == dispatch.lease_id


def test_f02_non_running_waiting_human_and_terminal_cannot_receive_grant(tmp_path):
    store, _, _, controller, _, _, dispatch = environment(tmp_path, running=False)
    for state in ("LEASED", "WAITING_HUMAN", "COMPLETED"):
        store.db.execute("UPDATE tasks SET state=? WHERE task_id='task-a'", (state,))
        with pytest.raises(BlockedError): grant(controller, dispatch)


def test_f03_expired_lease_cannot_issue_or_consume_grant(tmp_path):
    store, _, _, controller, root, _, dispatch = environment(tmp_path)
    issued = grant(controller, dispatch)
    store.db.execute("UPDATE tasks SET lease_expires_at=102 WHERE task_id='task-a'")
    with pytest.raises(BlockedError): controller.apply(create_plan(issued["grant_id"]), now=103)
    assert not (root / "artifact.txt").exists()


def test_f04_worker_session_lease_mismatch_rejected(tmp_path):
    _, _, _, controller, _, _, dispatch = environment(tmp_path)
    for field, value in (("worker_id", "forged"), ("session_id", "forged"), ("lease_id", "forged")):
        with pytest.raises(BlockedError): grant(controller, dispatch, **{field: value})


def test_f05_capability_and_target_mismatch_rejected(tmp_path):
    store, _, _, controller, _, _, dispatch = environment(tmp_path)
    store.db.execute("UPDATE tasks SET capability='OTHER' WHERE task_id='task-a'")
    with pytest.raises(BlockedError): grant(controller, dispatch)
    store.db.execute("UPDATE tasks SET capability='MUTATE_FILES',target_project='OTHER' WHERE task_id='task-a'")
    with pytest.raises(BlockedError): grant(controller, dispatch)


def test_f06_disposable_registration_succeeds_real_root_rejected(tmp_path):
    _, _, registry, _, root, real, _ = environment(tmp_path)
    assert registry.resolve("workspace-a", "PROJECT").root == root.resolve()
    with pytest.raises(BlockedError): registry.register_local_disposable(workspace_id="real", root=real, target_project="PROJECT")


def test_f07_create_succeeds_with_exact_postimage(tmp_path):
    _, _, _, controller, root, _, dispatch = environment(tmp_path); issued = grant(controller, dispatch)
    result = controller.apply(create_plan(issued["grant_id"]), now=103)
    assert result["state"] == "APPLIED" and digest((root / "artifact.txt").read_bytes()) == digest(b"created")


def test_f08_replace_requires_exact_preimage(tmp_path):
    _, _, _, controller, root, _, dispatch = environment(tmp_path); path = root / "artifact.txt"; path.write_bytes(b"old")
    issued = grant(controller, dispatch); plan = ExecutionPlan(issued["grant_id"], (FileOperation("REPLACE", "artifact.txt", digest(b"old"), digest(b"new"), b"new"),))
    controller.apply(plan, now=103); assert path.read_bytes() == b"new"


def test_f09_delete_requires_exact_preimage(tmp_path):
    _, _, _, controller, root, _, dispatch = environment(tmp_path); path = root / "artifact.txt"; path.write_bytes(b"old")
    issued = grant(controller, dispatch); plan = ExecutionPlan(issued["grant_id"], (FileOperation("DELETE", "artifact.txt", digest(b"old"), "ABSENT"),))
    controller.apply(plan, now=103); assert not path.exists()


def test_f10_multifile_plan_applies_in_deterministic_path_order(tmp_path):
    _, _, _, controller, root, _, dispatch = environment(tmp_path); issued = grant(controller, dispatch); order = []
    plan = ExecutionPlan(issued["grant_id"], tuple(FileOperation("CREATE", p, "ABSENT", digest(v), v) for p, v in (("z.txt", b"z"), ("a.txt", b"a"))))
    controller.apply(plan, now=103, after_operation=lambda _, path: order.append(path.name))
    assert order == ["a.txt", "z.txt"] and (root / "z.txt").read_bytes() == b"z"


def test_f11_any_preimage_mismatch_means_zero_mutation(tmp_path):
    _, _, _, controller, root, _, dispatch = environment(tmp_path); (root / "b.txt").write_bytes(b"wrong"); issued = grant(controller, dispatch)
    plan = ExecutionPlan(issued["grant_id"], (FileOperation("CREATE", "a.txt", "ABSENT", digest(b"a"), b"a"), FileOperation("REPLACE", "b.txt", digest(b"expected"), digest(b"b"), b"b")))
    with pytest.raises(BlockedError): controller.apply(plan, now=103)
    assert not (root / "a.txt").exists() and (root / "b.txt").read_bytes() == b"wrong"


def test_f12_duplicate_grant_plan_replay_cannot_duplicate_mutation(tmp_path):
    _, _, _, controller, root, _, dispatch = environment(tmp_path); issued = grant(controller, dispatch); plan = create_plan(issued["grant_id"])
    controller.apply(plan, now=103)
    with pytest.raises(BlockedError): controller.apply(plan, now=104)
    assert (root / "artifact.txt").read_bytes() == b"created"


def test_f13_second_operation_failure_rolls_back_first_exactly(tmp_path):
    _, _, _, controller, root, _, dispatch = environment(tmp_path); issued = grant(controller, dispatch)
    plan = ExecutionPlan(issued["grant_id"], tuple(FileOperation("CREATE", p, "ABSENT", digest(v), v) for p, v in (("a.txt", b"a"), ("b.txt", b"b"))))
    def fail(index, _):
        if index == 1: raise OSError("injected")
    with pytest.raises(OSError): controller.apply(plan, now=103, after_operation=fail)
    assert not (root / "a.txt").exists() and not (root / "b.txt").exists()
    assert controller.transaction(issued["grant_id"])["state"] == "FAILED"


def test_f14_rollback_failure_blocks_workspace(tmp_path):
    _, _, registry, controller, root, _, dispatch = environment(tmp_path); issued = grant(controller, dispatch); plan = create_plan(issued["grant_id"])
    def fail_and_remove(_, __): raise OSError("apply failure")
    def sabotage():
        (root / "artifact.txt").unlink(missing_ok=True)
        (root / "artifact.txt").mkdir()
    with pytest.raises(OSError): controller.apply(plan, now=103, after_operation=fail_and_remove, before_rollback=sabotage)
    assert controller.transaction(issued["grant_id"])["state"] == "INTEGRITY_BLOCKED"
    assert registry.state("workspace-a") == "INTEGRITY_BLOCKED"


def test_f15_restart_reconciliation_complete_preimage_is_failed_safe(tmp_path):
    store, gateway, registry, controller, _, real, dispatch = environment(tmp_path); issued = grant(controller, dispatch); plan = create_plan(issued["grant_id"]); force_applying(controller, plan); store.close()
    reopened = AutonomyStore(tmp_path / "truth.sqlite"); recovered = GovernedExecutionController(reopened, gateway, registry, clock=lambda: 104)
    assert recovered.recover(issued["grant_id"], now=104) == "FAILED"


def test_f16_restart_complete_postimage_requires_verified_hashes(tmp_path):
    _, _, _, controller, root, _, dispatch = environment(tmp_path); issued = grant(controller, dispatch); plan = create_plan(issued["grant_id"]); force_applying(controller, plan); (root / "artifact.txt").write_bytes(b"created")
    assert controller.recover(issued["grant_id"], now=104) == "APPLIED"
    assert controller.transaction(issued["grant_id"])["evidence_sha256"] is not None


def test_f17_mixed_crash_state_integrity_blocks(tmp_path):
    _, _, registry, controller, root, _, dispatch = environment(tmp_path); issued = grant(controller, dispatch)
    plan = ExecutionPlan(issued["grant_id"], tuple(FileOperation("CREATE", p, "ABSENT", digest(v), v) for p, v in (("a.txt", b"a"), ("b.txt", b"b"))))
    force_applying(controller, plan); (root / "a.txt").write_bytes(b"a")
    assert controller.recover(issued["grant_id"], now=104) == "INTEGRITY_BLOCKED" and registry.state("workspace-a") == "INTEGRITY_BLOCKED"


def test_f18_success_evidence_binds_actual_bytes_and_review_pending_only(tmp_path):
    store, _, _, controller, root, _, dispatch = environment(tmp_path); issued = grant(controller, dispatch); result = controller.apply(create_plan(issued["grant_id"]), now=103)
    envelope = json.loads(result["evidence_envelope"])
    expected = digest(json.dumps(envelope, sort_keys=True, separators=(",", ":")).encode())
    assert result["evidence_sha256"] == expected
    assert envelope["paths"][0]["after_sha256"] == digest((root / "artifact.txt").read_bytes())
    assert store.task("task-a")["state"] == "REVIEW_PENDING"


def test_f19_projection_never_fabricates_available_or_applied(tmp_path):
    _, _, _, controller, _, _, dispatch = environment(tmp_path, workspace=False)
    projection = controller.projection(now=102)
    assert projection["last_execution"] == "UNKNOWN" and projection["counts"]["APPLIED"] == 0
    with pytest.raises(IntegrityBlockedError): grant(controller, dispatch)


def test_f20_workspace_and_plan_identity_stable_across_restart(tmp_path):
    _, _, registry, controller, _, _, dispatch = environment(tmp_path); issued = grant(controller, dispatch); plan = create_plan(issued["grant_id"])
    first = controller.canonical_plan(plan)[0]
    restarted = GovernedExecutionController(controller.store, controller.gateway, registry, clock=lambda: 103)
    second = restarted.canonical_plan(plan)[0]
    assert first == second and restarted.grant(issued["grant_id"])["grant_id"] == issued["grant_id"]
    assert registry.resolve("workspace-a", "PROJECT").workspace_id == "workspace-a"


def test_r1_final_postimage_reverified_before_evidence_and_review(tmp_path):
    store, _, _, controller, root, _, dispatch = environment(tmp_path); issued = grant(controller, dispatch)
    def tamper(_, path): path.write_bytes(b"tampered-after-operation")
    with pytest.raises(IntegrityBlockedError):
        controller.apply(create_plan(issued["grant_id"]), now=103, after_operation=tamper)
    assert not (root / "artifact.txt").exists()
    assert store.task("task-a")["state"] == "RUNNING"
    assert controller.transaction(issued["grant_id"])["evidence_sha256"] is None


def test_r1_configured_sensitive_prefix_is_enforced(tmp_path):
    store, gateway, _, _, root, real, dispatch = environment(tmp_path); (root / "private").mkdir()
    registry = DisposableWorkspaceRegistry(real_repository_root=real, protected_paths=("private",))
    registry.register_local_disposable(workspace_id="workspace-a", root=root, target_project="PROJECT")
    controller = GovernedExecutionController(store, gateway, registry, clock=lambda: 103)
    issued = grant(controller, dispatch)
    with pytest.raises(BlockedError): controller.apply(create_plan(issued["grant_id"], "private/value.txt"), now=103)
    assert not (root / "private" / "value.txt").exists()


def test_r1_projection_uses_durable_workspace_truth_not_memory_flags(tmp_path):
    _, _, registry, controller, _, _, _ = environment(tmp_path)
    controller.status = "FAKE_APPLIED"; controller.last_error = "FAKE_GREEN"
    assert controller.projection(now=103)["status"] == "AVAILABLE"
    controller.store.db.execute("UPDATE execution_workspaces SET state='INTEGRITY_BLOCKED',last_error='DURABLE_BLOCK' WHERE workspace_id='workspace-a'")
    registry._blocked.clear()
    projection = controller.projection(now=103)
    assert projection["status"] == "INTEGRITY_BLOCKED" and projection["last_error"] == "DURABLE_BLOCK"
