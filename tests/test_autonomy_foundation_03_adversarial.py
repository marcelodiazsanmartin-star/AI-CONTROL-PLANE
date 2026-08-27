"""AF-03 A01-A20 adversarial campaign; every case must classify BLOCKED."""
import inspect
import os
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from threading import Barrier

import pytest

import src.autonomy.execution as execution_module
from src.autonomy import (AutonomyStore, BlockedError, ExecutionPlan, FileOperation,
                          GovernedExecutionController, SessionHello)
from tests.test_autonomy_foundation_03 import create_plan, digest, environment, force_applying, grant


def blocked(call):
    try:
        call()
    except BlockedError:
        return "BLOCKED"
    except Exception:
        return "HARNESS_ERROR"
    return "BYPASS_DETECTED"


def test_a01_forged_or_replayed_grant_id_is_blocked(tmp_path):
    _, _, _, controller, _, _, dispatch = environment(tmp_path); grant(controller, dispatch)
    assert blocked(lambda: controller.apply(create_plan("a" * 64), now=103)) == "BLOCKED"


def test_a02_wrong_worker_session_lease_on_valid_grant_is_blocked(tmp_path):
    _, _, _, controller, _, _, dispatch = environment(tmp_path)
    assert all(blocked(lambda f=f, v=v: grant(controller, dispatch, **{f: v})) == "BLOCKED" for f, v in (("worker_id", "evil"), ("session_id", "evil"), ("lease_id", "evil")))


def test_a03_grant_use_after_lease_or_grant_expiry_is_blocked(tmp_path):
    store, _, _, controller, _, _, dispatch = environment(tmp_path); issued = grant(controller, dispatch)
    store.db.execute("UPDATE execution_grants SET expires_at=102 WHERE grant_id=?", (issued["grant_id"],))
    assert blocked(lambda: controller.apply(create_plan(issued["grant_id"]), now=103)) == "BLOCKED"


def test_a04_capability_escalation_operation_not_granted_is_blocked(tmp_path):
    _, _, _, controller, _, _, dispatch = environment(tmp_path); issued = grant(controller, dispatch, allowed_operations=("DELETE",))
    assert blocked(lambda: controller.apply(create_plan(issued["grant_id"]), now=103)) == "BLOCKED"


def test_a05_target_project_substitution_is_blocked(tmp_path):
    store, _, _, controller, _, _, dispatch = environment(tmp_path); issued = grant(controller, dispatch)
    store.db.execute("UPDATE execution_grants SET target_project='EVIL' WHERE grant_id=?", (issued["grant_id"],))
    assert blocked(lambda: controller.apply(create_plan(issued["grant_id"]), now=103)) == "BLOCKED"


def test_a06_absolute_parent_drive_unc_escapes_are_blocked(tmp_path):
    _, _, _, controller, _, _, dispatch = environment(tmp_path); issued = grant(controller, dispatch)
    bad = ("/abs.txt", "../escape.txt", "C:/escape.txt", "//server/share/x")
    assert all(blocked(lambda p=p: controller.canonical_plan(create_plan(issued["grant_id"], p))) == "BLOCKED" for p in bad)


def test_a07_symlink_junction_reparse_traversal_is_blocked(tmp_path, monkeypatch):
    _, _, _, controller, root, _, dispatch = environment(tmp_path); (root / "link").mkdir(); issued = grant(controller, dispatch)
    original = Path.is_symlink
    monkeypatch.setattr(Path, "is_symlink", lambda self: self.name == "link" or original(self))
    assert blocked(lambda: controller.apply(create_plan(issued["grant_id"], "link/x.txt"), now=103)) == "BLOCKED"
    assert not (root / "link" / "x.txt").exists()


def test_a08_protected_tree_mutation_attempts_are_blocked(tmp_path):
    _, _, _, controller, _, _, dispatch = environment(tmp_path); issued = grant(controller, dispatch)
    paths = ("state/x", "reports/x", "directives/audit/x", ".git/config")
    assert all(blocked(lambda p=p: controller.apply(create_plan(issued["grant_id"], p), now=103)) == "BLOCKED" for p in paths)


def test_a09_authority_loss_between_validation_and_apply_means_zero_mutation(tmp_path):
    store, _, _, controller, root, _, dispatch = environment(tmp_path); issued = grant(controller, dispatch)
    def steal_lease(): store.db.execute("UPDATE tasks SET lease_id='forged' WHERE task_id='task-a'")
    assert blocked(lambda: controller.apply(create_plan(issued["grant_id"]), now=103, before_first_write=steal_lease)) == "BLOCKED"
    assert not (root / "artifact.txt").exists()


def test_a10_concurrent_duplicate_consume_mutates_once(tmp_path):
    _, gateway, registry, controller, root, _, dispatch = environment(tmp_path); issued = grant(controller, dispatch); plan = create_plan(issued["grant_id"]); barrier = Barrier(2)
    second_store = AutonomyStore(tmp_path / "truth.sqlite", busy_timeout_ms=2000)
    second = GovernedExecutionController(second_store, gateway, registry, clock=lambda: 103)
    def consume(instance):
        barrier.wait(timeout=5)
        return blocked(lambda: instance.apply(plan, now=103))
    with ThreadPoolExecutor(max_workers=2) as pool: outcomes = list(pool.map(consume, (controller, second)))
    assert sorted(outcomes) == ["BLOCKED", "BYPASS_DETECTED"] and (root / "artifact.txt").read_bytes() == b"created"


def test_a11_two_grants_race_same_file_only_one_applies(tmp_path):
    _, gateway, registry, controller, root, _, dispatch = environment(tmp_path); first = grant(controller, dispatch); second_grant = grant(controller, dispatch); barrier = Barrier(2)
    second_store = AutonomyStore(tmp_path / "truth.sqlite", busy_timeout_ms=2000)
    second = GovernedExecutionController(second_store, gateway, registry, clock=lambda: 103)
    def consume(pair):
        instance, issued = pair
        barrier.wait(timeout=5); return blocked(lambda: instance.apply(create_plan(issued["grant_id"]), now=103))
    with ThreadPoolExecutor(max_workers=2) as pool: outcomes = list(pool.map(consume, ((controller, first), (second, second_grant))))
    assert sorted(outcomes) == ["BLOCKED", "BYPASS_DETECTED"] and (root / "artifact.txt").read_bytes() == b"created"


def test_a12_casefold_and_unicode_normalization_collisions_are_blocked(tmp_path):
    _, _, _, controller, _, _, dispatch = environment(tmp_path); issued = grant(controller, dispatch)
    case = ExecutionPlan(issued["grant_id"], (FileOperation("CREATE", "A.txt", "ABSENT", digest(b"a"), b"a"), FileOperation("CREATE", "a.txt", "ABSENT", digest(b"b"), b"b")))
    assert blocked(lambda: controller.canonical_plan(case)) == "BLOCKED"
    assert blocked(lambda: controller.canonical_plan(create_plan(issued["grant_id"], "e\u0301.txt"))) == "BLOCKED"


def test_a13_create_replace_delete_precondition_attacks_are_blocked(tmp_path):
    _, _, _, controller, root, _, dispatch = environment(tmp_path); (root / "exists").write_bytes(b"x")
    plans = []
    for operation, path, pre, post, content in (("CREATE", "exists", "ABSENT", digest(b"n"), b"n"), ("REPLACE", "missing", digest(b"x"), digest(b"n"), b"n"), ("DELETE", "missing", digest(b"x"), "ABSENT", None)):
        issued = grant(controller, dispatch); plans.append(ExecutionPlan(issued["grant_id"], (FileOperation(operation, path, pre, post, content),)))
    assert all(blocked(lambda p=p: controller.apply(p, now=103)) == "BLOCKED" for p in plans)


def test_a14_partial_apply_exception_rolls_back_and_is_blocked(tmp_path):
    _, _, _, controller, root, _, dispatch = environment(tmp_path); issued = grant(controller, dispatch)
    plan = ExecutionPlan(issued["grant_id"], tuple(FileOperation("CREATE", p, "ABSENT", digest(v), v) for p, v in (("a", b"a"), ("b", b"b"))))
    assert blocked(lambda: controller.apply(plan, now=103, after_operation=lambda i, _: (_ for _ in ()).throw(BlockedError("fault")) if i else None)) == "BLOCKED"
    assert not (root / "a").exists() and not (root / "b").exists()


def test_a15_rollback_sabotage_integrity_blocks(tmp_path):
    _, _, registry, controller, root, _, dispatch = environment(tmp_path); issued = grant(controller, dispatch); plan = create_plan(issued["grant_id"])
    def sabotage(): (root / "artifact.txt").unlink(missing_ok=True); (root / "artifact.txt").mkdir()
    assert blocked(lambda: controller.apply(plan, now=103, after_operation=lambda *_: (_ for _ in ()).throw(BlockedError("fault")), before_rollback=sabotage)) == "BLOCKED"
    assert registry.state("workspace-a") == "INTEGRITY_BLOCKED"
    restarted_registry = type(registry)(real_repository_root=tmp_path / "canonical-repository")
    restarted_registry.register_local_disposable(workspace_id="workspace-a", root=root, target_project="PROJECT")
    restarted = GovernedExecutionController(AutonomyStore(tmp_path / "truth.sqlite"), controller.gateway, restarted_registry, clock=lambda: 104)
    assert restarted.projection(now=104)["status"] == "INTEGRITY_BLOCKED"


def test_a16_oversized_content_and_secret_metadata_do_not_leak(tmp_path):
    _, _, _, controller, _, _, dispatch = environment(tmp_path); issued = grant(controller, dispatch)
    assert blocked(lambda: controller.canonical_plan(create_plan(issued["grant_id"], "secret=TOPSECRET.txt"))) == "BLOCKED"
    huge = b"x" * 1_048_577
    assert blocked(lambda: controller.canonical_plan(ExecutionPlan(issued["grant_id"], (FileOperation("CREATE", "x", "ABSENT", digest(huge), huge),)))) == "BLOCKED"
    assert "TOPSECRET" not in str(controller.projection(now=103))


def test_a17_audit_failure_before_first_write_is_zero_mutation(tmp_path, monkeypatch):
    _, _, _, controller, root, _, dispatch = environment(tmp_path); issued = grant(controller, dispatch)
    monkeypatch.setattr(controller.store, "audit", lambda *a, **k: (_ for _ in ()).throw(BlockedError("audit unavailable")))
    assert blocked(lambda: controller.apply(create_plan(issued["grant_id"]), now=103)) == "BLOCKED"
    assert not (root / "artifact.txt").exists() and controller.grant(issued["grant_id"])["state"] == "ISSUED"


def test_a18_corrupt_unknown_transaction_state_restart_fails_closed(tmp_path):
    _, _, _, controller, _, _, dispatch = environment(tmp_path); issued = grant(controller, dispatch); plan = create_plan(issued["grant_id"]); force_applying(controller, plan)
    controller.store.db.execute("UPDATE execution_transactions SET state='FUTURE' WHERE grant_id=?", (issued["grant_id"],))
    assert blocked(lambda: controller.recover(issued["grant_id"], now=104)) == "BLOCKED"
    assert controller.projection(now=104)["status"] == "UNKNOWN"


def test_a19_worker_message_cannot_register_real_workspace_or_enable_mutation(tmp_path):
    _, gateway, registry, _, _, real, _ = environment(tmp_path)
    hello = SessionHello("worker-a", "local-disposable", ("MUTATE_FILES",), ("PROJECT",), "evil", 9, 102, 1, "VERIFIED", "VERIFIED")
    assert blocked(lambda: gateway.register(hello, now=102)) == "BLOCKED"
    assert blocked(lambda: registry.register_local_disposable(workspace_id="evil", root=real, target_project="PROJECT")) == "BLOCKED"
    assert execution_module.REAL_PROJECT_MUTATION_ENABLED is False


def test_a20_no_forbidden_mutation_surface_static_and_dynamic(tmp_path):
    _, _, _, controller, _, _, _ = environment(tmp_path)
    source = inspect.getsource(execution_module).lower()
    forbidden_imports = ("import subprocess", "import socket", "import requests", "from git", "git push", "git commit", "place_order", "credential")
    forbidden_methods = {"run_shell", "subprocess", "git_write", "push", "commit", "process_control", "provider_api", "place_order", "mutate_real_project"}
    assert all(token not in source for token in forbidden_imports)
    assert forbidden_methods.isdisjoint(set(dir(controller))) and execution_module.REAL_PROJECT_MUTATION_ENABLED is False


def test_r1_hardlinked_target_is_blocked_without_mutation(tmp_path):
    _, _, _, controller, root, _, dispatch = environment(tmp_path)
    outside = tmp_path / "outside.txt"; outside.write_bytes(b"outside")
    os.link(outside, root / "artifact.txt")
    issued = grant(controller, dispatch)
    assert blocked(lambda: controller.apply(create_plan(issued["grant_id"]), now=103)) == "BLOCKED"
    assert outside.read_bytes() == b"outside" and (root / "artifact.txt").read_bytes() == b"outside"


def test_r1_workspace_root_rebind_changes_physical_identity_and_durably_blocks(tmp_path):
    _, _, _, controller, root, _, dispatch = environment(tmp_path); issued = grant(controller, dispatch)
    old_root = tmp_path / "old-workspace"
    def rebind():
        root.rename(old_root); root.mkdir()
    assert blocked(lambda: controller.apply(create_plan(issued["grant_id"]), now=103, before_first_write=rebind)) == "BLOCKED"
    row = controller.store.db.execute("SELECT state FROM execution_workspaces WHERE workspace_id='workspace-a'").fetchone()
    assert row[0] == "INTEGRITY_BLOCKED" and not (root / "artifact.txt").exists()


def test_r1_expiry_during_apply_is_revalidated_before_mutation(tmp_path):
    _, _, _, controller, root, _, dispatch = environment(tmp_path); issued = grant(controller, dispatch, grant_seconds=5)
    plan = ExecutionPlan(issued["grant_id"], tuple(FileOperation("CREATE", p, "ABSENT", digest(v), v) for p, v in (("a.txt", b"a"), ("b.txt", b"b"))))
    moments = iter((103, 103, 200)); controller._clock = lambda: next(moments)
    assert blocked(lambda: controller.apply(plan, now=103)) == "BLOCKED"
    assert not (root / "a.txt").exists() and not (root / "b.txt").exists()
    assert controller.transaction(issued["grant_id"])["state"] == "FAILED"


def test_r1_unexpected_oserror_is_harness_error_not_blocked(tmp_path):
    _, _, _, controller, _, _, dispatch = environment(tmp_path); issued = grant(controller, dispatch)
    outcome = blocked(lambda: controller.apply(create_plan(issued["grant_id"]), now=103,
                      before_first_write=lambda: (_ for _ in ()).throw(OSError("unexpected harness fault"))))
    assert outcome == "HARNESS_ERROR"


def test_r1_hardlink_swap_during_failure_never_writes_external_inode(tmp_path):
    _, _, registry, controller, root, _, dispatch = environment(tmp_path)
    target = root / "artifact.txt"; target.write_bytes(b"old")
    outside = tmp_path / "outside.txt"; outside.write_bytes(b"outside")
    issued = grant(controller, dispatch)
    plan = ExecutionPlan(issued["grant_id"], (FileOperation("REPLACE", "artifact.txt", digest(b"old"), digest(b"new"), b"new"),))
    def hostile_swap(*_):
        target.unlink(); os.link(outside, target); raise BlockedError("injected failure")
    assert blocked(lambda: controller.apply(plan, now=103, after_operation=hostile_swap)) == "BLOCKED"
    assert outside.read_bytes() == b"outside"
    assert registry.state("workspace-a") == "INTEGRITY_BLOCKED"
