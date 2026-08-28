"""AF-04 functional tests using disposable runtime and queue roots only."""
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from src.autonomy import (AutonomyRuntime, BlockedError, DisposableExternalSession,
                          IntegrityBlockedError, RuntimeRootPolicy, WorkerProfile,
                          deterministic_task_id)
from src.directive.contracts import ValidationStatus
from src.directive.authenticator import DirectiveAuthenticator, compute_payload_bytes_and_hash


def sha(data): return hashlib.sha256(data).hexdigest()


class Verifier:
    def __init__(self, ok=True): self.ok = ok
    def __call__(self, payload, envelope, directive_file_path=None):
        if not self.ok: return ValidationStatus.REMOTE_BRANCH_UNAVAILABLE, "unavailable", False, {}
        return ValidationStatus.AUTHENTIC, "ok", payload.requires_human_approval, {
            "payload_commit_sha": envelope.payload_commit_sha,
            "payload_blob_sha": envelope.payload_blob_sha,
            "payload_sha256": envelope.payload_sha256,
            "signer_identity": "trusted-signer", "signature_valid": True,
            "signer_allowed": True, "remote_ancestry_verified": True,
        }


def record(directive_id="directive-a", action="STATUS_REQUEST", target="PROJECT", human=False, **changes):
    payload = {
        "directive_version": "2.0", "directive_id": directive_id, "project": "CONTROL",
        "target_project": target, "target_stage": "TEST", "action_type": action,
        "action": "read-only", "created_at": "2026-01-01T00:00:00+00:00",
        "expires_at": "2099-01-01T00:00:00+00:00", "issued_by": "human",
        "requires_human_approval": human, "allowed_scope": [], "preconditions": {},
        "success_criteria": {}, "failure_policy": "FAIL_CLOSED",
        "rollback_policy": "NONE", "payload": {},
    }
    commit = "a" * 40; blob = "b" * 40
    payload_hash = sha(json.dumps(payload, sort_keys=True).encode())
    values = {
        "directive_id": directive_id, "directive_source_sha": commit,
        "directive_blob_sha": blob, "directive_payload_sha256": payload_hash,
        "accepted_at": "2026-01-01T00:00:00+00:00",
        "queue_state": "READY_FOR_FUTURE_EXECUTOR", "target_project": target,
        "action_type": action, "requires_human_approval": human, "executed": False,
        "execution_attempts": 0, "readback_verified": True,
        "idempotency_key": sha(f"{directive_id}:{commit}:{payload_hash}".encode()),
        "signer_identity": "trusted-signer", "directive_payload": payload,
        "directive_source_path": f"directives/inbox/{directive_id}.json",
    }
    values.update(changes); return values


def write_queue(path, records):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(json.dumps(item, separators=(",", ":")) + "\n" for item in records), encoding="utf-8")


def environment(tmp_path, records=(), *, verifier=None, profiles=()):
    roots = tuple(tmp_path / name for name in ("canonical-repo", "oracle-repo", "micro-repo"))
    for root in roots: root.mkdir()
    runtime_root = tmp_path / "runtime"; runtime_root.mkdir()
    queue = tmp_path / "input" / "execution_queue.jsonl"; write_queue(queue, records)
    runtime = AutonomyRuntime(runtime_root=runtime_root, queue_path=queue,
                              repository_roots=roots, supported_targets=("PROJECT",),
                              verifier=verifier if verifier is not None else Verifier(),
                              profiles=profiles, clock=lambda: 100)
    return runtime, queue, roots


def test_f01_explicit_safe_runtime_root_initializes(tmp_path):
    runtime, _, _ = environment(tmp_path); assert runtime.root == (tmp_path / "runtime").resolve()
    assert (runtime.root / "autonomy.sqlite").exists()


def test_f02_repository_protected_and_symlink_roots_rejected(tmp_path, monkeypatch):
    runtime, _, roots = environment(tmp_path); policy = RuntimeRootPolicy(roots)
    with pytest.raises(BlockedError): policy.validate(roots[0])
    monkeypatch.setattr(Path, "is_symlink", lambda self: self.name == "runtime" or False)
    with pytest.raises(BlockedError): policy.validate(runtime.root)


def test_f03_valid_authenticated_directive_creates_deterministic_task(tmp_path):
    item = record(); runtime, _, _ = environment(tmp_path, (item,)); result = runtime.run_once(now=100)
    task_id = deterministic_task_id(item["directive_id"], item["idempotency_key"])
    assert result["ingested"] == [task_id] and runtime.store.task(task_id)["state"] == "WAITING_CAPACITY"


def test_f04_identical_duplicate_ingest_is_idempotent(tmp_path):
    item = record(); runtime, _, _ = environment(tmp_path, (item,)); runtime.run_once(now=100)
    assert runtime.run_once(now=100)["ingested"] == []
    assert runtime.store.db.execute("SELECT count(*) FROM tasks").fetchone()[0] == 1


def test_f05_conflicting_duplicate_provenance_integrity_blocks(tmp_path):
    first = record(); runtime, queue, _ = environment(tmp_path, (first,)); runtime.run_once(now=100)
    second = record(); second["directive_source_sha"] = "c" * 40
    second["idempotency_key"] = sha(f"directive-a:{'c'*40}:{second['directive_payload_sha256']}".encode())
    write_queue(queue, (first, second))
    with pytest.raises(IntegrityBlockedError): runtime.run_once(now=100)


def test_f06_malformed_queue_creates_no_task(tmp_path):
    runtime, queue, _ = environment(tmp_path); queue.write_bytes(b"{bad json\n")
    with pytest.raises(IntegrityBlockedError): runtime.run_once(now=100)
    assert runtime.store.db.execute("SELECT count(*) FROM tasks").fetchone()[0] == 0


@pytest.mark.parametrize("change", ({"readback_verified": False}, {"executed": True}, {"queue_state": "EXECUTED"}))
def test_f07_unverified_executed_or_wrong_state_blocked(tmp_path, change):
    runtime, _, _ = environment(tmp_path, (record(**change),))
    with pytest.raises(BlockedError): runtime.run_once(now=100)


def test_f08_provenance_failure_creates_no_task(tmp_path):
    runtime, _, _ = environment(tmp_path, (record(),), verifier=Verifier(False))
    with pytest.raises(BlockedError): runtime.run_once(now=100)
    assert runtime.store.db.execute("SELECT count(*) FROM tasks").fetchone()[0] == 0


def test_f09_unknown_and_prohibited_actions_blocked(tmp_path):
    for index, action in enumerate(("FUTURE_ACTION", "ENABLE_REAL_MONEY")):
        root = tmp_path / str(index); root.mkdir(); runtime, _, _ = environment(root, (record(action=action),))
        with pytest.raises(BlockedError): runtime.run_once(now=100)


def test_f10_unknown_target_blocked(tmp_path):
    runtime, _, _ = environment(tmp_path, (record(target="EVIL"),))
    with pytest.raises(BlockedError): runtime.run_once(now=100)


def test_f11_waiting_human_remains_nonleaseable(tmp_path):
    item = record(human=True); runtime, _, _ = environment(tmp_path, (item,)); runtime.run_once(now=100)
    task_id = deterministic_task_id(item["directive_id"], item["idempotency_key"])
    assert runtime.store.task(task_id)["state"] == "WAITING_HUMAN"


def test_f12_mapping_is_deterministic_and_governance_bound(tmp_path):
    item = record(action="AUDIT_REQUEST"); runtime, _, _ = environment(tmp_path, (item,)); runtime.run_once(now=100)
    task = runtime.store.task(deterministic_task_id(item["directive_id"], item["idempotency_key"]))
    assert task["capability"] == "AUDIT_READ" and task["governance_allowed"] == 1


def test_f13_zero_workers_waits_capacity_never_running(tmp_path):
    item = record(); runtime, _, _ = environment(tmp_path, (item,)); runtime.run_once(now=100)
    assert runtime.projection(now=100)["workers"] == []
    assert runtime.projection(now=100)["tasks"]["RUNNING"] == 0


def test_f14_local_harness_routes_matching_truth_only(tmp_path):
    profile = WorkerProfile("local", "local-disposable", ("OBSERVE_STATUS",), ("PROJECT",), 1, 10)
    item = record(); runtime, _, _ = environment(tmp_path, (item,), profiles=(profile,))
    DisposableExternalSession(runtime.gateway, profile, session_id="session").connect(now=100)
    result = runtime.run_once(now=100); assert len(result["routed"]) == 1


def test_f15_stale_session_not_eligible(tmp_path):
    profile = WorkerProfile("local", "local-disposable", ("OBSERVE_STATUS",), ("PROJECT",), 1, 10)
    runtime, _, _ = environment(tmp_path, (record(),), profiles=(profile,))
    DisposableExternalSession(runtime.gateway, profile, session_id="session").connect(now=80)
    runtime.run_once(now=100); assert runtime.projection(now=100)["tasks"]["WAITING_CAPACITY"] == 1


def test_f16_expired_lease_reconciles_deterministically(tmp_path):
    runtime, _, _ = environment(tmp_path); runtime.store.create_task(task_id="t",directive_id="d",target_project="PROJECT",capability="C",governance_allowed=True,retry_budget=1,now=1)
    runtime.store.register_worker(worker_id="w",kind="test",capabilities=("C",),targets=("PROJECT",),heartbeat_sla=100,capacity=1,now=1)
    runtime.store.claim("t","w",lease_seconds=1,now=1); runtime.run_once(now=3)
    task = runtime.store.task("t")
    assert task["attempt_count"] == 1 and task["state"] == "WAITING_CAPACITY"
    assert any(event["event"] == "LEASE_EXPIRED" for event in runtime.store.audit_events("t"))


def test_f17_reopen_preserves_task_and_provenance(tmp_path):
    item = record(); runtime, queue, roots = environment(tmp_path, (item,)); runtime.run_once(now=100); runtime.store.close()
    reopened = AutonomyRuntime(runtime_root=tmp_path/"runtime",queue_path=queue,repository_roots=roots,supported_targets=("PROJECT",),verifier=Verifier(),clock=lambda:100)
    assert reopened.store.db.execute("SELECT count(*) FROM autonomy_provenance").fetchone()[0] == 1


def test_f18_recovery_skips_applying_without_workspace_authority(tmp_path):
    runtime, _, _ = environment(tmp_path)
    runtime.store.db.execute("INSERT INTO execution_grants VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",("g","t","w","s","l","missing","PROJECT","C","[]","[]",1,200,1,"APPLYING","p"))
    assert runtime._recover(100) == [{"grant_id":"g","state":"UNKNOWN"}]


def test_f19_projection_never_fabricates_provider_availability(tmp_path):
    runtime, _, _ = environment(tmp_path); projection = runtime.projection(now=100)
    assert projection["workers"] == [] and projection["execution"]["status"] == "UNKNOWN"


def test_f20_source_and_protected_roots_are_not_modified(tmp_path):
    runtime, queue, roots = environment(tmp_path, (record(),)); before = queue.read_bytes(); runtime.run_once(now=100)
    assert queue.read_bytes() == before and all(not list(root.rglob("autonomy.sqlite")) for root in roots)


def test_f_r1_01_default_named_source_revalidates_exact_path(tmp_path):
    seen = []
    class Capture(Verifier):
        def __call__(self, payload, envelope, directive_file_path=None):
            seen.append(directive_file_path.as_posix())
            return super().__call__(payload, envelope, directive_file_path)
    runtime, _, _ = environment(tmp_path, (record(),), verifier=Capture())
    runtime.run_once(now=100)
    assert seen == ["directives/inbox/directive-a.json"]


def test_f_r1_02_nonstandard_filename_revalidates_original_blob_path(tmp_path):
    item = record(directive_source_path="directives/inbox/human-chosen-name.json")
    seen = []
    class Capture(Verifier):
        def __call__(self, payload, envelope, directive_file_path=None):
            seen.append(directive_file_path.as_posix())
            return super().__call__(payload, envelope, directive_file_path)
    runtime, _, _ = environment(tmp_path, (item,), verifier=Capture())
    runtime.run_once(now=100)
    assert seen == ["directives/inbox/human-chosen-name.json"]


@pytest.mark.parametrize("source", (
    "../directive-a.json", "/directives/inbox/a.json", "C:/directives/inbox/a.json",
    "\\\\host\\share\\a.json", "directives/inbox/../a.json",
    "directives/inbox/a\x00.json", "state/a.json", "directives/inbox/\u202ea.json",
))
def test_f_r1_03_04_source_path_substitution_and_traversal_blocked(tmp_path, source):
    runtime, _, _ = environment(tmp_path, (record(directive_source_path=source),))
    with pytest.raises(BlockedError): runtime.run_once(now=100)


def test_f_r1_05_identical_source_path_duplicate_is_idempotent(tmp_path):
    item = record(directive_source_path="directives/inbox/custom.json")
    runtime, queue, _ = environment(tmp_path, (item,)); runtime.run_once(now=100)
    write_queue(queue, (item, item)); assert runtime.run_once(now=100)["ingested"] == []
    assert runtime.store.db.execute("SELECT count(*) FROM tasks").fetchone()[0] == 1


def test_f_r1_06_conflicting_source_path_integrity_blocks(tmp_path):
    first = record(directive_source_path="directives/inbox/one.json")
    second = dict(first, directive_source_path="directives/inbox/two.json")
    runtime, queue, _ = environment(tmp_path, (first,)); runtime.run_once(now=100)
    write_queue(queue, (first, second))
    with pytest.raises(IntegrityBlockedError): runtime.run_once(now=100)


def _real_authenticator(tmp_path, monkeypatch, item, *, human=None):
    payload_bytes = json.dumps(item["directive_payload"], sort_keys=True).encode()
    _, payload_sha, blob_sha = compute_payload_bytes_and_hash(payload_bytes)
    item["directive_payload_sha256"] = payload_sha
    item["directive_blob_sha"] = blob_sha
    item["idempotency_key"] = sha(f'{item["directive_id"]}:{item["directive_source_sha"]}:{payload_sha}'.encode())
    repo = tmp_path / "auth-repo"; repo.mkdir(); (repo / ".git").mkdir()
    auth = DirectiveAuthenticator(repo_root=repo)
    monkeypatch.setattr(auth, "query_remote_branch_head", lambda _: (item["directive_source_sha"], None))
    monkeypatch.setattr(auth, "verify_commit_signature", lambda *_: (True, True, "trusted-signer", True))
    import src.directive.authenticator as auth_module
    def run(args, **kwargs):
        op = args[3]
        if op == "show": return SimpleNamespace(returncode=0, stdout=payload_bytes, stderr=b"")
        if op == "rev-parse": return SimpleNamespace(returncode=0, stdout=blob_sha + "\n", stderr="")
        return SimpleNamespace(returncode=0, stdout="", stderr="")
    monkeypatch.setattr(auth_module.subprocess, "run", run)
    return auth


def test_f_r1_07_real_directive_authenticator_contract_ingests(tmp_path, monkeypatch):
    item = record(directive_source_path="directives/inbox/not-the-id.json")
    auth = _real_authenticator(tmp_path, monkeypatch, item)
    runtime, _, _ = environment(tmp_path, (item,), verifier=auth.authenticate)
    assert len(runtime.run_once(now=100)["ingested"]) == 1


@pytest.mark.parametrize("change", ("signer", "ancestry", "commit", "blob", "payload", "human"))
def test_f_r1_08_09_10_12_real_contract_contradictions_block(tmp_path, change):
    item = record()
    class Contradiction(Verifier):
        def __call__(self, payload, envelope, directive_file_path=None):
            status, reason, human, meta = super().__call__(payload, envelope, directive_file_path)
            if change == "signer": meta["signer_allowed"] = False
            elif change == "ancestry": meta["remote_ancestry_verified"] = False
            elif change == "commit": meta["payload_commit_sha"] = "f" * 40
            elif change == "blob": meta["payload_blob_sha"] = "f" * 40
            elif change == "payload": meta["payload_sha256"] = "f" * 64
            elif change == "human": human = not human
            return status, reason, human, meta
    runtime, _, _ = environment(tmp_path, (item,), verifier=Contradiction())
    with pytest.raises(BlockedError): runtime.run_once(now=100)
    assert runtime.store.db.execute("SELECT count(*) FROM tasks").fetchone()[0] == 0


@pytest.mark.parametrize("verifier", (
    lambda *args: (_ for _ in ()).throw(RuntimeError("offline secret=hidden")),
    lambda *args: (ValidationStatus.AUTHENTIC, "bad", False, None),
))
def test_f_r1_11_unavailable_or_malformed_authenticator_fails_closed(tmp_path, verifier):
    runtime, _, _ = environment(tmp_path, (record(),), verifier=verifier)
    with pytest.raises(BlockedError): runtime.run_once(now=100)
    assert runtime.store.db.execute("SELECT count(*) FROM tasks").fetchone()[0] == 0


def test_f_r1_legacy_record_without_source_path_fails_closed(tmp_path):
    item = record(); del item["directive_source_path"]
    runtime, _, _ = environment(tmp_path, (item,))
    with pytest.raises(BlockedError): runtime.run_once(now=100)
