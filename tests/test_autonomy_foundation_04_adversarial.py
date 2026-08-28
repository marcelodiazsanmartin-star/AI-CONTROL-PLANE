"""AF-04 A01-A20 adversarial campaign."""
import inspect
import json
import os
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from threading import Barrier

import pytest

import src.autonomy.ingestion as ingestion_module
import src.autonomy.runtime as runtime_module
from src.autonomy import (AutonomyRuntime, AutonomyStore, BlockedError,
                          DisposableExternalSession, IntegrityBlockedError,
                          RuntimeRootPolicy, SessionHello, WorkerProfile)
from tests.test_autonomy_foundation_04 import Verifier, environment, record, sha, write_queue


def classify(call):
    try: call()
    except BlockedError: return "BLOCKED"
    except Exception: return "HARNESS_ERROR"
    return "BYPASS_DETECTED"


def test_a01_forged_queue_without_provenance_blocked(tmp_path):
    runtime, _, _ = environment(tmp_path, (record(),), verifier=Verifier(False))
    assert classify(lambda: runtime.run_once(now=100)) == "BLOCKED"


def test_a02_payload_source_blob_sha_substitution_blocked(tmp_path):
    item = record(); original = Verifier()
    class Mismatch:
        def __call__(self, payload, envelope, directive_file_path=None):
            status, msg, human, meta = original(payload, envelope, directive_file_path); meta["payload_blob_sha"] = "f"*40; return status,msg,human,meta
    runtime, _, _ = environment(tmp_path, (item,), verifier=Mismatch())
    assert classify(lambda: runtime.run_once(now=100)) == "BLOCKED"


def test_a03_directive_replay_conflicting_provenance_blocked(tmp_path):
    first=record(); runtime,queue,_=environment(tmp_path,(first,));runtime.run_once(now=100)
    second=record();second["directive_blob_sha"]="c"*40;write_queue(queue,(first,second))
    assert classify(lambda: runtime.run_once(now=100)) == "BLOCKED"


def test_a04_target_action_capability_escalation_blocked(tmp_path):
    item=record();item["action_type"]="AUDIT_REQUEST"
    runtime,_,_=environment(tmp_path,(item,));assert classify(lambda:runtime.run_once(now=100))=="BLOCKED"


def test_a05_waiting_human_bypass_blocked(tmp_path):
    item=record(human=True);item["requires_human_approval"]=False
    runtime,_,_=environment(tmp_path,(item,));assert classify(lambda:runtime.run_once(now=100))=="BLOCKED"


def test_a06_prohibited_mutating_action_blocked(tmp_path):
    runtime,_,_=environment(tmp_path,(record(action="EXECUTE_TRADE"),));assert classify(lambda:runtime.run_once(now=100))=="BLOCKED"


def test_a07_malformed_and_oversized_jsonl_blocked(tmp_path):
    runtime,queue,_=environment(tmp_path);queue.write_bytes(b"x"*2_097_153)
    assert classify(lambda:runtime.run_once(now=100))=="BLOCKED"


def test_a08_queue_rewrite_reorder_truncation_across_restart_blocked(tmp_path):
    one=record("one");two=record("two");runtime,queue,roots=environment(tmp_path,(one,two));runtime.run_once(now=100);write_queue(queue,(two,one))
    reopened=AutonomyRuntime(runtime_root=tmp_path/"runtime",queue_path=queue,repository_roots=roots,supported_targets=("PROJECT",),verifier=Verifier(),clock=lambda:100)
    assert classify(lambda:reopened.run_once(now=100))=="BLOCKED"


def test_a09_signature_or_reachability_contradiction_blocked(tmp_path):
    runtime,_,_=environment(tmp_path,(record(),),verifier=Verifier(False));assert classify(lambda:runtime.run_once(now=100))=="BLOCKED"


def test_a10_concurrent_double_ingestion_never_duplicates(tmp_path):
    item=record();runtime,queue,roots=environment(tmp_path,(item,));second=AutonomyRuntime(runtime_root=tmp_path/"runtime",queue_path=queue,repository_roots=roots,supported_targets=("PROJECT",),verifier=Verifier(),clock=lambda:100);barrier=Barrier(2)
    def run(instance):
        barrier.wait(timeout=5)
        try: return len(instance.run_once(now=100)["ingested"])
        except BlockedError: return 0
        except Exception: return "HARNESS_ERROR"
    with ThreadPoolExecutor(max_workers=2) as pool: outcomes=list(pool.map(run,(runtime,second)))
    attack_result = "BLOCKED" if sorted(outcomes) == [0, 1] else "BYPASS_DETECTED"
    assert attack_result == "BLOCKED" and runtime.store.db.execute("SELECT count(*) FROM tasks").fetchone()[0]==1


def test_a11_crash_between_binding_and_task_creation_rolls_back(tmp_path,monkeypatch):
    runtime,_,_=environment(tmp_path,(record(),));original=runtime.store.audit;monkeypatch.setattr(runtime.store,"audit",lambda *a,**k:(_ for _ in()).throw(BlockedError("fault")))
    assert classify(lambda:runtime.run_once(now=100))=="BLOCKED" and runtime.store.db.execute("SELECT count(*) FROM tasks").fetchone()[0]==0
    monkeypatch.setattr(runtime.store,"audit",original);runtime.run_once(now=100);assert runtime.store.db.execute("SELECT count(*) FROM tasks").fetchone()[0]==1


def test_a12_corrupt_unsupported_sqlite_fails_closed(tmp_path):
    root=tmp_path/"runtime";root.mkdir();(root/"autonomy.sqlite").write_bytes(b"corrupt")
    repos=[]
    for name in ("a","b","c"): p=tmp_path/name;p.mkdir();repos.append(p)
    queue=tmp_path/"q";write_queue(queue,())
    assert classify(lambda:AutonomyRuntime(runtime_root=root,queue_path=queue,repository_roots=repos,supported_targets=("PROJECT",),verifier=Verifier()))=="BLOCKED"


def test_a13_fake_worker_self_registration_blocked(tmp_path):
    profile=WorkerProfile("w","local",("OBSERVE_STATUS",),("PROJECT",),1,10);runtime,_,_=environment(tmp_path,profiles=(profile,))
    hello=SessionHello("w","local",("OBSERVE_STATUS",),("PROJECT",),"s",0,100,1,"VERIFIED","VERIFIED")
    assert classify(lambda:runtime.gateway.register(hello,now=100))=="BLOCKED"


def test_a14_stale_future_heartbeat_cannot_fabricate_available(tmp_path):
    profile=WorkerProfile("w","local",("OBSERVE_STATUS",),("PROJECT",),1,10);runtime,_,_=environment(tmp_path,(record(),),profiles=(profile,));session=DisposableExternalSession(runtime.gateway,profile,session_id="s");session.connect(now=80)
    runtime.run_once(now=100);assert runtime.projection(now=100)["tasks"]["RUNNING"]==0


def test_a15_lease_session_owner_substitution_blocked(tmp_path):
    runtime,_,_=environment(tmp_path);runtime.store.create_task(task_id="t",directive_id="d",target_project="PROJECT",capability="C",governance_allowed=True,now=1);runtime.store.register_worker(worker_id="w",kind="x",capabilities=("C",),targets=("PROJECT",),heartbeat_sla=10,capacity=1,now=1);lease=runtime.store.claim("t","w",now=1)
    assert classify(lambda:runtime.store.start("t","evil",lease["lease_id"],now=1))=="BLOCKED"


def test_a16_real_repository_offered_as_runtime_root_blocked(tmp_path):
    runtime,_,roots=environment(tmp_path);assert classify(lambda:RuntimeRootPolicy(roots).validate(roots[0]))=="BLOCKED"


def test_a17_protected_symlink_reparse_escape_blocked(tmp_path,monkeypatch):
    runtime,_,roots=environment(tmp_path);original=Path.is_symlink;monkeypatch.setattr(Path,"is_symlink",lambda self:self.name=="runtime" or original(self))
    assert classify(lambda:RuntimeRootPolicy(roots).validate(runtime.root))=="BLOCKED"


def test_a18_secret_xss_metadata_is_sanitized_and_not_projected(tmp_path):
    item=record();item["signer_identity"]="secret=TOPSECRET<script>"
    class SecretVerifier(Verifier):
        def __call__(self,payload,envelope,directive_file_path=None):
            status,msg,human,meta=super().__call__(payload,envelope,directive_file_path);meta["signer_identity"]=item["signer_identity"];return status,msg,human,meta
    runtime,_,_=environment(tmp_path,(item,),verifier=SecretVerifier());runtime.run_once(now=100)
    assert "TOPSECRET" not in str(runtime.projection(now=100)) and "<script>" not in str(runtime.projection(now=100))


def test_a19_no_provider_network_subprocess_process_control_surface(tmp_path):
    # Scope: modules newly introduced by AF-04. The injected, existing
    # DirectiveAuthenticator retains bounded read-only Git provenance checks.
    source=(inspect.getsource(runtime_module)+inspect.getsource(ingestion_module)).lower()
    assert all(token not in source for token in ("import subprocess","import socket","import requests","popen(","os.system","provider_api"))


def test_a20_no_control_tower_main_protected_git_live_money_mutation(tmp_path):
    runtime,queue,roots=environment(tmp_path,(record(),));before=queue.read_bytes();runtime.run_once(now=100)
    assert queue.read_bytes()==before and runtime_module.CONTROL_PLANE_EXECUTE_MUTATING_DIRECTIVES is False
    assert all(not list(root.rglob("autonomy.sqlite")) for root in roots)
    assert {"git_add","git_commit","git_push","merge","place_order"}.isdisjoint(set(dir(runtime)))
