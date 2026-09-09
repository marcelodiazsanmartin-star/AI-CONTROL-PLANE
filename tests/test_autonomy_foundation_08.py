"""AF-08 functional tests over disposable ORACLE-shaped Git fixtures only."""
import hashlib
import json
import subprocess
import time
from pathlib import Path

import pytest

from src.autonomy.real_project import (
    AF08_PROTOCOL, CANARY_PATH, CAPABILITY, RISK, CanaryPlan, MutationSafetyTruth,
    DurableMutationSafetyAuthority, RealProjectCanaryRegistry, ScopedCanaryController, canonical_json,
)
from src.autonomy.store import AutonomyStore, BlockedError, IntegrityBlockedError
from src.directive.approval_engine import ApprovalAuditChain, ApprovalState, DurableApprovalEngine


class GatewayTruth:
    def __init__(self): self.fresh=True; self.dispatch=[]
    def verified_session_binding(self, worker_id, session_id, *, now): return self.fresh and (worker_id,session_id)==("worker-1","session-1")
    def dispatch_projection(self): return list(self.dispatch)


def git(root, *args):
    result=subprocess.run(["git","-C",str(root),*args],capture_output=True,text=True,check=True,shell=False)
    return result.stdout.strip()


def environment(tmp_path, *, operation="CREATE", initial=None):
    project=tmp_path/"oracle-fixture";project.mkdir(parents=True);git(project,"init","-q");git(project,"config","user.email","fixture@example.invalid");git(project,"config","user.name","Fixture")
    (project/"README.md").write_text("fixture\n",encoding="utf-8")
    if initial is not None:
        canary=project/CANARY_PATH;canary.parent.mkdir();canary.write_bytes(initial)
    git(project,"add",".");git(project,"commit","-qm","fixture")
    base=git(project,"rev-parse","HEAD")
    store=AutonomyStore(tmp_path/"runtime"/"autonomy.sqlite")
    store.create_task(task_id="task-1",directive_id="directive-1",target_project="ORACLE-AI",capability=CAPABILITY,requires_human_approval=True,governance_allowed=True,retry_budget=0)
    audit=ApprovalAuditChain(tmp_path/"runtime"/"approval.audit")
    approvals=DurableApprovalEngine(tmp_path/"runtime"/"approvals.jsonl",audit)
    parameter_hash=hashlib.sha256(b"parameters").hexdigest()
    approval=approvals.create_request("directive-1",CAPABILITY,parameter_hash,"ORACLE-AI",RISK)
    approvals.transition_state(approval["approval_request_id"],ApprovalState.NOTIFIED,"SYSTEM")
    approvals.transition_state(approval["approval_request_id"],ApprovalState.APPROVED,"SYSTEM",approver_id="HUMAN_OPERATOR")
    gateway=GatewayTruth();registry=RealProjectCanaryRegistry(control_plane_root=Path(__file__).resolve().parents[1])
    registry.register_fixture(workspace_id="authority-1",root=project,target_project="ORACLE-AI",project_identity="oracle-fixture",pinned_base_commit_sha=base)
    controller=ScopedCanaryController(store,gateway,registry)
    receipt=controller.consume_approval(engine=approvals,approval_request_id=approval["approval_request_id"],task_id="task-1",directive_id="directive-1",parameter_hash=parameter_hash)
    store.register_worker(worker_id="worker-1",kind="LOCAL",capabilities=[CAPABILITY],targets=["ORACLE-AI"],heartbeat_sla=120,capacity=1)
    lease=store.claim("task-1","worker-1",lease_seconds=120);store.start("task-1","worker-1",lease["lease_id"])
    dispatch_id="dispatch-1";gateway.dispatch=[{"dispatch_id":dispatch_id,"task_id":"task-1","worker_id":"worker-1","session_id":"session-1","lease_id":lease["lease_id"],"state":"RUNNING"}]
    content=b"AF08 governed canary\n" if operation!="DELETE" else None
    pre="ABSENT" if initial is None else hashlib.sha256(initial).hexdigest();post="ABSENT" if content is None else hashlib.sha256(content).hexdigest()
    authority={"protocol_version":AF08_PROTOCOL,"authorization_id":"authority-1","directive_id":"directive-1","task_id":"task-1","capability":CAPABILITY,"target_project":"ORACLE-AI","project_identity":"oracle-fixture","pinned_base_commit_sha":base,"worktree_root":str(project.resolve()),"allowed_relative_path":CANARY_PATH,"allowed_operation":operation,"max_files":1,"max_bytes":4096,"expected_preimage_sha256":pre,"expected_postimage_sha256":post,"approval_receipt_id":receipt["receipt_id"],"issued_at":time.time()-1,"expires_at":time.time()+120,"nonce":"nonce-1","worker_id":"worker-1","session_id":"session-1","lease_id":lease["lease_id"],"dispatch_id":dispatch_id}
    return locals()


def provision(env): return env["controller"].provision_authority(canonical_json(env["authority"]))
def safety(): return MutationSafetyTruth("HEALTHY","ARMED",time.time(),True,True)
def apply(env, **changes):
    args={"worker_id":"worker-1","session_id":"session-1","lease_id":env["lease"]["lease_id"],"dispatch_id":"dispatch-1","provider_state":"PROVIDER_CONNECTED_UNATTESTED","provider_observed_at":time.time(),"safety":safety(),"provenance_verifier":lambda _:True};args.update(changes)
    return env["controller"].apply("authority-1",CanaryPlan(env["operation"],CANARY_PATH,env["content"]),**args)


def test_exact_approval_receipt_releases_waiting_human(tmp_path):
    env=environment(tmp_path);receipt=env["receipt"];assert receipt["state"]=="READY";assert env["store"].task("task-1")["requires_human_approval"]==0

def test_authority_is_canonical_bounded_and_single_use(tmp_path):
    env=environment(tmp_path);provision(env)
    with pytest.raises(BlockedError):provision(env)

@pytest.mark.parametrize("field,value",[("capability","WRITE"),("target_project","MICRO-MARKET-ORACLE"),("allowed_relative_path","../x"),("max_files",2),("max_bytes",4097),("expires_at",0)],ids=["capability","target","path","files","bytes","expiry"])
def test_authority_scope_is_fail_closed(tmp_path,field,value):
    env=environment(tmp_path);env["authority"][field]=value
    with pytest.raises(BlockedError):provision(env)

def test_unknown_authority_field_is_blocked(tmp_path):
    env=environment(tmp_path);env["authority"]["provider_claim"]=True
    with pytest.raises(BlockedError):provision(env)

def test_actual_create_hashes_review_pending_and_rollback(tmp_path):
    env=environment(tmp_path);provision(env);evidence=apply(env);target=env["project"]/CANARY_PATH
    assert target.read_bytes()==env["content"] and evidence["postimage_sha256"]==hashlib.sha256(env["content"]).hexdigest()
    assert env["store"].task("task-1")["state"]=="REVIEW_PENDING"
    env["controller"].rollback("authority-1");assert not target.exists()

@pytest.mark.parametrize("operation,initial",[("REPLACE",b"old\n"),("DELETE",b"old\n")])
def test_replace_delete_and_exact_rollback(tmp_path,operation,initial):
    env=environment(tmp_path,operation=operation,initial=initial);provision(env);apply(env);env["controller"].rollback("authority-1");assert (env["project"]/CANARY_PATH).read_bytes()==initial

def test_provider_plan_cannot_expand_scope(tmp_path):
    env=environment(tmp_path);provision(env)
    with pytest.raises(BlockedError):env["controller"].apply("authority-1",CanaryPlan("CREATE","other",b"x"),worker_id="worker-1",session_id="session-1",lease_id=env["lease"]["lease_id"],dispatch_id="dispatch-1",provider_state="PROVIDER_CONNECTED_UNATTESTED",provider_observed_at=time.time(),safety=safety(),provenance_verifier=lambda _:True)

def test_toctou_before_write_rolls_back_without_mutation(tmp_path):
    env=environment(tmp_path);provision(env)
    with pytest.raises(BlockedError):apply(env,before_write=lambda:(env["project"]/"dirty.txt").write_text("x"))
    assert not (env["project"]/CANARY_PATH).exists()

@pytest.mark.parametrize("health,killswitch,valid",[("UNKNOWN","ARMED",True),("CRITICAL","ARMED",True),("HEALTHY","DISARMED",True),("HEALTHY","TRIGGERED",True),("HEALTHY","ARMED",False)])
def test_watchdog_killswitch_preflight(tmp_path,health,killswitch,valid):
    env=environment(tmp_path);provision(env)
    with pytest.raises(BlockedError):apply(env,safety=MutationSafetyTruth(health,killswitch,time.time(),valid,valid))

def test_receipt_survives_restart_and_replay_is_blocked(tmp_path):
    env=environment(tmp_path);restarted=ScopedCanaryController(env["store"],env["gateway"],env["registry"]);assert restarted.receipt(env["receipt"]["receipt_id"])["state"]=="READY"
    with pytest.raises(BlockedError):restarted.consume_approval(engine=env["approvals"],approval_request_id=env["approval"]["approval_request_id"],task_id="task-1",directive_id="directive-1",parameter_hash=env["parameter_hash"])

def test_crash_after_approval_consumption_recovers_once(tmp_path):
    env=environment(tmp_path)
    env["store"].create_task(task_id="task-2",directive_id="directive-2",target_project="ORACLE-AI",capability=CAPABILITY,requires_human_approval=True,governance_allowed=True,retry_budget=0)
    parameter_hash=hashlib.sha256(b"parameters-2").hexdigest()
    approval=env["approvals"].create_request("directive-2",CAPABILITY,parameter_hash,"ORACLE-AI",RISK)
    env["approvals"].transition_state(approval["approval_request_id"],ApprovalState.NOTIFIED,"SYSTEM")
    env["approvals"].transition_state(approval["approval_request_id"],ApprovalState.APPROVED,"SYSTEM",approver_id="HUMAN_OPERATOR")
    with pytest.raises(RuntimeError):
        env["controller"].consume_approval(engine=env["approvals"],approval_request_id=approval["approval_request_id"],task_id="task-2",directive_id="directive-2",parameter_hash=parameter_hash,crash_after_consumption=lambda:(_ for _ in ()).throw(RuntimeError("crash")))
    row=env["store"].db.execute("SELECT receipt_id,state FROM approval_consumption_receipts WHERE task_id='task-2'").fetchone()
    assert row["state"]=="PENDING"
    recovered=env["controller"].recover_approval_release(engine=env["approvals"],receipt_id=row["receipt_id"])
    assert recovered["state"]=="READY" and env["store"].task("task-2")["state"]=="QUEUED"
    assert env["store"].db.execute("SELECT count(*) FROM approval_consumption_receipts WHERE task_id='task-2'").fetchone()[0]==1

def test_global_mutation_defaults_remain_false():
    from src.autonomy.real_project import REAL_PROJECT_MUTATION_ENABLED,CONTROL_PLANE_EXECUTE_MUTATING_DIRECTIVES
    assert REAL_PROJECT_MUTATION_ENABLED is False and CONTROL_PLANE_EXECUTE_MUTATING_DIRECTIVES is False

def test_durable_watchdog_killswitch_truth_is_not_self_asserted(tmp_path):
    state=tmp_path/"killswitch.json";audit=tmp_path/"incident.audit"
    record={"killswitch_state":"ARMED","active_incident_id":None,"trigger_reason":None,"root_cause_resolved":False,"recovery_approved":False,"last_updated":time.time()}
    state.write_text(json.dumps(record),encoding="utf-8")
    authority=DurableMutationSafetyAuthority(killswitch_file=state,incident_audit_file=audit)
    truth=authority.evaluate(heartbeat_timestamp=time.time(),worker_state="AVAILABLE",crypto_valid=True,governance_valid=True)
    assert truth.watchdog_health=="HEALTHY" and truth.killswitch_state=="ARMED"

def test_missing_or_corrupt_durable_killswitch_blocks(tmp_path):
    authority=DurableMutationSafetyAuthority(killswitch_file=tmp_path/"missing",incident_audit_file=tmp_path/"audit")
    with pytest.raises(BlockedError):authority.evaluate(heartbeat_timestamp=time.time(),worker_state="AVAILABLE",crypto_valid=True,governance_valid=True)
    path=tmp_path/"missing";path.write_text("{")
    with pytest.raises(IntegrityBlockedError):authority.evaluate(heartbeat_timestamp=time.time(),worker_state="AVAILABLE",crypto_valid=True,governance_valid=True)

def test_ingestion_maps_only_exact_canary_action():
    from src.autonomy.ingestion import ACTION_CAPABILITIES
    assert ACTION_CAPABILITIES["GOVERNED_CANARY_WRITE"]==CAPABILITY
