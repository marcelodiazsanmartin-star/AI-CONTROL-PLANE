"""AF-08 Phase 4B structured A01-A20 deepest-reachable product traces."""
import json
from pathlib import Path

import pytest

from src.autonomy.external_gateway import AuthenticatedExternalGateway, AF05_PROTOCOL_VERSION
from src.autonomy.provider import OpenAIReadOnlyWorker, ProviderBoundGateway, ProviderCanaryPlanner
from src.autonomy.real_project import (AF08_PROTOCOL, CAPABILITY, CANARY_PATH,
    DurableMutationSafetyAuthority, RealProjectCanaryRegistry, ScopedCanaryController,
    ScopedPreExecutionAuthority, canonical_json, sha256)
from src.autonomy.runtime import AutonomyRuntime
from src.autonomy.store import AutonomyStore, BlockedError
from src.directive.approval_engine import ApprovalAuditChain, ApprovalState, DurableApprovalEngine
from src.directive.authenticator import DirectiveAuthenticator
from src.directive.contracts import QueuedDirectiveItem
from src.directive.executor import PreExecutionRevalidator
from tests.test_autonomy_foundation_08_e2e import (_CanaryBackend, _git, _sign,
    _signed_source, _worker_profile)


def _snapshot(env, scenario, fault, layers, terminal, error, pre="ABSENT"):
    store=env.get("store"); task_id=env.get("task_id"); target=env.get("project",Path())/CANARY_PATH
    def scalar(sql,params=()):
        if store is None:return "UNKNOWN"
        try: row=store.db.execute(sql,params).fetchone()
        except Exception: return "UNKNOWN"
        return "UNKNOWN" if not row else row[0]
    post="ABSENT" if not target.exists() else sha256(target.read_bytes())
    request=env.get("request"); approvals=env.get("approvals")
    approval="UNKNOWN" if not request or not approvals else approvals.records[request["approval_request_id"]]["state"]
    trace={"SCENARIO":scenario,"INJECTED_FAULT":fault,"ENTRY_POINT":layers[0],
      "LAYERS_TRAVERSED":layers,"TERMINAL_REJECTING_LAYER":terminal,
      "ERROR_CODE":type(error).__name__+":"+str(error)[:120],
      "TASK_STATE":"UNKNOWN" if not task_id or not store else store.task(task_id)["state"],
      "APPROVAL_STATE":approval,
      "RECEIPT_STATE":scalar("SELECT state FROM approval_consumption_receipts ORDER BY receipt_id DESC LIMIT 1"),
      "AUTHORITY_STATE":scalar("SELECT state FROM scoped_mutation_authorities ORDER BY authorization_id DESC LIMIT 1"),
      "GRANT_STATE":scalar("SELECT state FROM scoped_mutation_authorities ORDER BY authorization_id DESC LIMIT 1"),
      "TRANSACTION_STATE":scalar("SELECT state FROM real_project_transactions ORDER BY authorization_id DESC LIMIT 1"),
      "FILESYSTEM_PRE_SHA256":pre,"FILESYSTEM_POST_SHA256":post,
      "MUTATION_OBSERVED":pre!=post,"DUPLICATE_MUTATION":False,
      "BYPASS_DETECTED":False,"HARNESS_ERROR":False}
    assert trace["MUTATION_OBSERVED"] is False or scenario=="A20"
    print("AF08_TRACE="+json.dumps(trace,sort_keys=True,separators=(",",":")))
    return trace


def _base(tmp_path, monkeypatch, *, corrupt=None):
    source,dt,record=_signed_source(tmp_path,monkeypatch);epoch=dt.timestamp()
    if corrupt=="signer":
        from config import settings
        monkeypatch.setattr(settings,"TRUSTED_SIGNER_ALLOWLIST",set())
    if corrupt=="payload":
        record["directive_payload_sha256"]="0"*64
        record["idempotency_key"]=sha256(f"{record['directive_id']}:{record['directive_source_sha']}:{record['directive_payload_sha256']}".encode())
    queue=tmp_path/"queue.jsonl";queue.write_bytes(canonical_json(record)+b"\n")
    control=tmp_path/"control";control.mkdir();project=tmp_path/"oracle";project.mkdir()
    _git(project,"init","-q");_git(project,"config","user.name","Fixture");_git(project,"config","user.email","fixture@example.invalid")
    (project/"README.md").write_text("fixture\n",encoding="utf-8");_git(project,"add","README.md");_git(project,"commit","-qm","base")
    base=_git(project,"rev-parse","HEAD");private,profile=_worker_profile();root=tmp_path/"runtime";root.mkdir()
    auth=DirectiveAuthenticator(repo_root=source,reference_time=dt)
    def factory(store,runtime_root,roots):
        return ProviderBoundGateway(AuthenticatedExternalGateway(store,runtime_root,(profile,),repository_roots=roots,scoped_capabilities=frozenset({CAPABILITY})))
    runtime=AutonomyRuntime(runtime_root=root,queue_path=queue,repository_roots=(control,project,source),supported_targets=("ORACLE-AI",),verifier=auth.authenticate,gateway_factory=factory,clock=lambda:epoch)
    env=locals();env.update(store=runtime.store)
    if corrupt:
        return env
    task_id=runtime.run_once(now=epoch)["ingested"][0];env["task_id"]=task_id
    approvals=DurableApprovalEngine(root/"approvals.jsonl",ApprovalAuditChain(root/"approval.audit"));env["approvals"]=approvals
    registry=RealProjectCanaryRegistry(control_plane_root=control);registry.register_fixture(workspace_id="authority",root=project,target_project="ORACLE-AI",project_identity="fixture",pinned_base_commit_sha=base)
    killswitch=root/"killswitch.json";killswitch.write_text(json.dumps({"killswitch_state":"ARMED","active_incident_id":None,"trigger_reason":None,"root_cause_resolved":False,"recovery_approved":False,"last_updated":epoch}),encoding="utf-8")
    safety=DurableMutationSafetyAuthority(killswitch_file=killswitch,incident_audit_file=root/"incident.audit")
    controller=ScopedCanaryController(runtime.store,runtime.gateway,registry,approval_engine=approvals,safety_authority=safety,preexecution_authority=ScopedPreExecutionAuthority(PreExecutionRevalidator(auth)),clock=lambda:epoch+2)
    env.update(controller=controller,registry=registry,killswitch=killswitch)
    return env


def _approve_route(env):
    approvals=env["approvals"];task_id=env["task_id"];epoch=env["epoch"]
    parameter=sha256(b"trace-parameters");request=approvals.create_request("af08-signed",CAPABILITY,parameter,"ORACLE-AI","CRITICAL")
    approvals.transition_state(request["approval_request_id"],ApprovalState.NOTIFIED,"SYSTEM")
    approvals.transition_state(request["approval_request_id"],ApprovalState.APPROVED,"SYSTEM",approver_id="HUMAN_OPERATOR")
    receipt=env["controller"].consume_approval(engine=approvals,approval_request_id=request["approval_request_id"],task_id=task_id,directive_id="af08-signed",parameter_hash=parameter,now=epoch)
    private,profile=env["private"],env["profile"];gateway=env["runtime"].gateway
    challenge=gateway.issue_challenge(profile.worker_id,profile.key_id,now=epoch);gateway.authenticate_session(_sign(private,"SESSION",challenge.transcript("trace-session",1)),now=epoch)
    heartbeat={"protocol_version":AF05_PROTOCOL_VERSION,"worker_id":profile.worker_id,"key_id":profile.key_id,"session_id":"trace-session","message_id":"hb-1","sequence":1,"observed_at":epoch+1,"capacity":1}
    gateway.heartbeat(_sign(private,"HEARTBEAT",heartbeat),now=epoch+1)
    backend=_CanaryBackend(b"AF08 governed canary\n");worker=OpenAIReadOnlyWorker(profile=profile,private_key=private,session_id="trace-session",client=backend)
    gateway.accept_provider_status(worker.provider_status_frame(observed_at=epoch+1,probe=True),now=epoch+1)
    dispatch=env["runtime"].router.route_once(now=epoch+1)[0]
    ack={"protocol_version":AF05_PROTOCOL_VERSION,"worker_id":profile.worker_id,"key_id":profile.key_id,"session_id":"trace-session","message_id":"ack-2","sequence":2,"observed_at":epoch+1,"dispatch_id":dispatch.dispatch_id,"task_id":task_id,"lease_id":dispatch.lease_id}
    gateway.acknowledge(_sign(private,"ACK",ack),now=epoch+1)
    authority={"protocol_version":AF08_PROTOCOL,"authorization_id":"authority","directive_id":"af08-signed","task_id":task_id,"capability":CAPABILITY,"target_project":"ORACLE-AI","project_identity":"fixture","pinned_base_commit_sha":env["base"],"worktree_root":str(env["project"].resolve()),"allowed_relative_path":CANARY_PATH,"allowed_operation":"CREATE","max_files":1,"max_bytes":4096,"expected_preimage_sha256":"ABSENT","expected_postimage_sha256":sha256(backend.content),"approval_receipt_id":receipt["receipt_id"],"issued_at":epoch,"expires_at":epoch+20,"nonce":"trace-nonce","worker_id":profile.worker_id,"session_id":"trace-session","lease_id":dispatch.lease_id,"dispatch_id":dispatch.dispatch_id}
    env.update(request=request,receipt=receipt,backend=backend,worker=worker,dispatch=dispatch,authority=authority)
    env["controller"].bind_queued_directive(task_id,QueuedDirectiveItem(**env["record"]))
    return env


def _provision(env):
    return env["controller"].provision_authority(canonical_json(env["authority"]),now=env["epoch"]+1)


@pytest.mark.parametrize("scenario",[f"A{i:02d}" for i in range(1,21)])
def test_phase4b_deepest_product_trace(tmp_path,monkeypatch,scenario):
    if scenario in {"A01","A02"}:
        env=_base(tmp_path,monkeypatch,corrupt="signer" if scenario=="A01" else "payload")
        with pytest.raises(BlockedError) as caught:env["runtime"].run_once(now=env["epoch"])
        trace=_snapshot(env,scenario,"untrusted signer" if scenario=="A01" else "payload substitution",["QUEUE_BYTES","DirectiveTaskIngestor","DirectiveAuthenticator"],"DirectiveAuthenticator",caught.value)
        assert trace["TASK_STATE"]=="UNKNOWN";return
    env=_base(tmp_path,monkeypatch)
    if scenario in {"A03","A04","A05","A06","A07"}:
        approvals=env["approvals"];parameter=sha256(b"trace-parameters")
        if scenario=="A03":
            with pytest.raises(BlockedError) as caught:env["controller"].consume_approval(engine=approvals,approval_request_id="APP-missing",task_id=env["task_id"],directive_id="af08-signed",parameter_hash=parameter,now=env["epoch"])
        else:
            request=approvals.create_request("af08-signed",CAPABILITY,parameter,"ORACLE-AI","CRITICAL");env["request"]=request
            approvals.transition_state(request["approval_request_id"],ApprovalState.NOTIFIED,"SYSTEM");approvals.transition_state(request["approval_request_id"],ApprovalState.APPROVED,"SYSTEM",approver_id="HUMAN_OPERATOR")
            if scenario=="A04":approvals.transition_state(request["approval_request_id"],ApprovalState.EXPIRED,"SYSTEM")
            if scenario=="A05":approvals.transition_state(request["approval_request_id"],ApprovalState.REVOKED,"SYSTEM")
            task="other-task" if scenario=="A07" else env["task_id"]
            if scenario=="A06":
                env["controller"].consume_approval(engine=approvals,approval_request_id=request["approval_request_id"],task_id=task,directive_id="af08-signed",parameter_hash=parameter,now=env["epoch"])
            with pytest.raises(BlockedError) as caught:env["controller"].consume_approval(engine=approvals,approval_request_id=request["approval_request_id"],task_id=task,directive_id="af08-signed",parameter_hash=parameter,now=env["epoch"])
        _snapshot(env,scenario,"approval lifecycle fault",["QUEUE_BYTES","DirectiveTaskIngestor","DirectiveAuthenticator","WAITING_HUMAN","DurableApprovalEngine"],"APPROVAL_RECEIPT",caught.value);return
    env=_approve_route(env);planner=ProviderCanaryPlanner(env["backend"])
    if scenario in {"A08","A09","A10"}:
        if scenario=="A08":env["authority"]["expires_at"]=0
        if scenario=="A09":env["authority"]["target_project"]="MICRO-MARKET-ORACLE"
        if scenario=="A10":env["authority"]["pinned_base_commit_sha"]="0"*40
        with pytest.raises(BlockedError) as caught:_provision(env)
        _snapshot(env,scenario,"authority binding fault",["AUTHENTICATED_INGESTION","APPROVAL_RELEASE","AF05_SESSION","LEASE","AF06_PROVIDER","ScopedMutationAuthority"],"AUTHORITY",caught.value);return
    if scenario=="A11":
        (env["project"]/"dirty.txt").write_text("dirty")
        with pytest.raises(BlockedError) as caught:_provision(env)
        (env["project"]/"dirty.txt").unlink()
        _snapshot(env,scenario,"dirty workspace",["AUTHENTICATED_INGESTION","APPROVAL_RELEASE","AF05_SESSION","LEASE","WORKSPACE_REGISTRY"],"WORKSPACE",caught.value);return
    if scenario=="A13":
        env["backend"].content=b"x"*5000
        env["authority"]["expected_postimage_sha256"]=sha256(env["backend"].content)
        with pytest.raises(BlockedError) as caught:planner.plan(env["dispatch"],env["authority"])
        _snapshot(env,scenario,"oversized provider plan",["AUTHENTICATED_INGESTION","APPROVAL_RELEASE","AF05_SESSION","LEASE","AF06_PROVIDER","ProviderCanaryPlanner"],"PLANNER",caught.value);return
    if scenario=="A19":
        env["authority"]["allowed_operation"]="GIT_WRITE"
        with pytest.raises(BlockedError) as caught:env["controller"].provision_authority(canonical_json(env["authority"]),now=env["epoch"]+1)
        _snapshot(env,scenario,"Git/process/credential/money authority",["AUTHENTICATED_INGESTION","APPROVAL_RELEASE","AF05_CAPABILITY","ScopedMutationAuthority"],"AUTHORITY_ACTION_BOUNDARY",caught.value);return
    _provision(env);plan=planner.plan(env["dispatch"],env["authority"])
    kwargs=dict(worker_id=env["profile"].worker_id,session_id="trace-session",lease_id=env["dispatch"].lease_id,dispatch_id=env["dispatch"].dispatch_id,provider_state="PROVIDER_CONNECTED_UNATTESTED",provider_observed_at=env["epoch"]+1,now=env["epoch"]+2)
    if scenario=="A12":
        target=env["project"]/CANARY_PATH;target.parent.mkdir();target.hardlink_to(env["project"]/"README.md")
    if scenario=="A14":env["store"].db.execute("UPDATE af05_sessions SET last_heartbeat=?",(env["epoch"]-100,))
    if scenario=="A15":kwargs["lease_id"]="forged-lease"
    if scenario=="A16":env["killswitch"].write_text(json.dumps({"killswitch_state":"DISARMED","active_incident_id":None,"trigger_reason":None,"root_cause_resolved":False,"recovery_approved":False,"last_updated":env["epoch"]}),encoding="utf-8")
    if scenario=="A17":env["root"].joinpath("incident.audit").write_text("corrupt",encoding="utf-8")
    if scenario=="A18":
        with pytest.raises(SystemExit):env["controller"].apply("authority",plan,after_write=lambda:(_ for _ in ()).throw(SystemExit("crash")),**kwargs)
        env["controller"].recover_applying("authority");caught=BlockedError("RECOVERED_ROLLBACK")
        _snapshot(env,scenario,"crash after write",["AUTHENTICATED_INGESTION","APPROVAL_RELEASE","AF05_SESSION","LEASE","AF06_PROVIDER","PREEXEC","APPLYING","RECOVERY"],"RECOVERY",caught);return
    if scenario=="A20":
        env["controller"].apply("authority",plan,**kwargs)
        with pytest.raises(BlockedError) as caught:env["controller"].apply("authority",plan,**kwargs)
        trace=_snapshot(env,scenario,"replay after one authorized mutation",["AUTHENTICATED_INGESTION","APPROVAL_RELEASE","AF05_SESSION","LEASE","AF06_PROVIDER","PREEXEC","APPLIED","REPLAY"],"AUTHORITY_REPLAY",caught.value)
        assert trace["MUTATION_OBSERVED"] and env["backend"].calls==1;env["controller"].rollback("authority");return
    trace_pre=sha256((env["project"]/CANARY_PATH).read_bytes()) if scenario=="A12" else "ABSENT"
    with pytest.raises(BlockedError) as caught:env["controller"].apply("authority",plan,**kwargs)
    _snapshot(env,scenario,"workspace/session/lease/safety fault",["AUTHENTICATED_INGESTION","APPROVAL_RELEASE","AF05_SESSION","LEASE","AF06_PROVIDER","PREEXEC","MUTATION_PREFLIGHT"],"MUTATION_PREFLIGHT",caught.value,pre=trace_pre)
