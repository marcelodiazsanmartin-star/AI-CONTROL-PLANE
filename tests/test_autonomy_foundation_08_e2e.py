"""AF-08 disposable project-path end-to-end proof."""
import base64
import hashlib
import json
import subprocess
from dataclasses import asdict
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from config import settings
from src.autonomy.external_gateway import AF05_PROTOCOL_VERSION, DOMAINS, AuthenticatedExternalGateway
from src.autonomy.provider import (PROVIDER_CONNECTED_UNATTESTED, OpenAIReadOnlyWorker,
    ProviderBoundGateway, ProviderCallResult, ProviderCanaryPlanner, ProviderEvidence)
from src.autonomy.real_project import (AF08_PROTOCOL, CAPABILITY, CANARY_PATH,
    AF08ProductProcessor, DurableMutationSafetyAuthority, RealProjectCanaryRegistry,
    ScopedCanaryController, ScopedPreExecutionAuthority, canonical_json, sha256)
from src.autonomy.runtime import AutonomyRuntime
from src.autonomy.store import AutonomyStore, IntegrityBlockedError
from src.autonomy.trust import TrustedWorkerProfile, signed_bytes
from src.directive.approval_engine import ApprovalAuditChain, ApprovalState, DurableApprovalEngine
from src.directive.authenticator import DirectiveAuthenticator, compute_payload_bytes_and_hash
from src.directive.contracts import QueuedDirectiveItem, ValidationStatus
from src.directive.executor import PreExecutionRevalidator
from tests.test_autonomy_foundation_08 import environment, provision, apply
from tests.test_autonomy_foundation_08 import GatewayTruth

def test_authenticated_governed_canary_e2e_and_exact_rollback(tmp_path):
    env=environment(tmp_path);assert env["store"].task("task-1")["state"]=="RUNNING";provision(env)
    evidence=apply(env);target=env["project"]/CANARY_PATH
    assert evidence["preimage_sha256"]=="ABSENT"
    assert evidence["postimage_sha256"]==hashlib.sha256(target.read_bytes()).hexdigest()
    assert env["store"].task("task-1")["state"]=="REVIEW_PENDING"
    env["controller"].rollback("authority-1");assert not target.exists()
    assert env["controller"].receipt(env["receipt"]["receipt_id"])["state"]=="READY"


import os
import shutil


def _resolve_ssh_keygen() -> str:
    found = shutil.which("ssh-keygen")
    if found:
        return found
    if os.name == "nt":
        win_path = Path(os.environ.get("WINDIR", r"C:\Windows")) / "System32" / "OpenSSH" / "ssh-keygen.exe"
        if win_path.exists():
            return str(win_path)
    raise RuntimeError("ssh-keygen executable not found on system; cannot generate or inspect test keys")


def _git(root, *args):
    result = subprocess.run(["git", "-C", str(root), *args], check=True,
                            capture_output=True, text=True, shell=False)
    return result.stdout.strip()


def _signed_source(tmp_path, monkeypatch):
    ssh_keygen = _resolve_ssh_keygen()
    remote = tmp_path / "directive-remote.git"
    source = tmp_path / "directive-source"
    remote.mkdir(); source.mkdir()
    _git(remote, "init", "--bare", "-q")
    _git(source, "init", "-q", "-b", "main")
    _git(source, "config", "user.name", "AF08 Fixture")
    _git(source, "config", "user.email", "af08@example.invalid")
    key = tmp_path / "signer"
    subprocess.run([ssh_keygen, "-q", "-t", "ed25519", "-N", "", "-f", str(key)], check=True)
    public = key.with_suffix(".pub").read_text(encoding="utf-8").strip()
    allowed = tmp_path / "allowed_signers"
    allowed.write_text("af08-fixture " + public + "\n", encoding="utf-8")
    _git(source, "config", "gpg.format", "ssh")
    _git(source, "config", "user.signingkey", str(key))
    _git(source, "config", "gpg.ssh.allowedSignersFile", str(allowed))
    _git(source, "config", "commit.gpgsign", "true")
    _git(source, "remote", "add", "origin", str(remote))
    now = datetime.now(timezone.utc)
    payload = {"directive_version":"1","directive_id":"af08-signed","project":"AI-CONTROL-PLANE",
        "target_project":"ORACLE-AI","target_stage":"AF-08","action_type":"GOVERNED_CANARY_WRITE",
        "action":"one-shot canary","created_at":now.isoformat(),"expires_at":(now+timedelta(hours=1)).isoformat(),
        "issued_by":"HUMAN_AUTHORITY","requires_human_approval":True,"allowed_scope":[CANARY_PATH],
        "preconditions":{},"success_criteria":{},"failure_policy":"FAIL_CLOSED","rollback_policy":"EXACT",
        "payload":{"path":CANARY_PATH}}
    inbox = source / "directives" / "inbox"; inbox.mkdir(parents=True)
    directive = inbox / "af08-signed.json"
    directive.write_text(json.dumps(payload, sort_keys=True), encoding="utf-8")
    _git(source, "add", "directives/inbox/af08-signed.json")
    _git(source, "commit", "-q", "-S", "-m", "signed AF08 fixture")
    _git(source, "push", "-q", "origin", "main")
    commit = _git(source, "rev-parse", "HEAD")
    blob = _git(source, "rev-parse", f"{commit}:directives/inbox/af08-signed.json")
    _, payload_hash, _ = compute_payload_bytes_and_hash(directive.read_bytes())
    fingerprint = subprocess.run([ssh_keygen, "-lf", str(key.with_suffix('.pub'))],
        check=True, capture_output=True, text=True).stdout.split()[1]
    monkeypatch.setattr(settings, "TRUSTED_SIGNER_ALLOWLIST", {fingerprint})
    monkeypatch.setattr(settings, "ACTIONS_REQUIRING_HUMAN_APPROVAL", settings.ACTIONS_REQUIRING_HUMAN_APPROVAL | {"GOVERNED_CANARY_WRITE"})
    record = {"directive_id":"af08-signed","directive_source_sha":commit,"directive_blob_sha":blob,
        "directive_payload_sha256":payload_hash,"accepted_at":now.isoformat(),"queue_state":"READY_FOR_FUTURE_EXECUTOR",
        "target_project":"ORACLE-AI","action_type":"GOVERNED_CANARY_WRITE","requires_human_approval":True,
        "executed":False,"execution_attempts":0,"readback_verified":True,
        "idempotency_key":hashlib.sha256(f"af08-signed:{commit}:{payload_hash}".encode()).hexdigest(),
        "signer_identity":fingerprint,"directive_payload":payload,"directive_source_path":"directives/inbox/af08-signed.json"}
    return source, now, record


def _worker_profile():
    private = Ed25519PrivateKey.generate()
    raw = private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    profile = TrustedWorkerProfile("af08-worker", "AF08_LOCAL_FIXTURE", "af08-key",
        base64.b64encode(raw).decode(), (CAPABILITY,), ("ORACLE-AI",), 1, 30.0)
    return private, profile


def _sign(private, domain, frame):
    value = dict(frame)
    value["signature"] = base64.b64encode(private.sign(signed_bytes(DOMAINS[domain], value))).decode()
    return value


class _CanaryBackend:
    provider_kind = "OPENAI_RESPONSES"
    model = "gpt-5.6-sol"
    def __init__(self, content): self.content=content; self.calls=0
    def configured(self): return True
    def probe(self): return ProviderCallResult("resp-probe", self.model, "connected")
    def execute(self, dispatch):
        self.calls += 1
        proposed = json.dumps({"content_b64":base64.b64encode(self.content).decode(),"content_sha256":sha256(self.content)}, sort_keys=True)
        payload = canonical_json({"output_text":proposed,"dispatch":asdict(dispatch)})
        return ProviderEvidence("evidence-plan", sha256(payload), payload, "resp-plan", self.model, self.model)


def test_phase3_signed_queue_af05_af06_runtime_product_path(tmp_path, monkeypatch):
    source, dt, record = _signed_source(tmp_path, monkeypatch)
    epoch = dt.timestamp(); queue = tmp_path/"queue.jsonl"
    queue.write_bytes(canonical_json(record)+b"\n")
    control = tmp_path/"control"; control.mkdir()
    project = tmp_path/"oracle-fixture"; project.mkdir(); _git(project,"init","-q"); _git(project,"config","user.name","Fixture"); _git(project,"config","user.email","fixture@example.invalid")
    (project/"README.md").write_text("fixture\n",encoding="utf-8"); _git(project,"add","README.md"); _git(project,"commit","-qm","base")
    base_sha=_git(project,"rev-parse","HEAD"); base_tree=_git(project,"rev-parse","HEAD^{tree}")
    private, profile = _worker_profile(); runtime_root=tmp_path/"runtime"; runtime_root.mkdir()
    auth=DirectiveAuthenticator(repo_root=source,reference_time=dt)
    def gateway_factory(store, root, roots):
        return ProviderBoundGateway(AuthenticatedExternalGateway(store,root,(profile,),repository_roots=roots,scoped_capabilities=frozenset({CAPABILITY})))
    runtime=AutonomyRuntime(runtime_root=runtime_root,queue_path=queue,repository_roots=(control,project,source),
        supported_targets=("ORACLE-AI",),verifier=auth.authenticate,gateway_factory=gateway_factory,clock=lambda:epoch)
    first=runtime.run_once(now=epoch); task_id=first["ingested"][0]
    assert runtime.store.task(task_id)["state"]=="WAITING_HUMAN"
    provenance=dict(runtime.store.db.execute("SELECT * FROM autonomy_provenance WHERE task_id=?",(task_id,)).fetchone())
    assert provenance["source_commit_sha"]==record["directive_source_sha"] and provenance["blob_sha"]==record["directive_blob_sha"]
    audit=ApprovalAuditChain(runtime_root/"approval.audit"); approvals=DurableApprovalEngine(runtime_root/"approvals.jsonl",audit)
    parameter_hash=sha256(b"af08-parameters"); request=approvals.create_request("af08-signed",CAPABILITY,parameter_hash,"ORACLE-AI","CRITICAL")
    approvals.transition_state(request["approval_request_id"],ApprovalState.NOTIFIED,"SYSTEM")
    approvals.transition_state(request["approval_request_id"],ApprovalState.APPROVED,"SYSTEM",approver_id="HUMAN_OPERATOR")
    registry=RealProjectCanaryRegistry(control_plane_root=control)
    registry.register_fixture(workspace_id="af08-authority",root=project,target_project="ORACLE-AI",project_identity="oracle-fixture",pinned_base_commit_sha=base_sha)
    killswitch=runtime_root/"killswitch.json"; killswitch.write_text(json.dumps({"killswitch_state":"ARMED","active_incident_id":None,"trigger_reason":None,"root_cause_resolved":False,"recovery_approved":False,"last_updated":epoch}),encoding="utf-8")
    safety=DurableMutationSafetyAuthority(killswitch_file=killswitch,incident_audit_file=runtime_root/"incident.audit")
    controller=ScopedCanaryController(runtime.store,runtime.gateway,registry,approval_engine=approvals,safety_authority=safety,
        preexecution_authority=ScopedPreExecutionAuthority(PreExecutionRevalidator(auth)),clock=lambda:epoch+2)
    with pytest.raises(RuntimeError):
        controller.consume_approval(engine=approvals,approval_request_id=request["approval_request_id"],task_id=task_id,directive_id="af08-signed",parameter_hash=parameter_hash,now=epoch,crash_after_consumption=lambda:(_ for _ in ()).throw(RuntimeError("crash")))
    assert runtime.store.db.execute("SELECT state FROM approval_consumption_receipts").fetchone()[0]=="PENDING"
    assert controller.approval_engine is approvals
    runtime.af08_reconciler=controller; released=runtime.run_once(now=epoch)
    assert released["approval_releases"]
    assert runtime.store.task(task_id)["state"]=="QUEUED"
    challenge=runtime.gateway.issue_challenge(profile.worker_id,profile.key_id,now=epoch)
    runtime.gateway.authenticate_session(_sign(private,"SESSION",challenge.transcript("af08-session",1)),now=epoch)
    heartbeat={"protocol_version":AF05_PROTOCOL_VERSION,"worker_id":profile.worker_id,"key_id":profile.key_id,"session_id":"af08-session","message_id":"hb-1","sequence":1,"observed_at":epoch+1,"capacity":1}
    runtime.gateway.heartbeat(_sign(private,"HEARTBEAT",heartbeat),now=epoch+1)
    backend=_CanaryBackend(b"AF08 governed canary\n")
    worker=OpenAIReadOnlyWorker(profile=profile,private_key=private,session_id="af08-session",client=backend)
    runtime.gateway.accept_provider_status(worker.provider_status_frame(observed_at=epoch+1,probe=True),now=epoch+1)
    routed=runtime.run_once(now=epoch+1)["routed"]; assert routed==[task_id]
    dispatch=runtime.gateway.dispatch_projection()[0]
    ack={"protocol_version":AF05_PROTOCOL_VERSION,"worker_id":profile.worker_id,"key_id":profile.key_id,"session_id":"af08-session","message_id":"ack-2","sequence":2,"observed_at":epoch+1,"dispatch_id":dispatch["dispatch_id"],"task_id":task_id,"lease_id":dispatch["lease_id"]}
    runtime.gateway.acknowledge(_sign(private,"ACK",ack),now=epoch+1)
    receipt=controller.receipt(runtime.store.db.execute("SELECT receipt_id FROM approval_consumption_receipts").fetchone()[0])
    content=backend.content
    authority={"protocol_version":AF08_PROTOCOL,"authorization_id":"af08-authority","directive_id":"af08-signed","task_id":task_id,"capability":CAPABILITY,"target_project":"ORACLE-AI","project_identity":"oracle-fixture","pinned_base_commit_sha":base_sha,"worktree_root":str(project.resolve()),"allowed_relative_path":CANARY_PATH,"allowed_operation":"CREATE","max_files":1,"max_bytes":4096,"expected_preimage_sha256":"ABSENT","expected_postimage_sha256":sha256(content),"approval_receipt_id":receipt["receipt_id"],"issued_at":epoch,"expires_at":epoch+20,"nonce":"af08-nonce","worker_id":profile.worker_id,"session_id":"af08-session","lease_id":dispatch["lease_id"],"dispatch_id":dispatch["dispatch_id"]}
    controller.bind_queued_directive(task_id,QueuedDirectiveItem(**record)); controller.provision_authority(canonical_json(authority),now=epoch+1)
    runtime.af08_processor=AF08ProductProcessor(controller,ProviderCanaryPlanner(backend))
    final=runtime.run_once(now=epoch+2); assert final["af08_processed"]==["af08-authority"]
    target=project/CANARY_PATH; assert target.read_bytes()==content and runtime.store.task(task_id)["state"]=="REVIEW_PENDING"
    receipt_id=receipt["receipt_id"]
    authority_digest=runtime.store.db.execute("SELECT digest FROM scoped_mutation_authorities WHERE authorization_id='af08-authority'").fetchone()[0]
    evidence_count=runtime.store.db.execute("SELECT count(*) FROM real_project_transactions WHERE evidence_sha256 IS NOT NULL").fetchone()[0]
    lease_id=runtime.store.task(task_id)["lease_id"]
    assert runtime.store.db.execute("SELECT state FROM scoped_mutation_authorities WHERE authorization_id='af08-authority'").fetchone()[0]=="CONSUMED"
    assert runtime.store.db.execute("SELECT state FROM real_project_transactions WHERE authorization_id='af08-authority'").fetchone()[0]=="APPLIED"
    assert backend.calls==1
    runtime.store.close(); del runtime,controller,registry,worker
    restarted=AutonomyRuntime(runtime_root=runtime_root,queue_path=queue,repository_roots=(control,project,source),supported_targets=("ORACLE-AI",),verifier=auth.authenticate,gateway_factory=gateway_factory,clock=lambda:epoch+3)
    approvals2=DurableApprovalEngine(runtime_root/"approvals.jsonl",ApprovalAuditChain(runtime_root/"approval.audit"))
    registry2=RealProjectCanaryRegistry(control_plane_root=control)
    config={"workspace_id":"af08-authority","root":str(project.resolve()),"target_project":"ORACLE-AI","project_identity":"oracle-fixture","pinned_base_commit_sha":base_sha}
    controller2=ScopedCanaryController(restarted.store,restarted.gateway,registry2,approval_engine=approvals2,
        recovery_workspaces=(config,),clock=lambda:epoch+3)
    restarted.af08_reconciler=controller2; restarted.af08_processor=AF08ProductProcessor(controller2,ProviderCanaryPlanner(backend))
    replay=restarted.run_once(now=epoch+3)
    assert replay["routed"]==[] and replay["af08_processed"]==[]
    assert restarted.store.task(task_id)["state"]=="REVIEW_PENDING" and restarted.store.task(task_id)["lease_id"]==lease_id
    assert approvals2.records[request["approval_request_id"]]["state"]=="CONSUMED"
    assert controller2.receipt(receipt_id)["state"]=="READY"
    recovered_authority=restarted.store.db.execute("SELECT state,digest FROM scoped_mutation_authorities WHERE authorization_id='af08-authority'").fetchone()
    assert (recovered_authority["state"],recovered_authority["digest"])==("CONSUMED",authority_digest)
    assert restarted.store.db.execute("SELECT state FROM real_project_transactions WHERE authorization_id='af08-authority'").fetchone()[0]=="APPLIED"
    assert restarted.store.db.execute("SELECT count(*) FROM real_project_transactions WHERE evidence_sha256 IS NOT NULL").fetchone()[0]==evidence_count
    assert backend.calls==1
    controller2.rollback("af08-authority")
    assert not target.exists() and _git(project,"rev-parse","HEAD")==base_sha and _git(project,"rev-parse","HEAD^{tree}")==base_tree and _git(project,"status","--porcelain")==""


def test_postwrite_precompletion_crash_recovers_exactly_once(tmp_path):
    env=environment(tmp_path); provision(env); target=env["project"]/CANARY_PATH
    with pytest.raises(SystemExit): apply(env,after_write=lambda:(_ for _ in ()).throw(SystemExit("crash")))
    assert target.exists() and env["store"].db.execute("SELECT state FROM real_project_transactions WHERE authorization_id='authority-1'").fetchone()[0]=="APPLYING"
    restarted=ScopedCanaryController(env["store"],env["gateway"],env["registry"])
    assert restarted.recover_applying("authority-1")=="FAILED" and not target.exists()


@pytest.mark.parametrize("field,value",[("root","wrong"),("project_identity","substituted"),("pinned_base_commit_sha","0"*40)])
def test_restart_workspace_binding_mismatch_integrity_blocks(tmp_path,field,value):
    env=environment(tmp_path); provision(env); apply(env); database=env["store"].path
    config={"workspace_id":"authority-1","root":str(env["project"].resolve()),"target_project":"ORACLE-AI",
            "project_identity":"oracle-fixture","pinned_base_commit_sha":env["base"]}
    if field=="root":
        other=tmp_path/"wrong";other.mkdir();config[field]=str(other.resolve())
    else: config[field]=value
    env["store"].close(); reopened=AutonomyStore(database)
    registry=RealProjectCanaryRegistry(control_plane_root=Path(__file__).resolve().parents[1])
    with pytest.raises(IntegrityBlockedError):
        ScopedCanaryController(reopened,GatewayTruth(),registry,recovery_workspaces=(config,))
    correct={"workspace_id":"authority-1","root":str(env["project"].resolve()),"target_project":"ORACLE-AI",
             "project_identity":"oracle-fixture","pinned_base_commit_sha":env["base"]}
    controller=ScopedCanaryController(reopened,GatewayTruth(),RealProjectCanaryRegistry(control_plane_root=Path(__file__).resolve().parents[1]),recovery_workspaces=(correct,))
    controller.rollback("authority-1")
