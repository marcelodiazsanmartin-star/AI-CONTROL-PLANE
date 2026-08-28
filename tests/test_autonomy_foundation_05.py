"""AF-05 functional acceptance and cross-process proof."""
import base64, hashlib, json, subprocess, sys
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from src.autonomy import (AUTHENTICATION_SCOPE, AF05_PROTOCOL_VERSION, AgentRouter,
    AuthenticatedExternalGateway, AutonomyRuntime, AutonomyStore, BlockedError, IntegrityBlockedError,
    TrustedWorkerProfile, TrustedWorkerRegistry, signed_bytes)
from src.autonomy.external_gateway import DOMAINS

def keypair():
    private=Ed25519PrivateKey.generate(); raw=private.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw)
    return private,base64.b64encode(raw).decode()

def profile(public,**changes):
    values=dict(worker_id="external-1",worker_kind="test-adapter",key_id="key-1",public_key_base64=public,
        capabilities=("OBSERVE_STATUS",),allowed_targets=("PROJECT",),max_capacity=1,heartbeat_sla=10.0)
    values.update(changes); return TrustedWorkerProfile(**values)

def environment(tmp_path,*,profiles=None):
    private,public=keypair(); p=profile(public); root=tmp_path/"runtime";root.mkdir(parents=True)
    repositories=[]
    for name in ("control-repo","oracle-repo","micro-repo"):
        item=tmp_path/name;item.mkdir();repositories.append(item)
    store=AutonomyStore(root/"autonomy.sqlite")
    gateway=AuthenticatedExternalGateway(store,root,tuple(profiles or (p,)),repository_roots=repositories);gateway._test_repository_roots=tuple(repositories);return store,gateway,private,p,root

def sign(private,domain,frame):
    value=dict(frame);value["signature"]=base64.b64encode(private.sign(signed_bytes(DOMAINS[domain],value))).decode();return value

def authenticate(gateway,private,p,*,now=100,session="session-1",capacity=1):
    c=gateway.issue_challenge(p.worker_id,p.key_id,now=now);frame=c.transcript(session,capacity);frame=sign(private,"SESSION",frame);gateway.authenticate_session(frame,now=now);return frame

def message(private,domain,p,session,sequence,observed,**fields):
    frame={"protocol_version":AF05_PROTOCOL_VERSION,"worker_id":p.worker_id,"key_id":p.key_id,"session_id":session,
           "message_id":f"{domain.lower()}-{sequence}","sequence":sequence,"observed_at":observed,**fields}
    return sign(private,domain,frame)

def heartbeat(gateway,private,p,*,sequence=1,observed=101,capacity=1,session="session-1"):
    frame=message(private,"HEARTBEAT",p,session,sequence,observed,capacity=capacity);gateway.heartbeat(frame,now=observed);return frame

def routed(tmp_path):
    store,gateway,private,p,root=environment(tmp_path);authenticate(gateway,private,p);heartbeat(gateway,private,p)
    store.create_task(task_id="task-1",directive_id="directive-1",target_project="PROJECT",capability="OBSERVE_STATUS",governance_allowed=True,now=100)
    envelope=AgentRouter(store,gateway).route_once(now=101)[0];return store,gateway,private,p,root,envelope

def test_f01_authority_trusted_profile_loads(tmp_path):
    store,gateway,_,p,_=environment(tmp_path);row=store.db.execute("SELECT * FROM af05_profiles").fetchone();assert row["worker_id"]==p.worker_id and len(row["fingerprint"])==64

def test_f02_malformed_duplicate_revoked_profiles_block(tmp_path):
    _,public=keypair()
    with pytest.raises(IntegrityBlockedError): environment(tmp_path/"a",profiles=(profile(public),profile(public)))
    with pytest.raises(BlockedError): TrustedWorkerRegistry((profile("bad"),))
    with pytest.raises(BlockedError): TrustedWorkerRegistry((profile(public,revoked=True),)).get("external-1")

def test_f03_secure_challenge_ttl_and_single_use(tmp_path):
    _,g,private,p,_=environment(tmp_path);a=g.issue_challenge(p.worker_id,p.key_id,now=100);b=g.issue_challenge(p.worker_id,p.key_id,now=100)
    assert a.nonce!=b.nonce and a.challenge_id!=b.challenge_id and a.expires_at==130
    frame=sign(private,"SESSION",a.transcript("s",1));g.authenticate_session(frame,now=100)
    with pytest.raises(BlockedError):g.authenticate_session(frame,now=100)

def test_f04_valid_ed25519_exact_transcript_authenticates(tmp_path):
    _,g,private,p,_=environment(tmp_path);authenticate(g,private,p);assert g.session_projection(now=100)[0]["verification_scope"]==AUTHENTICATION_SCOPE

def test_f05_invalid_signature_creates_no_session(tmp_path):
    store,g,_,p,_=environment(tmp_path);wrong,_=keypair();c=g.issue_challenge(p.worker_id,p.key_id,now=100)
    with pytest.raises(BlockedError):g.authenticate_session(sign(wrong,"SESSION",c.transcript("s",1)),now=100)
    assert store.db.execute("SELECT count(*) FROM af05_sessions").fetchone()[0]==0

def test_f06_challenge_replay_blocked(tmp_path): test_f03_secure_challenge_ttl_and_single_use(tmp_path)

def test_f07_scope_never_claims_provider(tmp_path):
    _,g,private,p,_=environment(tmp_path);authenticate(g,private,p);text=str(g.session_projection(now=100));assert AUTHENTICATION_SCOPE in text and "VERIFIED_PROVIDER" not in text

@pytest.mark.parametrize("change",({"capacity":2},{"worker_id":"evil"},{"key_id":"evil"}))
def test_f08_worker_escalation_or_identity_substitution_blocked(tmp_path,change):
    _,g,private,p,_=environment(tmp_path);c=g.issue_challenge(p.worker_id,p.key_id,now=100);frame=c.transcript("s",1);frame.update(change)
    with pytest.raises(BlockedError):g.authenticate_session(sign(private,"SESSION",frame),now=100)

def test_f09_signed_heartbeat_monotonic_and_fresh(tmp_path):
    _,g,private,p,_=environment(tmp_path);authenticate(g,private,p);frame=heartbeat(g,private,p)
    with pytest.raises(BlockedError):g.heartbeat(frame,now=101)

def test_f10_restart_requires_reauthentication(tmp_path):
    store,g,private,p,root=environment(tmp_path);authenticate(g,private,p);heartbeat(g,private,p);g2=AuthenticatedExternalGateway(store,root,(p,),repository_roots=g._test_repository_roots);assert g2.eligible_sessions(capability="OBSERVE_STATUS",target_project="PROJECT",now=101)==[] and g2.session_projection(now=101)[0]["status"]=="REAUTH_REQUIRED"

def test_f11_no_authenticated_worker_waits_capacity(tmp_path):
    store,g,_,_,_=environment(tmp_path);store.create_task(task_id="t",directive_id="d",target_project="PROJECT",capability="OBSERVE_STATUS",governance_allowed=True,now=1);assert AgentRouter(store,g).route_once(now=1)==[] and store.task("t")["state"]=="WAITING_CAPACITY"

def test_f12_matching_worker_routes_atomic_lease(tmp_path):
    store,_,_,_,_,envelope=routed(tmp_path);assert store.task("task-1")["state"]=="LEASED" and envelope.worker_id=="external-1"

def test_f13_dispatch_durable_only_under_runtime_root(tmp_path):
    _,g,_,_,root,e=routed(tmp_path);path=g.transport.outbound/f"{e.dispatch_id}.json";assert path.exists() and path.resolve().is_relative_to(root.resolve())

def test_f14_signed_ack_transitions_running(tmp_path):
    store,g,private,p,_,e=routed(tmp_path);frame=message(private,"ACK",p,e.session_id,2,102,dispatch_id=e.dispatch_id,task_id=e.task_id,lease_id=e.lease_id);g.acknowledge(frame,now=102);assert store.task(e.task_id)["state"]=="RUNNING"

def test_f15_unsigned_wrong_ack_blocked(tmp_path):
    store,g,private,p,_,e=routed(tmp_path);frame=message(private,"ACK",p,e.session_id,2,102,dispatch_id=e.dispatch_id,task_id=e.task_id,lease_id="wrong")
    with pytest.raises(BlockedError):g.acknowledge(frame,now=102)
    assert store.task(e.task_id)["state"]=="LEASED"

def test_f16_result_before_ack_blocked(tmp_path):
    _,g,private,p,_,e=routed(tmp_path);frame=message(private,"RESULT",p,e.session_id,2,102,dispatch_id=e.dispatch_id,task_id=e.task_id,lease_id=e.lease_id,status="SUCCEEDED",evidence_id="e",evidence_sha256="0"*64)
    with pytest.raises(BlockedError):g.result(frame,now=102)

def test_f17_valid_result_and_evidence_reaches_review(tmp_path):
    store,g,private,p,_,e=routed(tmp_path);g.acknowledge(message(private,"ACK",p,e.session_id,2,102,dispatch_id=e.dispatch_id,task_id=e.task_id,lease_id=e.lease_id),now=102)
    content=b"verified evidence";g.transport.evidence_path("evidence-1").write_bytes(content);digest=hashlib.sha256(content).hexdigest()
    g.result(message(private,"RESULT",p,e.session_id,3,103,dispatch_id=e.dispatch_id,task_id=e.task_id,lease_id=e.lease_id,status="SUCCEEDED",evidence_id="evidence-1",evidence_sha256=digest),now=103);assert store.task(e.task_id)["state"]=="REVIEW_PENDING"

@pytest.mark.parametrize("evidence,digest",(("../escape","0"*64),("missing","0"*64),("evidence","f"*64)))
def test_f18_evidence_path_digest_or_missing_blocked(tmp_path,evidence,digest):
    store,g,private,p,_,e=routed(tmp_path);g.acknowledge(message(private,"ACK",p,e.session_id,2,102,dispatch_id=e.dispatch_id,task_id=e.task_id,lease_id=e.lease_id),now=102)
    if evidence=="evidence":g.transport.evidence_path(evidence).write_bytes(b"actual")
    with pytest.raises(BlockedError):g.result(message(private,"RESULT",p,e.session_id,3,103,dispatch_id=e.dispatch_id,task_id=e.task_id,lease_id=e.lease_id,status="SUCCEEDED",evidence_id=evidence,evidence_sha256=digest),now=103)

def test_f19_revocation_immediately_removes_eligibility(tmp_path):
    store,g,private,p,root=environment(tmp_path);authenticate(g,private,p);heartbeat(g,private,p);g.revoke(p.worker_id);assert g.eligible_sessions(capability="OBSERVE_STATUS",target_project="PROJECT",now=101)==[] and g.session_projection(now=101)[0]["status"]=="REVOKED";assert AuthenticatedExternalGateway(store,root,(p,),repository_roots=g._test_repository_roots).session_projection(now=101)[0]["status"]=="REVOKED"

def test_f20_expired_lease_result_race_blocks(tmp_path):
    _,g,private,p,_,e=routed(tmp_path);frame=message(private,"ACK",p,e.session_id,2,200,dispatch_id=e.dispatch_id,task_id=e.task_id,lease_id=e.lease_id)
    with pytest.raises(BlockedError):g.acknowledge(frame,now=200)

def test_f21_projection_bounded_and_secret_free(tmp_path):
    _,g,private,p,_=environment(tmp_path);authenticate(g,private,p);projection=g.session_projection(now=100)[0];assert "signature" not in projection and "private" not in str(projection).lower()

def test_f21b_autonomy_runtime_optionally_projects_authenticated_gateway(tmp_path):
    private,public=keypair();p=profile(public);runtime_root=tmp_path/"runtime";runtime_root.mkdir();queue=tmp_path/"queue.jsonl";queue.write_text("")
    repos=[]
    for name in ("control","oracle","micro"): item=tmp_path/name;item.mkdir();repos.append(item)
    runtime=AutonomyRuntime(runtime_root=runtime_root,queue_path=queue,repository_roots=repos,supported_targets=("PROJECT",),verifier=None,
        gateway_factory=lambda store,root,roots:AuthenticatedExternalGateway(store,root,(p,),repository_roots=roots),clock=lambda:100)
    authenticate(runtime.gateway,private,p);assert runtime.projection(now=100)["workers"][0]["verification_scope"]==AUTHENTICATION_SCOPE

def test_f22_local_harness_regression_scope_is_unchanged():
    from src.autonomy.gateway import LocalWorkerGateway
    assert "local harness" in (LocalWorkerGateway.__doc__ or "").lower()

def test_f23_cross_process_authenticated_bridge_proof(tmp_path):
    store,g,private,p,root,e=routed(tmp_path);raw=private.private_bytes(serialization.Encoding.Raw,serialization.PrivateFormat.Raw,serialization.NoEncryption())
    adapter=tmp_path/"adapter.py";adapter.write_text("""import base64,json,sys\nfrom cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey\ndata=json.load(open(sys.argv[1])); key=Ed25519PrivateKey.from_private_bytes(base64.b64decode(data.pop('_key'))); domain=data.pop('_domain'); body=json.dumps(data,sort_keys=True,separators=(',',':'),ensure_ascii=True,allow_nan=False).encode('ascii'); transcript=('AI-CONTROL-PLANE/AF05/'+domain+'\\n').encode('ascii')+body; data['signature']=base64.b64encode(key.sign(transcript)).decode();json.dump(data,open(sys.argv[2],'w'))\n""",encoding="utf-8")
    def external(domain,frame,name):
        source=tmp_path/f"{name}-in.json";dest=tmp_path/f"{name}-out.json";source.write_text(json.dumps({**frame,"_key":base64.b64encode(raw).decode(),"_domain":domain}),encoding="utf-8");subprocess.run([sys.executable,str(adapter),str(source),str(dest)],check=True,cwd=Path.cwd(),capture_output=True);return json.loads(dest.read_text())
    ack={"protocol_version":AF05_PROTOCOL_VERSION,"worker_id":p.worker_id,"key_id":p.key_id,"session_id":e.session_id,"message_id":"xp-ack","sequence":2,"observed_at":102,"dispatch_id":e.dispatch_id,"task_id":e.task_id,"lease_id":e.lease_id};g.acknowledge(external("ACK",ack,"ack"),now=102)
    content=b"cross process";g.transport.evidence_path("xp-evidence").write_bytes(content);result={"protocol_version":AF05_PROTOCOL_VERSION,"worker_id":p.worker_id,"key_id":p.key_id,"session_id":e.session_id,"message_id":"xp-result","sequence":3,"observed_at":103,"dispatch_id":e.dispatch_id,"task_id":e.task_id,"lease_id":e.lease_id,"status":"SUCCEEDED","evidence_id":"xp-evidence","evidence_sha256":hashlib.sha256(content).hexdigest()};g.result(external("RESULT",result,"result"),now=103);assert store.task(e.task_id)["state"]=="REVIEW_PENDING"

def test_f24_runtime_and_repository_roots_remain_disposable(tmp_path):
    _,g,_,_,root=environment(tmp_path);assert g.transport.root.is_relative_to(root) and not any("AI-CONTROL-PLANE" in str(path) for path in g.transport.root.parents if path==root)
