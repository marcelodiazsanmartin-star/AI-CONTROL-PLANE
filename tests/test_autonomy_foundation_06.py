"""AF-06 functional tests for a provider-bound read-only OpenAI adapter."""
import base64, hashlib, json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from src.autonomy import (AF05_PROTOCOL_VERSION, AgentRouter, AuthenticatedExternalGateway,
    AutonomyStore, BlockedError, OpenAIReadOnlyWorker, OpenAIResponsesClient,
    PROVIDER_ATTESTATION_SCOPE, PROVIDER_CONNECTED_UNATTESTED, PROVIDER_KIND,
    ProviderBoundGateway, TrustedWorkerProfile, signed_bytes)
from src.autonomy.external_gateway import DOMAINS


def keypair():
    private=Ed25519PrivateKey.generate(); raw=private.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw)
    return private,base64.b64encode(raw).decode()

def profile(public,**changes):
    values=dict(worker_id="provider-1",worker_kind="openai-adapter",key_id="key-1",public_key_base64=public,
        capabilities=("OBSERVE_STATUS",),allowed_targets=("PROJECT",),max_capacity=1,heartbeat_sla=10.0)
    values.update(changes);return TrustedWorkerProfile(**values)

def sign(private,domain,frame):
    value=dict(frame);value["signature"]=base64.b64encode(private.sign(signed_bytes(DOMAINS[domain],value))).decode();return value

def authenticate(gateway,private,p,*,now=100,session="provider-session",capacity=1):
    c=gateway.issue_challenge(p.worker_id,p.key_id,now=now);frame=sign(private,"SESSION",c.transcript(session,capacity));gateway.authenticate_session(frame,now=now)

def heartbeat(gateway,private,p,*,sequence=1,observed=101,session="provider-session"):
    frame={"protocol_version":AF05_PROTOCOL_VERSION,"worker_id":p.worker_id,"key_id":p.key_id,"session_id":session,
        "message_id":f"hb-{sequence}","sequence":sequence,"observed_at":observed,"capacity":1}
    gateway.heartbeat(sign(private,"HEARTBEAT",frame),now=observed)

def fake_response(text="READ_ONLY_PROVIDER_OK",rid="resp_test_1"):
    return json.dumps({"id":rid,"object":"response","status":"completed","model":"gpt-5.6-sol",
        "output":[{"type":"message","content":[{"type":"output_text","text":text}]}]}).encode()

def fake_client(*,key="test-key",payload=None):
    body=fake_response() if payload is None else payload
    def transport(req,timeout,max_bytes):
        assert req.full_url=="https://api.openai.com/v1/responses" and req.get_method()=="POST"
        parsed=json.loads(req.data.decode());assert parsed["store"] is False and parsed["tools"]==[] and parsed["reasoning"]=={"effort":"none"}
        return body
    return OpenAIResponsesClient(api_key_provider=lambda:key,transport=transport)

def environment(tmp_path):
    private,public=keypair();p=profile(public);root=tmp_path/"runtime";root.mkdir()
    repos=[]
    for name in ("control","oracle","micro"):
        path=tmp_path/name;path.mkdir();repos.append(path)
    store=AutonomyStore(root/"autonomy.sqlite");base=AuthenticatedExternalGateway(store,root,(p,),repository_roots=repos);gateway=ProviderBoundGateway(base)
    authenticate(gateway,private,p);heartbeat(gateway,private,p)
    return store,gateway,private,p,root,repos

def connected(tmp_path):
    store,gateway,private,p,root,repos=environment(tmp_path);worker=OpenAIReadOnlyWorker(profile=p,private_key=private,session_id="provider-session",client=fake_client())
    gateway.accept_provider_status(worker.provider_status_frame(observed_at=101,probe=True),now=101)
    return store,gateway,private,p,worker,root,repos

def routed(tmp_path):
    store,gateway,private,p,worker,root,repos=connected(tmp_path)
    store.create_task(task_id="task-1",directive_id="directive-1",target_project="PROJECT",capability="OBSERVE_STATUS",governance_allowed=True,retry_budget=1,now=100)
    envelope=AgentRouter(store,gateway).route_once(now=101)[0]
    return store,gateway,private,p,worker,root,repos,envelope


def test_f01_missing_credential_is_not_connected_and_not_eligible(tmp_path):
    store,gateway,private,p,_,_=environment(tmp_path);worker=OpenAIReadOnlyWorker(profile=p,private_key=private,session_id="provider-session",client=fake_client(key=None))
    gateway.accept_provider_status(worker.provider_status_frame(observed_at=101,probe=True),now=101)
    assert gateway.eligible_sessions(capability="OBSERVE_STATUS",target_project="PROJECT",now=101)==[]
    assert gateway.session_projection(now=101)[0]["provider_connection_status"]=="NOT_CONNECTED"

def test_f02_revoked_af05_adapter_never_becomes_provider_worker(tmp_path):
    _,gateway,private,p,_,_=environment(tmp_path);gateway.revoke(p.worker_id);worker=OpenAIReadOnlyWorker(profile=p,private_key=private,session_id="provider-session",client=fake_client())
    with pytest.raises(BlockedError):gateway.accept_provider_status(worker.provider_status_frame(observed_at=101,probe=True),now=101)

def test_f03_provider_failure_does_not_fabricate_availability(tmp_path):
    _,gateway,private,p,_,_=environment(tmp_path);client=OpenAIResponsesClient(api_key_provider=lambda:"x",transport=lambda *args:(_ for _ in ()).throw(BlockedError("down")));worker=OpenAIReadOnlyWorker(profile=p,private_key=private,session_id="provider-session",client=client)
    gateway.accept_provider_status(worker.provider_status_frame(observed_at=101,probe=True),now=101);assert gateway.eligible_sessions(capability="OBSERVE_STATUS",target_project="PROJECT",now=101)==[]

def test_f04_provider_truth_is_explicitly_unattested(tmp_path):
    _,gateway,_,_,_,_,_=connected(tmp_path);item=gateway.session_projection(now=101)[0]
    assert item["provider_connection_status"]==PROVIDER_CONNECTED_UNATTESTED and item["provider_attestation_scope"]==PROVIDER_ATTESTATION_SCOPE and "VERIFIED_PROVIDER" not in str(item)

def test_f05_unsupported_mutating_capability_blocks_before_provider(tmp_path):
    _,_,_,_,worker,_,_=connected(tmp_path)
    from src.autonomy.protocol import DispatchEnvelope
    envelope=DispatchEnvelope("d","t",worker.profile.worker_id,worker.session_id,"l",200,"WRITE_FILE","PROJECT",AF05_PROTOCOL_VERSION)
    with pytest.raises(BlockedError):worker.ack_frame(envelope,sequence=2,observed_at=102)

def test_f06_allowed_read_only_task_gets_one_canonical_lease(tmp_path):
    store,_,_,_,_,_,_,e=routed(tmp_path);assert store.task(e.task_id)["state"]=="LEASED" and e.worker_id=="provider-1"

def test_f07_ack_result_bind_exact_session_task_lease(tmp_path):
    store,gateway,_,_,worker,_,_,e=routed(tmp_path);gateway.acknowledge(worker.ack_frame(e,sequence=2,observed_at=102),now=102);assert store.task(e.task_id)["state"]=="RUNNING"
    sink=lambda eid,data:gateway.transport.evidence_path(eid).write_bytes(data)
    gateway.result(worker.execute_result_frame(e,sequence=3,observed_at=103,evidence_sink=sink),now=103);assert store.task(e.task_id)["state"]=="REVIEW_PENDING"

def test_f08_provider_timeout_reconciles_by_canonical_lease_expiry(tmp_path):
    store,gateway,_,_,worker,_,_,e=routed(tmp_path);gateway.acknowledge(worker.ack_frame(e,sequence=2,observed_at=102),now=102);assert store.task(e.task_id)["state"]=="RUNNING"
    store.reclaim_expired(e.task_id,now=e.lease_expires_at+1);assert store.task(e.task_id)["state"]=="RETRYING"

def test_f09_stale_provider_probe_is_ineligible(tmp_path):
    _,gateway,_,_,_,_,_=connected(tmp_path);assert gateway.eligible_sessions(capability="OBSERVE_STATUS",target_project="PROJECT",now=112)==[]

def test_f10_result_after_lease_expiry_is_rejected(tmp_path):
    _,gateway,_,_,worker,_,_,e=routed(tmp_path)
    with pytest.raises(BlockedError):gateway.acknowledge(worker.ack_frame(e,sequence=2,observed_at=200),now=200)

def test_f11_result_without_independent_evidence_is_rejected(tmp_path):
    _,gateway,_,_,worker,_,_,e=routed(tmp_path);gateway.acknowledge(worker.ack_frame(e,sequence=2,observed_at=102),now=102)
    frame=worker.execute_result_frame(e,sequence=3,observed_at=103,evidence_sink=lambda eid,data:None)
    with pytest.raises(BlockedError):gateway.result(frame,now=103)

def test_f12_duplicate_provider_status_is_replay_blocked(tmp_path):
    _,gateway,private,p,_,_=environment(tmp_path);worker=OpenAIReadOnlyWorker(profile=p,private_key=private,session_id="provider-session",client=fake_client());frame=worker.provider_status_frame(observed_at=101,probe=True);gateway.accept_provider_status(frame,now=101)
    with pytest.raises(BlockedError):gateway.accept_provider_status(frame,now=101)

def test_f13_provider_output_schema_and_size_are_bounded():
    with pytest.raises(BlockedError):fake_client(payload=b"not-json").probe()
    c=OpenAIResponsesClient(api_key_provider=lambda:"x",transport=lambda req,t,m:b"x"*(m+1))
    with pytest.raises(BlockedError):c.probe()

def test_f14_secret_shaped_output_is_redacted():
    c=fake_client(payload=fake_response("Bearer abcdefghijklmnop sk-SECRETSECRET token=topsecret"));from src.autonomy.protocol import DispatchEnvelope
    e=DispatchEnvelope("d","t","provider-1","provider-session","l",200,"OBSERVE_STATUS","PROJECT",AF05_PROTOCOL_VERSION);body=json.loads(c.execute(e).payload)
    assert "SECRETSECRET" not in body["output_text"] and "topsecret" not in body["output_text"]

def test_f15_restart_does_not_resurrect_provider_eligibility(tmp_path):
    store,gateway,_,p,_,root,repos=connected(tmp_path);base2=AuthenticatedExternalGateway(store,root,(p,),repository_roots=repos);g2=ProviderBoundGateway(base2)
    assert g2.eligible_sessions(capability="OBSERVE_STATUS",target_project="PROJECT",now=101)==[] and g2.session_projection(now=101)[0]["provider_execution_eligible"] is False

def test_f16_provider_adapter_exposes_no_repo_or_process_mutator():
    import inspect,src.autonomy.provider as module
    text=inspect.getsource(module);assert "subprocess" not in text and "git push" not in text and "os.system" not in text

def test_f17_projection_separates_adapter_auth_from_provider_truth(tmp_path):
    _,gateway,_,_,_,_,_=connected(tmp_path);p=gateway.session_projection(now=101)[0]
    assert p["verification_scope"]=="AUTHENTICATED_EXTERNAL_ADAPTER" and p["provider_connection_status"]==PROVIDER_CONNECTED_UNATTESTED and p["provider_execution_eligible"] is True

def test_f18_client_does_not_store_api_key():
    c=fake_client();assert "test-key" not in str(c.__dict__)

def test_f19_provider_evidence_is_bound_to_dispatch_and_response():
    from src.autonomy.protocol import DispatchEnvelope
    c=fake_client(payload=fake_response("result","resp_bound_1"));a=DispatchEnvelope("d1","t","provider-1","s","l1",200,"OBSERVE_STATUS","PROJECT",AF05_PROTOCOL_VERSION);b=DispatchEnvelope("d1","t","provider-1","s","l2",200,"OBSERVE_STATUS","PROJECT",AF05_PROTOCOL_VERSION)
    x=c.execute(a);y=c.execute(b);assert x.sha256!=y.sha256 and x.evidence_id!=y.evidence_id

def test_f20_mutation_flags_remain_false():
    from src.autonomy.protocol import REAL_PROJECT_MUTATION_ENABLED
    from config import settings
    assert REAL_PROJECT_MUTATION_ENABLED is False and settings.CONTROL_PLANE_EXECUTE_MUTATING_DIRECTIVES is False


def test_provider_reported_model_mismatch_fails_closed():
    payload = json.dumps({
        "id": "resp_wrong_model", "object": "response", "status": "completed",
        "model": "gpt-5.6-terra",
        "output": [{"type": "message", "content": [{"type": "output_text", "text": "OK"}]}],
    }).encode()
    with pytest.raises(BlockedError, match="model mismatch"):
        fake_client(payload=payload).probe()


def test_provider_transport_must_return_bytes():
    client = OpenAIResponsesClient(
        api_key_provider=lambda: "x",
        transport=lambda request, timeout, maximum: "not-bytes",
    )
    with pytest.raises(BlockedError, match="must be bytes"):
        client.probe()


def test_future_provider_status_never_projects_available(tmp_path):
    store, gateway, private, p, _, _ = environment(tmp_path)
    worker = OpenAIReadOnlyWorker(
        profile=p, private_key=private, session_id="provider-session", client=fake_client()
    )
    frame = worker.provider_status_frame(observed_at=102.0, probe=True)
    gateway.accept_provider_status(frame, now=101.0)
    assert gateway.eligible_sessions(
        capability="OBSERVE_STATUS", target_project="PROJECT", now=100.0
    ) == []
    projection = gateway.session_projection(now=100.0)[0]
    assert projection["provider_connection_status"] == "STALE"
    assert projection["provider_execution_eligible"] is False


def test_duplicate_signed_result_is_replay_blocked(tmp_path):
    store, gateway, _, _, worker, _, _, envelope = routed(tmp_path)
    gateway.acknowledge(worker.ack_frame(envelope, sequence=2, observed_at=102), now=102)
    sink = lambda evidence_id, data: gateway.transport.evidence_path(evidence_id).write_bytes(data)
    frame = worker.execute_result_frame(
        envelope, sequence=3, observed_at=103, evidence_sink=sink
    )
    gateway.result(frame, now=103)
    assert store.task(envelope.task_id)["state"] == "REVIEW_PENDING"
    with pytest.raises(BlockedError):
        gateway.result(frame, now=103)
    assert store.task(envelope.task_id)["state"] == "REVIEW_PENDING"
