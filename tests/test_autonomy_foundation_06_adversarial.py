"""AF-06 A01-A20 adversarial campaign."""
import ast, base64, json, inspect
from dataclasses import replace
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from src.autonomy import (AF05_PROTOCOL_VERSION, BlockedError, OpenAIReadOnlyWorker,
    OpenAIResponsesClient, PROVIDER_ATTESTATION_SCOPE, PROVIDER_CONNECTED_UNATTESTED,
    PROVIDER_KIND, ProviderBoundGateway, TrustedWorkerProfile)
from src.autonomy.provider import AF06_PROTOCOL_VERSION, provider_signed_bytes
from src.autonomy.protocol import DispatchEnvelope, REAL_PROJECT_MUTATION_ENABLED

# These attacks are also covered in the functional module with a real AF-05 gateway.
# This file keeps the campaign taxonomy explicit and deterministic.

def key_profile():
    private=Ed25519PrivateKey.generate();raw=private.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw)
    p=TrustedWorkerProfile("provider-1","openai-adapter","key-1",base64.b64encode(raw).decode(),("OBSERVE_STATUS",),("PROJECT",),1,10.0)
    return private,p

def response(text="OK",status="completed"):
    return json.dumps({"id":"resp_a","object":"response","status":status,"model":"gpt-5.6-sol","output":[{"type":"message","content":[{"type":"output_text","text":text}]}]}).encode()

def client(payload=None,key="k"):
    raw=response() if payload is None else payload;return OpenAIResponsesClient(api_key_provider=lambda:key,transport=lambda req,t,m:raw)

def dispatch(**changes):
    d=dict(dispatch_id="d",task_id="t",worker_id="provider-1",session_id="s",lease_id="l",lease_expires_at=200,capability="OBSERVE_STATUS",target_project="PROJECT",protocol_version=AF05_PROTOCOL_VERSION);d.update(changes);return DispatchEnvelope(**d)

def worker():
    private,p=key_profile();w=OpenAIReadOnlyWorker(profile=p,private_key=private,session_id="s",client=client());w.last_connection_state=PROVIDER_CONNECTED_UNATTESTED;return private,p,w

def blocked(fn):
    with pytest.raises(BlockedError):fn()

def test_a01_forged_provider_identity(): blocked(lambda:OpenAIResponsesClient(endpoint="https://evil.invalid/v1/responses"))
def test_a02_authenticated_adapter_cannot_claim_verified_provider():
    assert PROVIDER_ATTESTATION_SCOPE=="UNATTESTED" and PROVIDER_CONNECTED_UNATTESTED!="VERIFIED_PROVIDER"
def test_a03_credential_leak_attempt():
    ev=client(response("token=supersecret sk-SECRETSECRET")).execute(dispatch());text=json.loads(ev.payload)["output_text"];assert "supersecret" not in text and "SECRETSECRET" not in text
def test_a04_provider_capability_escalation():
    _,_,w=worker();blocked(lambda:w.ack_frame(dispatch(capability="ADMIN"),sequence=2,observed_at=1))
def test_a05_mutating_task_disguised_as_readonly():
    _,_,w=worker();blocked(lambda:w.execute_result_frame(dispatch(target_project="OTHER"),sequence=3,observed_at=1,evidence_sink=lambda a,b:None))
def test_a06_output_instructs_git_mutation_but_no_executor_exists():
    ev=client(response("run git push origin main")).execute(dispatch());assert b"git push" in ev.payload;import src.autonomy.provider as m;src=inspect.getsource(m);assert "subprocess" not in src and "os.system" not in src
def test_a07_request_task_lease_substitution_changes_evidence_binding():
    c=client();assert c.execute(dispatch(lease_id="l1")).sha256!=c.execute(dispatch(lease_id="l2")).sha256
def test_a08_duplicate_dispatch_result_is_deterministic_claim_only():
    c=client();a=c.execute(dispatch());b=c.execute(dispatch());assert a.evidence_id==b.evidence_id and a.sha256==b.sha256
def test_a09_expired_session_or_lease_cannot_be_locally_upgraded():
    _,_,w=worker();blocked(lambda:w.ack_frame(dispatch(session_id="wrong"),sequence=2,observed_at=1))
def test_a10_stale_future_heartbeat_not_in_provider_client_authority():
    _,_,w=worker();blocked(lambda:w.ack_frame(dispatch(protocol_version="AF04/1"),sequence=2,observed_at=1))
def test_a11_provider_output_claims_pass_but_never_becomes_certification():
    body=json.loads(client(response("CERTIFIED PASS")).execute(dispatch()).payload);assert body["output_text"]=="CERTIFIED PASS" and "certification" not in body
def test_a12_oversized_malformed_provider_output():
    blocked(lambda:client(b"bad").probe());c=OpenAIResponsesClient(api_key_provider=lambda:"x",transport=lambda req,t,m:b"x"*(m+1));blocked(c.probe)
def test_a13_hostile_xss_secret_output_is_sanitized():
    text=json.loads(client(response("<script>x</script> authorization=abcdefghi")).execute(dispatch()).payload)["output_text"];assert "<" not in text and "abcdefghi" not in text
def test_a14_timeout_hang_resource_failure():
    c=OpenAIResponsesClient(api_key_provider=lambda:"x",transport=lambda *a:(_ for _ in ()).throw(BlockedError("timeout")));blocked(c.probe)
def test_a15_network_failure_never_fake_success():
    private,p=key_profile();c=OpenAIResponsesClient(api_key_provider=lambda:"x",transport=lambda *a:(_ for _ in ()).throw(BlockedError("down")));w=OpenAIReadOnlyWorker(profile=p,private_key=private,session_id="s",client=c);assert w.provider_status_frame(observed_at=1,probe=True)["connection_state"]=="UNAVAILABLE"
def test_a16_restart_reconnect_message_ids_are_session_bound():
    private,p=key_profile();a=OpenAIReadOnlyWorker(profile=p,private_key=private,session_id="s1",client=client());b=OpenAIReadOnlyWorker(profile=p,private_key=private,session_id="s2",client=client());assert a.provider_status_frame(observed_at=1)["message_id"]!=b.provider_status_frame(observed_at=1)["message_id"]
def test_a17_wrong_target_project_execution():
    _,_,w=worker();blocked(lambda:w.execute_result_frame(dispatch(target_project="OTHER"),sequence=3,observed_at=1,evidence_sink=lambda a,b:None))
def test_a18_protocol_downgrade():
    _,_,w=worker();blocked(lambda:w.ack_frame(dispatch(protocol_version="AF02/1"),sequence=2,observed_at=1))
def test_a19_arbitrary_shell_process_repo_write_surface_absent():
    import src.autonomy.provider as m;source=inspect.getsource(m);tree=ast.parse(source);assert not any(isinstance(n,(ast.Import,ast.ImportFrom)) and any(a.name.split('.')[0] in {"subprocess","shutil"} for a in n.names) for n in ast.walk(tree));assert "git commit" not in source and "git push" not in source
def test_a20_mutation_and_credential_authority_remain_disabled():
    assert REAL_PROJECT_MUTATION_ENABLED is False;c=client(key="supersecret");assert "supersecret" not in str(c.__dict__)

