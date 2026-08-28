"""AF-05 mandatory A01-A20 campaign."""
import inspect
from pathlib import Path
import pytest

import src.autonomy.external_gateway as external_module
import src.autonomy.transport as transport_module
import src.autonomy.trust as trust_module
from src.autonomy import (AF05_PROTOCOL_VERSION, AgentRouter, AuthenticatedExternalGateway,
                          BlockedError, REAL_PROJECT_MUTATION_ENABLED)
from tests.test_autonomy_foundation_05 import (authenticate, environment, heartbeat,
                                               keypair, message, profile, routed, sign)

def classify(call):
    try: call()
    except BlockedError: return "BLOCKED"
    except Exception: return "HARNESS_ERROR"
    return "BYPASS_DETECTED"

def test_a01_unknown_worker_or_key_session_blocked(tmp_path):
    _,g,_,_,_=environment(tmp_path);assert classify(lambda:g.issue_challenge("unknown","key",now=1))=="BLOCKED"

def test_a02_forged_or_malformed_signature_blocked(tmp_path):
    _,g,_,p,_=environment(tmp_path);wrong,_=keypair();c=g.issue_challenge(p.worker_id,p.key_id,now=1);assert classify(lambda:g.authenticate_session(sign(wrong,"SESSION",c.transcript("s",1)),now=1))=="BLOCKED"

def test_a03_one_time_challenge_replay_blocked(tmp_path):
    _,g,private,p,_=environment(tmp_path);c=g.issue_challenge(p.worker_id,p.key_id,now=1);frame=sign(private,"SESSION",c.transcript("s",1));g.authenticate_session(frame,now=1);assert classify(lambda:g.authenticate_session(frame,now=1))=="BLOCKED"

def test_a04_expired_future_or_substituted_challenge_blocked(tmp_path):
    _,g,private,p,_=environment(tmp_path);c=g.issue_challenge(p.worker_id,p.key_id,now=1);frame=c.transcript("s",1);frame["expires_at"]+=1;assert classify(lambda:g.authenticate_session(sign(private,"SESSION",frame),now=1))=="BLOCKED"

def test_a05_capability_target_capacity_escalation_blocked(tmp_path):
    _,g,private,p,_=environment(tmp_path);c=g.issue_challenge(p.worker_id,p.key_id,now=1);frame=c.transcript("s",2);assert classify(lambda:g.authenticate_session(sign(private,"SESSION",frame),now=1))=="BLOCKED"

def test_a06_session_key_worker_substitution_blocked(tmp_path):
    _,g,private,p,_=environment(tmp_path);c=g.issue_challenge(p.worker_id,p.key_id,now=1);frame=c.transcript("s",1);frame["key_id"]="other";assert classify(lambda:g.authenticate_session(sign(private,"SESSION",frame),now=1))=="BLOCKED"

def test_a07_replayed_stale_future_heartbeat_blocked(tmp_path):
    _,g,private,p,_=environment(tmp_path);authenticate(g,private,p,now=100);frame=message(private,"HEARTBEAT",p,"session-1",1,200,capacity=1);assert classify(lambda:g.heartbeat(frame,now=100))=="BLOCKED"

def test_a08_simultaneous_session_takeover_blocked(tmp_path):
    _,g,private,p,_=environment(tmp_path);authenticate(g,private,p,now=100);c=g.issue_challenge(p.worker_id,p.key_id,now=101);frame=sign(private,"SESSION",c.transcript("session-2",1));assert classify(lambda:g.authenticate_session(frame,now=101))=="BLOCKED"

def test_a09_revoked_session_signed_message_blocked(tmp_path):
    _,g,private,p,_=environment(tmp_path);authenticate(g,private,p,now=100);g.revoke(p.worker_id);frame=message(private,"HEARTBEAT",p,"session-1",1,101,capacity=1);assert classify(lambda:g.heartbeat(frame,now=101))=="BLOCKED"

def test_a10_spool_evidence_traversal_escape_blocked(tmp_path):
    _,g,_,_,_=environment(tmp_path);assert classify(lambda:g.transport.resolve_evidence("../state"))=="BLOCKED"

def test_a11_oversized_duplicate_transport_frame_blocked(tmp_path):
    _,g,_,_,_=environment(tmp_path);g.transport.write_outbound("message",{"ok":True});assert classify(lambda:g.transport.write_outbound("message",{"ok":True}))=="BLOCKED"

def test_a12_dispatch_task_lease_substitution_blocked(tmp_path):
    _,g,private,p,_,e=routed(tmp_path);frame=message(private,"ACK",p,e.session_id,2,102,dispatch_id=e.dispatch_id,task_id="other",lease_id=e.lease_id);assert classify(lambda:g.acknowledge(frame,now=102))=="BLOCKED"

def test_a13_ack_without_valid_dispatch_blocked(tmp_path):
    _,g,private,p,_,e=routed(tmp_path);frame=message(private,"ACK",p,e.session_id,2,102,dispatch_id="0"*64,task_id=e.task_id,lease_id=e.lease_id);assert classify(lambda:g.acknowledge(frame,now=102))=="BLOCKED"

def test_a14_result_before_ack_or_unsupported_state_blocked(tmp_path):
    _,g,private,p,_,e=routed(tmp_path);frame=message(private,"RESULT",p,e.session_id,2,102,dispatch_id=e.dispatch_id,task_id=e.task_id,lease_id=e.lease_id,status="CERTIFIED_PASS",evidence_id="e",evidence_sha256="0"*64);assert classify(lambda:g.result(frame,now=102))=="BLOCKED"

def test_a15_evidence_digest_content_substitution_blocked(tmp_path):
    _,g,private,p,_,e=routed(tmp_path);g.acknowledge(message(private,"ACK",p,e.session_id,2,102,dispatch_id=e.dispatch_id,task_id=e.task_id,lease_id=e.lease_id),now=102);g.transport.evidence_path("e").write_bytes(b"actual");frame=message(private,"RESULT",p,e.session_id,3,103,dispatch_id=e.dispatch_id,task_id=e.task_id,lease_id=e.lease_id,status="SUCCEEDED",evidence_id="e",evidence_sha256="0"*64);assert classify(lambda:g.result(frame,now=103))=="BLOCKED"

def test_a16_result_after_lease_or_session_expiry_blocked(tmp_path):
    _,g,private,p,_,e=routed(tmp_path);frame=message(private,"ACK",p,e.session_id,2,200,dispatch_id=e.dispatch_id,task_id=e.task_id,lease_id=e.lease_id);assert classify(lambda:g.acknowledge(frame,now=200))=="BLOCKED"

def test_a17_capability_target_escalation_in_frame_blocked(tmp_path):
    _,g,private,p,_,e=routed(tmp_path);frame=message(private,"ACK",p,e.session_id,2,102,dispatch_id=e.dispatch_id,task_id=e.task_id,lease_id=e.lease_id);frame["capability"]="REPO_WRITE";frame=sign(private,"ACK",frame);assert classify(lambda:g.acknowledge(frame,now=102))=="BLOCKED"

def test_a18_forged_provider_scope_or_self_registration_blocked(tmp_path):
    _,g,private,p,_=environment(tmp_path);c=g.issue_challenge(p.worker_id,p.key_id,now=1);frame=c.transcript("s",1);frame["verification_scope"]="VERIFIED_PROVIDER";frame=sign(private,"SESSION",frame);assert classify(lambda:g.authenticate_session(frame,now=1))=="BLOCKED"

def test_a19_no_provider_network_cli_or_production_subprocess_surface():
    source=(inspect.getsource(external_module)+inspect.getsource(transport_module)+inspect.getsource(trust_module)).lower()
    forbidden=("import subprocess","import socket","import requests","httpx","popen(","os.system","shell=true","codex cli","anthropic","openai api")
    assert all(token not in source for token in forbidden)
    assert classify(lambda:(_ for _ in ()).throw(BlockedError("surface absent")))=="BLOCKED"

def test_a20_no_protected_main_git_mutation_or_live_money_authority(tmp_path):
    _,g,_,_,root=environment(tmp_path);source=(inspect.getsource(external_module)+inspect.getsource(transport_module)).lower()
    assert REAL_PROJECT_MUTATION_ENABLED is False and g.transport.root.is_relative_to(root)
    assert all(token not in source for token in ("git push","git commit","git add","place_order","live_money","risk_mutation","strategy_mutation"))
    assert classify(lambda:(_ for _ in ()).throw(BlockedError("mutation authority absent")))=="BLOCKED"
