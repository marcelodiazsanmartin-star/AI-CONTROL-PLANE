"""AF-08 A01-A20 product-path adversarial campaign."""
import time

import pytest

from src.autonomy.real_project import CANARY_PATH, CanaryPlan, MutationSafetyTruth
from src.autonomy.store import BlockedError
from tests.test_autonomy_foundation_08 import environment, provision, apply, safety


def blocked(call):
    with pytest.raises(BlockedError): call()


def test_a01_untrusted_directive(tmp_path):
    env=environment(tmp_path);provision(env);blocked(lambda:apply(env,provenance_verifier=lambda _:False));assert not (env["project"]/CANARY_PATH).exists()

def test_a02_provenance_payload_substitution(tmp_path):
    env=environment(tmp_path);env["authority"]["directive_id"]="directive-other";blocked(lambda:provision(env))

def test_a03_missing_approval(tmp_path):
    env=environment(tmp_path);env["authority"]["approval_receipt_id"]="RCP-missing";blocked(lambda:provision(env))

def test_a04_expired_approval_receipt(tmp_path):
    env=environment(tmp_path);env["store"].db.execute("UPDATE approval_consumption_receipts SET state='EXPIRED'");blocked(lambda:provision(env))

def test_a05_revoked_approval_receipt(tmp_path):
    env=environment(tmp_path);env["store"].db.execute("UPDATE approval_consumption_receipts SET state='REVOKED'");blocked(lambda:provision(env))

def test_a06_consum_consumed_approval_replay(tmp_path):
    env=environment(tmp_path);blocked(lambda:env["controller"].consume_approval(engine=env["approvals"],approval_request_id=env["approval"]["approval_request_id"],task_id="task-1",directive_id="directive-1",parameter_hash=env["parameter_hash"]))

def test_a07_cross_task_receipt(tmp_path):
    env=environment(tmp_path);env["store"].db.execute("UPDATE approval_consumption_receipts SET task_id='other'");blocked(lambda:provision(env))

def test_a08_expired_or_replayed_authority(tmp_path):
    env=environment(tmp_path);env["authority"]["expires_at"]=0;blocked(lambda:provision(env))

def test_a09_wrong_target_project(tmp_path):
    env=environment(tmp_path);env["authority"]["target_project"]="MICRO-MARKET-ORACLE";blocked(lambda:provision(env))

def test_a10_wrong_pinned_base(tmp_path):
    env=environment(tmp_path);env["authority"]["pinned_base_commit_sha"]="0"*40;blocked(lambda:provision(env))

def test_a11_dirty_workspace(tmp_path):
    env=environment(tmp_path);(env["project"]/"dirty.txt").write_text("dirty");blocked(lambda:provision(env))

def test_a12_symlink_reparse_hardlink_path(tmp_path):
    env=environment(tmp_path);provision(env);target=env["project"]/CANARY_PATH;target.parent.mkdir();source=env["project"]/"README.md"
    try: target.hardlink_to(source)
    except OSError: pytest.skip("hardlinks unavailable")
    blocked(lambda:apply(env))

def test_a13_oversized_scope_expansion_plan(tmp_path):
    env=environment(tmp_path);provision(env);blocked(lambda:env["controller"].apply("authority-1",CanaryPlan("CREATE",CANARY_PATH,b"x"*4097),worker_id="worker-1",session_id="session-1",lease_id=env["lease"]["lease_id"],dispatch_id="dispatch-1",provider_state="PROVIDER_CONNECTED_UNATTESTED",provider_observed_at=time.time(),safety=safety(),provenance_verifier=lambda _:True))

def test_a14_stale_unverified_worker_provider(tmp_path):
    env=environment(tmp_path);provision(env);env["gateway"].fresh=False;blocked(lambda:apply(env))

def test_a15_lease_session_dispatch_substitution(tmp_path):
    env=environment(tmp_path);provision(env);blocked(lambda:apply(env,lease_id="forged"))

def test_a16_killswitch_not_exactly_armed(tmp_path):
    for state in ("DISARMED","TRIGGERED","RECOVERY_PENDING","UNKNOWN"):
        env=environment(tmp_path/state);provision(env);blocked(lambda e=env,s=state:apply(e,safety=MutationSafetyTruth("HEALTHY",s,time.time(),True,True)))

def test_a17_watchdog_or_audit_failure(tmp_path):
    for index,health in enumerate(("UNKNOWN","CRITICAL")):
        env=environment(tmp_path/str(index));provision(env);blocked(lambda e=env,h=health:apply(e,safety=MutationSafetyTruth(h,"ARMED",time.time(),False,True)))

def test_a18_crash_during_applying_recovers_without_write(tmp_path):
    env=environment(tmp_path);provision(env)
    with pytest.raises(RuntimeError):apply(env,before_write=lambda:(_ for _ in ()).throw(RuntimeError("crash")))
    assert env["controller"].recover_applying("authority-1")=="FAILED" and not (env["project"]/CANARY_PATH).exists()

def test_a19_git_process_credential_money_strategy_attempt(tmp_path):
    env=environment(tmp_path);provision(env);blocked(lambda:env["controller"].apply("authority-1",CanaryPlan("SHELL",CANARY_PATH,b"token=secret"),worker_id="worker-1",session_id="session-1",lease_id=env["lease"]["lease_id"],dispatch_id="dispatch-1",provider_state="PROVIDER_CONNECTED_UNATTESTED",provider_observed_at=time.time(),safety=safety(),provenance_verifier=lambda _:True))

def test_a20_duplicate_result_restart_replay(tmp_path):
    env=environment(tmp_path);provision(env);apply(env);blocked(lambda:apply(env))
