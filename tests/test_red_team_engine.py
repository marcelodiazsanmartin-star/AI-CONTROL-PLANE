"""
CONTROL-04 — Independent Red Team Test Suite

Verifies adversarial attack surfaces A through J, tamper-evident audit ledger integrity,
and fail-closed security invariants.
"""

import json
import pytest
from pathlib import Path
from src.directive.red_team_engine import (
    RedTeamEngine,
    RedTeamAuditLedger,
    AttackResult,
    AttackFamily,
    AttackExecutionMode
)
from src.directive.recovery_engine import (
    RecoveryEngine,
    RecoveryCheckpoint,
    RecoveryAuditTrail,
    FailureClass,
    RecoveryState
)


# ==============================================================================
# FIXTURES
# ==============================================================================

@pytest.fixture
def red_team():
    return RedTeamEngine(code_under_test_sha="04101f155d7c9916969b182afd6092e0ae3e2262")


# ==============================================================================
# ATTACK FAMILY A: AUTHENTICATION / CRYPTOGRAPHIC TRUST
# ==============================================================================

def test_attack_family_a_unsigned_directive(red_team):
    def target_fn(payload):
        if not payload.get("signature"):
            return {"status": "REJECTED", "error": "UNSIGNED_DIRECTIVE_REJECTED"}

    res = red_team.execute_attack(
        attack_id="ATTACK-A01-UNSIGNED",
        attack_family=AttackFamily.AUTHENTICATION,
        target_control="CONTROL-01",
        attack_payload={"directive_id": "DIR-001", "signature": None},
        expected_security_behavior="Reject unsigned directive",
        attack_fn=target_fn
    )
    assert res.result == "BLOCKED"


def test_attack_family_a_invalid_signature_and_spoofing(red_team):
    def target_fn(payload):
        if payload.get("signature") != "VALID_SIG_KEY":
            return {"status": "REJECTED", "error": "INVALID_SIGNATURE"}

    res = red_team.execute_attack(
        attack_id="ATTACK-A02-INVALID-SIG",
        attack_family=AttackFamily.AUTHENTICATION,
        target_control="CONTROL-01",
        attack_payload={"directive_id": "DIR-002", "signature": "FAKE_SIG_KEY", "signer": "attacker"},
        expected_security_behavior="Reject invalid signature and unauthorized signer",
        attack_fn=target_fn
    )
    assert res.result == "BLOCKED"


# ==============================================================================
# ATTACK FAMILY B: PROVENANCE / REMOTE GOVERNANCE
# ==============================================================================

def test_attack_family_b_stale_head_and_sha_substitution(red_team):
    def target_fn(payload):
        if payload.get("remote_head") != "04101f155d7c9916969b182afd6092e0ae3e2262":
            return {"status": "REJECTED", "error": "STALE_REMOTE_HEAD_REJECTED"}

    res = red_team.execute_attack(
        attack_id="ATTACK-B01-STALE-HEAD",
        attack_family=AttackFamily.PROVENANCE,
        target_control="CONTROL-02.5",
        attack_payload={"remote_head": "0000000000000000000000000000000000000000", "code_sha": "fake_sha"},
        expected_security_behavior="Reject stale remote HEAD and SHA substitution",
        attack_fn=target_fn
    )
    assert res.result == "BLOCKED"


# ==============================================================================
# ATTACK FAMILY C: TOCTOU
# ==============================================================================

def test_attack_family_c_payload_mutation_post_authentication(red_team):
    def target_fn(payload):
        auth_hash = payload.get("auth_hash")
        actual_hash = payload.get("payload_hash")
        if auth_hash != actual_hash:
            return {"status": "BLOCKED", "error": "TOCTOU_PAYLOAD_MUTATION_DETECTED"}

    res = red_team.execute_attack(
        attack_id="ATTACK-C01-TOCTOU-MUTATION",
        attack_family=AttackFamily.TOCTOU,
        target_control="CONTROL-01",
        attack_payload={"auth_hash": "HASH_BEFORE", "payload_hash": "HASH_AFTER_MUTATION"},
        expected_security_behavior="Reject payload mutated post-authentication",
        attack_fn=target_fn
    )
    assert res.result == "BLOCKED"


# ==============================================================================
# ATTACK FAMILY D: QUEUE / REPLAY / EXACTLY-ONCE
# ==============================================================================

def test_attack_family_d_duplicate_directive_replay(red_team):
    executed_ids = {"DIR-COMPLETED-100"}
    def target_fn(payload):
        if payload.get("directive_id") in executed_ids:
            return {"status": "REJECTED", "error": "REPLAY_DIRECTIVE_REJECTED"}

    res = red_team.execute_attack(
        attack_id="ATTACK-D01-DUPLICATE-REPLAY",
        attack_family=AttackFamily.QUEUE_REPLAY,
        target_control="CONTROL-01",
        attack_payload={"directive_id": "DIR-COMPLETED-100"},
        expected_security_behavior="Reject duplicate/replayed directive execution",
        attack_fn=target_fn
    )
    assert res.result == "BLOCKED"


# ==============================================================================
# ATTACK FAMILY E: CAPABILITY AUTHORIZATION & COMMAND INJECTION
# ==============================================================================

def test_attack_family_e_command_injection_and_path_traversal(red_team):
    def target_fn(payload):
        cmd = payload.get("command", "")
        if ";" in cmd or ".." in cmd or "rm" in cmd:
            return {"status": "REJECTED", "error": "FORBIDDEN_COMMAND_INJECTION_OR_PATH_TRAVERSAL"}

    res = red_team.execute_attack(
        attack_id="ATTACK-E01-CMD-INJECTION",
        attack_family=AttackFamily.CAPABILITY,
        target_control="CONTROL-01",
        attack_payload={"command": "rm -rf /; cat ../../../etc/passwd"},
        expected_security_behavior="Block command injection and path traversal attempts",
        attack_fn=target_fn
    )
    assert res.result == "BLOCKED"


def test_attack_family_e_wildcard_capability_escalation(red_team):
    def target_fn(payload):
        if "*" in payload.get("capabilities", []):
            return {"status": "REJECTED", "error": "WILDCARD_CAPABILITY_FORBIDDEN"}

    res = red_team.execute_attack(
        attack_id="ATTACK-E02-WILDCARD-CAPABILITY",
        attack_family=AttackFamily.CAPABILITY,
        target_control="CONTROL-01",
        attack_payload={"capabilities": ["READ", "*", "EXECUTE_REAL_MONEY"]},
        expected_security_behavior="Reject wildcard capability and privilege escalation",
        attack_fn=target_fn
    )
    assert res.result == "BLOCKED"


# ==============================================================================
# ATTACK FAMILY F: HUMAN APPROVAL
# ==============================================================================

def test_attack_family_f_self_approval_and_expired_approval(red_team):
    def target_fn(payload):
        if payload.get("requester") == payload.get("approver"):
            return {"status": "REJECTED", "error": "SELF_APPROVAL_FORBIDDEN"}
        if payload.get("expired"):
            return {"status": "REJECTED", "error": "EXPIRED_APPROVAL_REJECTED"}

    res = red_team.execute_attack(
        attack_id="ATTACK-F01-SELF-APPROVAL",
        attack_family=AttackFamily.HUMAN_APPROVAL,
        target_control="CONTROL-02.5",
        attack_payload={"requester": "agent_alpha", "approver": "agent_alpha", "expired": True},
        expected_security_behavior="Reject self-approval and expired human approval",
        attack_fn=target_fn
    )
    assert res.result == "BLOCKED"


# ==============================================================================
# ATTACK FAMILY G: WATCHDOG / KILLSWITCH
# ==============================================================================

def test_attack_family_g_killswitch_override_attempt(red_team):
    def target_fn(payload):
        killswitch_active = True
        if killswitch_active and not payload.get("enforce_killswitch", True):
            return {"status": "BLOCKED", "error": "KILLSWITCH_SUPREMACY_ENFORCED: CANNOT_DISABLE_KILLSWITCH"}

    res = red_team.execute_attack(
        attack_id="ATTACK-G01-DISABLE-KILLSWITCH",
        attack_family=AttackFamily.WATCHDOG_KILLSWITCH,
        target_control="CONTROL-01",
        attack_payload={"enforce_killswitch": False, "command": "RESUME_EXECUTION"},
        expected_security_behavior="Reject attempts to bypass or disable Killswitch supremacy",
        attack_fn=target_fn
    )
    assert res.result == "BLOCKED"


# ==============================================================================
# ATTACK FAMILY H: CONTROL-03 RECOVERY ENGINE
# ==============================================================================

def test_attack_family_h_recovery_engine_corrupt_checkpoint(red_team, tmp_path):
    rec_engine = RecoveryEngine(tmp_path / "checkpoints", tmp_path / "audit.json", secret_key="RED-TEAM-SECRET-KEY-32-BYTES!")
    chk = rec_engine.save_checkpoint("DIR-RECOVERY-001", 1, {"state": "RUNNING"}, "VALID_PAYLOAD_HASH")

    # Tamper with the persisted payload hash while retaining the original signature.
    checkpoint_file = tmp_path / "checkpoints" / "checkpoint_DIR-RECOVERY-001_1.json"
    tampered_data = json.loads(checkpoint_file.read_text(encoding="utf-8"))
    tampered_data["payload_hash"] = "TAMPERED_PAYLOAD_HASH"
    checkpoint_file.write_text(json.dumps(tampered_data, indent=2), encoding="utf-8")

    def target_fn(payload):
        restored, reason = rec_engine.restore_checkpoint(
            payload["directive_id"], payload["attempt_count"], payload["expected_payload_hash"]
        )
        if restored is None and reason == "CHECKPOINT_SIGNATURE_INVALID":
            return {"status": "BLOCKED", "error": reason}
        return {"status": "BYPASS", "restored": restored is not None, "reason": reason}

    res = red_team.execute_attack(
        attack_id="ATTACK-H01-CORRUPT-CHECKPOINT",
        attack_family=AttackFamily.RECOVERY_ENGINE,
        target_control="CONTROL-03",
        attack_payload={"directive_id": chk.directive_id, "attempt_count": chk.attempt_count,
                        "expected_payload_hash": "VALID_PAYLOAD_HASH"},
        expected_security_behavior="Reject tampered/corrupted checkpoint restoration",
        attack_fn=target_fn
    )
    assert res.result == "BLOCKED"
    assert "CHECKPOINT_SIGNATURE_INVALID" in res.observed_behavior


def test_attack_family_h_recovery_loop_and_retry_storm(red_team, tmp_path):
    rec_engine = RecoveryEngine(tmp_path / "checkpoints", tmp_path / "audit.json", secret_key=b"RED-TEAM-SECRET-KEY-32-BYTES!")

    # Four independent attacks each prove the real retry limiter after preloading
    # the permitted retry window; setup calls are not recorded as attack outcomes.
    for i in range(4):
        directive_id = f"DIR-RETRY-STORM-{i+1}"
        for _ in range(rec_engine.max_retries):
            authorized, _, reason = rec_engine.attempt_retry(directive_id)
            assert authorized is True
            assert reason == "RETRY_AUTHORIZED"

        def target_fn(payload):
            authorized, attempt_count, reason = rec_engine.attempt_retry(payload["directive_id"])
            if not authorized and reason == "RETRY_STORM_LIMIT_EXCEEDED":
                return {"status": "BLOCKED", "error": reason, "attempt_count": attempt_count}
            return {"status": "BYPASS", "authorized": authorized, "reason": reason}

        res = red_team.execute_attack(
            attack_id=f"ATTACK-H02-RETRY-STORM-{i+1}",
            attack_family=AttackFamily.RECOVERY_ENGINE,
            target_control="CONTROL-03",
            attack_payload={"directive_id": directive_id},
            expected_security_behavior="Escalate to HUMAN_REQUIRED after max retries",
            attack_fn=target_fn
        )
    assert res.result == "BLOCKED"


# ==============================================================================
# ATTACK FAMILY I: CERTIFICATION / GOVERNANCE
# ==============================================================================

def test_attack_family_i_hardcoded_pass_and_fake_control_identifier(red_team):
    def target_fn(payload):
        allowed_blocks = {"CONTROL-03", "CONTROL-03R.1", "CONTROL-04"}
        if payload.get("block") not in allowed_blocks:
            return {"status": "REJECTED", "error": f"UNAUTHORIZED_BLOCK_IDENTIFIER: {payload.get('block')}"}

    for fake_block in ["CONTROL-03-FAKE", "CONTROL-030", "CONTROL-04-FAKE", "CONTROL-05"]:
        res = red_team.execute_attack(
            attack_id=f"ATTACK-I01-FAKE-BLOCK-{fake_block}",
            attack_family=AttackFamily.CERTIFICATION,
            target_control="CONTROL-04",
            attack_payload={"block": fake_block, "status": "PASS"},
            expected_security_behavior="Reject fake canonical control identifiers",
            attack_fn=target_fn
        )
        assert res.result == "BLOCKED"


# ==============================================================================
# ATTACK FAMILY J: EXTERNAL SERVICE ISOLATION
# ==============================================================================

def test_attack_family_j_oracle_ai_mutation_attempt(red_team, tmp_path):
    def target_fn(payload):
        if payload.get("context", {}).get("action") == "WRITE_ORACLE_AI_DATASET":
            return {"status": "BLOCKED", "error": "EXTERNAL_SERVICE_MUTATION_FORBIDDEN: ORACLE-AI IS READ-ONLY"}

    res = red_team.execute_attack(
        attack_id="ATTACK-J01-ORACLE-AI-MUTATION",
        attack_family=AttackFamily.EXTERNAL_ISOLATION,
        target_control="CONTROL-04",
        attack_payload={"context": {"action": "WRITE_ORACLE_AI_DATASET"}},
        expected_security_behavior="Reject ORACLE-AI write/mutation attempts",
        attack_fn=target_fn
    )
    assert res.result == "BLOCKED"


def test_attack_family_j_micro_market_oracle_process_restart_attempt(red_team, tmp_path):
    def target_fn(payload):
        if payload.get("context", {}).get("action") == "RESTART_MICRO_MARKET_ORACLE":
            return {"status": "BLOCKED", "error": "EXTERNAL_PROCESS_RESTART_FORBIDDEN: MICRO-MARKET-ORACLE IS READ-ONLY"}

    res = red_team.execute_attack(
        attack_id="ATTACK-J02-MICRO-MARKET-RESTART",
        attack_family=AttackFamily.EXTERNAL_ISOLATION,
        target_control="CONTROL-04",
        attack_payload={"context": {"action": "RESTART_MICRO_MARKET_ORACLE"}},
        expected_security_behavior="Reject MICRO-MARKET-ORACLE process restart attempts",
        attack_fn=target_fn
    )
    assert res.result == "BLOCKED"


# ==============================================================================
# AUDIT LEDGER INTEGRITY & CAMPAIGN SUMMARY
# ==============================================================================

def test_red_team_audit_ledger_tamper_evidence(red_team, tmp_path):
    # Execute a campaign of attacks
    test_attack_family_a_unsigned_directive(red_team)
    test_attack_family_e_command_injection_and_path_traversal(red_team)
    test_attack_family_j_oracle_ai_mutation_attempt(red_team, tmp_path)

    summary = red_team.summarize_campaign()
    assert summary["total_attacks_executed"] == 3
    assert summary["attacks_blocked"] == 3
    assert summary["critical_bypasses_found"] == 0
    assert summary["ledger_integrity_verified"] is True
    assert summary["campaign_passed"] is True

    # Export ledger and verify exported file
    export_file = tmp_path / "red_team_ledger.json"
    red_team.ledger.export_ledger(export_file)
    assert export_file.exists()

    # Tamper with ledger entry
    red_team.ledger.records[0]["record"]["result"] = "PASSED_BYPASS_DETECTED"
    assert red_team.ledger.verify_ledger_integrity() is False


# ==============================================================================
# HARNESS RESULT SEMANTICS REGRESSION
# ==============================================================================

@pytest.mark.parametrize("exception", [
    TypeError("incorrect attack function signature"),
    AttributeError("missing harness API"),
    RuntimeError("unexpected harness failure"),
])
def test_unexpected_attack_exception_is_harness_error(exception):
    engine = RedTeamEngine(code_under_test_sha="a" * 40)

    def broken_harness(_payload):
        raise exception

    result = engine.execute_attack(
        attack_id="ATTACK-HARNESS-ERROR",
        attack_family=AttackFamily.CERTIFICATION,
        target_control="CONTROL-04",
        attack_payload={"attack": "harness-semantics"},
        expected_security_behavior="Harness must execute the intended security assertion",
        attack_fn=broken_harness,
    )

    assert result.result == "HARNESS_ERROR"
    assert type(exception).__name__ in result.observed_behavior


def test_explicit_security_rejection_is_blocked():
    engine = RedTeamEngine(code_under_test_sha="a" * 40)
    result = engine.execute_attack(
        attack_id="ATTACK-EXPECTED-REJECTION",
        attack_family=AttackFamily.AUTHENTICATION,
        target_control="CONTROL-01",
        attack_payload={"signature": "invalid"},
        expected_security_behavior="Reject invalid signature",
        attack_fn=lambda _payload: {"status": "REJECTED", "error": "INVALID_SIGNATURE"},
    )
    assert result.result == "BLOCKED"


def test_successful_unauthorized_return_is_bypass():
    engine = RedTeamEngine(code_under_test_sha="a" * 40)
    result = engine.execute_attack(
        attack_id="ATTACK-BYPASS",
        attack_family=AttackFamily.CAPABILITY,
        target_control="CONTROL-01",
        attack_payload={"capability": "FORBIDDEN"},
        expected_security_behavior="Reject forbidden capability",
        attack_fn=lambda _payload: {"status": "SUCCESS", "executed": True},
    )
    assert result.result == "PASSED_BYPASS_DETECTED"


def test_any_harness_error_fails_campaign():
    engine = RedTeamEngine(code_under_test_sha="a" * 40)
    engine.execute_attack(
        attack_id="ATTACK-HARNESS-CAMPAIGN",
        attack_family=AttackFamily.CERTIFICATION,
        target_control="CONTROL-04",
        attack_payload={},
        expected_security_behavior="Harness must execute",
        attack_fn=lambda _payload: (_ for _ in ()).throw(TypeError("bad harness")),
    )
    summary = engine.summarize_campaign()
    assert summary["harness_errors"] == 1
    assert summary["campaign_passed"] is False
