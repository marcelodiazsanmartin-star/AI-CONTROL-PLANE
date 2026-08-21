"""
CONTROL-03 — Recovery Engine Functional & Adversarial Test Suite

Verifies:
1. Safe failure classification, retries, checkpoint save/restore, integrity validation, and safe continuation.
2. Adversarial protection against retry storms, corrupt/tampered/stale checkpoints, replay attacks, duplicate execution,
   audit tampering, killswitch bypass, and unauthorized external service mutations (ORACLE/MICRO).
"""

import json
import time
import pytest
import hashlib
from pathlib import Path
from datetime import datetime, timezone, timedelta

from src.directive.recovery_engine import (
    RecoveryEngine, FailureClass, RecoveryState, RecoveryCheckpoint, RecoveryAuditTrail
)


@pytest.fixture
def recovery_setup(tmp_path):
    cp_dir = tmp_path / "checkpoints"
    audit_file = tmp_path / "recovery_audit.jsonl"
    engine = RecoveryEngine(checkpoint_dir=cp_dir, audit_file=audit_file, secret_key="TEST_SECRET_KEY")
    return engine, cp_dir, audit_file


# ==============================================================================
# FUNCTIONAL REVIEWS (Tests 1-8)
# ==============================================================================

def test_functional_safe_retry_on_recoverable_failure(recovery_setup):
    """1. Proves safe retry works on recoverable failure."""
    engine, _, _ = recovery_setup
    res = engine.execute_safe_recovery(
        directive_id="dir-001",
        error_type="TIMEOUT_ERROR",
        error_msg="Temporary network socket timeout",
        state_vector={"step": 2, "buffer": "partial_data"},
        payload_hash="hash_dir_001"
    )
    assert res["executed"] is True
    assert res["recovery_state"] == RecoveryState.CONTINUING
    assert res["human_required"] is False
    assert res["attempt_count"] == 1


def test_functional_recovery_from_valid_checkpoint(recovery_setup):
    """2. Proves recovery from valid checkpoint restores canonical state."""
    engine, _, _ = recovery_setup
    state = {"balance": 100, "phase": "PREPARED"}
    payload_hash = "hash_cp_valid"

    # Save checkpoint
    cp = engine.save_checkpoint("dir-002", attempt_count=1, state_vector=state, payload_hash=payload_hash)
    assert cp.signature != ""

    # Restore checkpoint
    restored, status = engine.restore_checkpoint("dir-002", attempt_count=1, expected_payload_hash=payload_hash)
    assert restored is not None
    assert status == "CHECKPOINT_INTEGRITY_VALIDATED"
    assert restored.state_vector == state


def test_functional_internal_restart_preserves_canonical_state(recovery_setup, tmp_path):
    """3. Proves internal restart preserves canonical state without data loss."""
    cp_dir = tmp_path / "checkpoints"
    audit_file = tmp_path / "recovery_audit.jsonl"

    engine1 = RecoveryEngine(checkpoint_dir=cp_dir, audit_file=audit_file, secret_key="TEST_SECRET_KEY")
    engine1.save_checkpoint("dir-003", 1, {"stage": "STAGE_1"}, "hash_003")

    # Simulate restart by instantiating new RecoveryEngine on same storage
    engine2 = RecoveryEngine(checkpoint_dir=cp_dir, audit_file=audit_file, secret_key="TEST_SECRET_KEY")
    restored, status = engine2.restore_checkpoint("dir-003", 1, "hash_003")
    assert restored is not None
    assert status == "CHECKPOINT_INTEGRITY_VALIDATED"
    assert restored.state_vector == {"stage": "STAGE_1"}


def test_functional_integrity_verified_before_continuation(recovery_setup):
    """4. Proves integrity is verified before continuing from checkpoint."""
    engine, _, _ = recovery_setup
    res = engine.execute_safe_recovery(
        directive_id="dir-004",
        error_type="LOCK_CONTENTION",
        error_msg="Queue lock busy, retrying",
        state_vector={"lock": "acquired"},
        payload_hash="hash_004"
    )
    assert res["executed"] is True
    assert res["reason"] == "SAFE_CONTINUATION_SUCCESSFUL"


def test_functional_successful_recovery_no_duplicate_execution(recovery_setup):
    """5. Proves successful recovery does not duplicate execution/work."""
    engine, _, _ = recovery_setup
    # First execution succeeds
    res1 = engine.execute_safe_recovery(
        directive_id="dir-005",
        error_type="TIMEOUT_ERROR",
        error_msg="Transient timeout",
        state_vector={"step": 1},
        payload_hash="hash_005"
    )
    assert res1["executed"] is True

    # Second execution attempt with same directive_id is blocked
    res2 = engine.execute_safe_recovery(
        directive_id="dir-005",
        error_type="TIMEOUT_ERROR",
        error_msg="Transient timeout",
        state_vector={"step": 1},
        payload_hash="hash_005"
    )
    assert res2["executed"] is False
    assert res2["human_required"] is True
    assert res2["reason"] == "DUPLICATE_EXECUTION_ATTEMPT_REJECTED"


def test_functional_failed_recovery_escalates_to_human(recovery_setup):
    """6. Proves failed recovery escalates correctly to HUMAN_REQUIRED."""
    engine, _, _ = recovery_setup
    res = engine.execute_safe_recovery(
        directive_id="dir-006",
        error_type="CORRUPT_DATA",
        error_msg="Unrecoverable database corruption",
        state_vector={},
        payload_hash="hash_006"
    )
    assert res["executed"] is False
    assert res["recovery_state"] == RecoveryState.HUMAN_REQUIRED
    assert res["human_required"] is True


def test_functional_audit_ledger_preserves_full_sequence(recovery_setup):
    """7. Proves audit ledger preserves complete recovery sequence."""
    engine, _, audit_file = recovery_setup
    engine.execute_safe_recovery(
        directive_id="dir-007",
        error_type="TIMEOUT_ERROR",
        error_msg="Transient error",
        state_vector={"val": 42},
        payload_hash="hash_007"
    )
    lines = [l for l in audit_file.read_text(encoding="utf-8").splitlines() if l.strip()]
    assert len(lines) >= 4  # RETRY_INITIATED, CHECKPOINT_SAVED, RESTORED, SAFE_CONTINUATION
    ok, msg = engine.audit.verify_ledger_integrity()
    assert ok is True
    assert msg == "INTEGRITY_VALIDATED"


def test_functional_watchdog_killswitch_supreme_authority(recovery_setup):
    """8. Proves watchdog and killswitch act as supreme authority over recovery."""
    engine, _, _ = recovery_setup
    res = engine.execute_safe_recovery(
        directive_id="dir-008",
        error_type="TIMEOUT_ERROR",
        error_msg="Transient error",
        state_vector={},
        payload_hash="hash_008",
        watchdog_killswitch_active=True
    )
    assert res["executed"] is False
    assert res["recovery_state"] == RecoveryState.KILLED_BY_WATCHDOG
    assert res["human_required"] is True


# ==============================================================================
# ADVERSARIAL REVIEWS (Tests 9-22)
# ==============================================================================

def test_adversarial_infinite_retry_storm_blocked(recovery_setup):
    """9. Proves infinite retry storm / recovery loop is blocked and escalates."""
    engine, _, _ = recovery_setup
    directive_id = "dir-storm"

    for i in range(3):
        ok, count, _ = engine.attempt_retry(directive_id)
        assert ok is True

    # 4th retry exceeds max_retries=3
    ok, count, reason = engine.attempt_retry(directive_id)
    assert ok is False
    assert reason == "RETRY_STORM_LIMIT_EXCEEDED"


def test_adversarial_corrupt_checkpoint_fails_closed(recovery_setup, tmp_path):
    """10. Proves corrupt checkpoint JSON fails closed."""
    engine, cp_dir, _ = recovery_setup
    cp_file = cp_dir / "checkpoint_dir-corrupt_1.json"
    cp_file.write_text("{invalid_json: true", encoding="utf-8")

    cp, status = engine.restore_checkpoint("dir-corrupt", 1, "hash_corrupt")
    assert cp is None
    assert status == "CHECKPOINT_CORRUPT_JSON"


def test_adversarial_tampered_checkpoint_signature_fails_closed(recovery_setup):
    """11. Proves tampered checkpoint signature fails closed."""
    engine, _, _ = recovery_setup
    cp = engine.save_checkpoint("dir-tamper", 1, {"data": "authentic"}, "hash_tamper")

    # Manually tamper signature in saved checkpoint file
    cp_file = engine.checkpoint_dir / "checkpoint_dir-tamper_1.json"
    data = json.loads(cp_file.read_text(encoding="utf-8"))
    data["signature"] = "0000000000000000000000000000000000000000000000000000000000000000"
    cp_file.write_text(json.dumps(data), encoding="utf-8")

    cp_restored, status = engine.restore_checkpoint("dir-tamper", 1, "hash_tamper")
    assert cp_restored is None
    assert status == "CHECKPOINT_SIGNATURE_INVALID"


def test_adversarial_stale_checkpoint_timestamp_fails_closed(recovery_setup):
    """12. Proves stale checkpoint timestamp fails closed."""
    engine, _, _ = recovery_setup
    # Save checkpoint with old timestamp (2 hours ago)
    old_time = (datetime.now(timezone.utc) - timedelta(hours=2)).isoformat()
    cp = RecoveryCheckpoint(
        directive_id="dir-stale",
        attempt_count=1,
        state_vector={"old": True},
        payload_hash="hash_stale",
        timestamp=old_time
    )
    cp.signature = cp.compute_signature(engine.secret_key)
    cp_file = engine.checkpoint_dir / "checkpoint_dir-stale_1.json"
    cp_file.write_text(json.dumps(cp.to_dict()), encoding="utf-8")

    cp_restored, status = engine.restore_checkpoint("dir-stale", 1, "hash_stale")
    assert cp_restored is None
    assert status == "CHECKPOINT_STALE_TIMESTAMP"


def test_adversarial_replay_attack_after_restart_blocked(recovery_setup):
    """13. Proves replay attack after restart is blocked."""
    engine, _, _ = recovery_setup
    engine.executed_directives["dir-replay"] = "COMPLETED"

    res = engine.execute_safe_recovery(
        directive_id="dir-replay",
        error_type="TIMEOUT_ERROR",
        error_msg="Replay timeout",
        state_vector={},
        payload_hash="hash_replay"
    )
    assert res["executed"] is False
    assert res["human_required"] is True


def test_adversarial_duplicate_execution_attempt_blocked(recovery_setup):
    """14. Proves duplicate execution attempt during recovery is blocked."""
    engine, _, _ = recovery_setup
    res1 = engine.execute_safe_recovery("dir-dup", "TIMEOUT_ERROR", "t1", {"v": 1}, "h_dup")
    assert res1["executed"] is True

    res2 = engine.execute_safe_recovery("dir-dup", "TIMEOUT_ERROR", "t1", {"v": 1}, "h_dup")
    assert res2["executed"] is False
    assert res2["human_required"] is True


def test_adversarial_crash_during_recovery_escalates_safely(recovery_setup):
    """15. Proves unclassified/exception failure during recovery escalates to HUMAN_REQUIRED."""
    engine, _, _ = recovery_setup
    fail_class, reason = engine.classify_failure("UNKNOWN_CRASH_EXCEPTION", "Process SEGFAULT or OOM")
    assert fail_class == FailureClass.UNRECOVERABLE
    assert reason == "UNCLASSIFIED_FAILURE_FAIL_CLOSED"


def test_adversarial_partial_recovery_state_rejected(recovery_setup):
    """16. Proves partial recovery / hash mismatch is rejected."""
    engine, _, _ = recovery_setup
    engine.save_checkpoint("dir-partial", 1, {"state": "complete"}, "hash_original")

    # Pass different expected hash
    cp, status = engine.restore_checkpoint("dir-partial", 1, "hash_MODIFIED_EXPECTED")
    assert cp is None
    assert status == "CHECKPOINT_PAYLOAD_HASH_MISMATCH"


def test_adversarial_split_brain_secondary_instance_blocked(recovery_setup):
    """17. Proves split brain / secondary instance error fails closed."""
    engine, _, _ = recovery_setup
    fail_class, reason = engine.classify_failure("SPLIT_BRAIN_ERROR", "Multiple active controller leases detected")
    assert fail_class == FailureClass.UNRECOVERABLE
    assert "SPLIT_BRAIN" in reason


def test_adversarial_bypass_human_required_blocked(recovery_setup):
    """18. Proves bypass of HUMAN_REQUIRED cannot occur without explicit human escalation."""
    engine, _, _ = recovery_setup
    res = engine.execute_safe_recovery(
        directive_id="dir-unrecoverable",
        error_type="CORRUPT_STATE",
        error_msg="Unrecoverable corruption",
        state_vector={},
        payload_hash="h"
    )
    assert res["executed"] is False
    assert res["human_required"] is True
    assert res["recovery_state"] == RecoveryState.HUMAN_REQUIRED


def test_adversarial_bypass_capability_policy_blocked(recovery_setup):
    """19. Proves capability policy denial fails closed."""
    engine, _, _ = recovery_setup
    fail_class, reason = engine.classify_failure("CAPABILITY_DENIED_ERROR", "Path outside workspace sandbox")
    assert fail_class == FailureClass.UNRECOVERABLE
    assert "CAPABILITY_DENIED" in reason


def test_adversarial_bypass_killswitch_blocked(recovery_setup):
    """20. Proves killswitch active cannot be bypassed by recovery."""
    engine, _, _ = recovery_setup
    fail_class, reason = engine.classify_failure("KILLSWITCH_TRIGGERED", "Emergency stop engaged")
    assert fail_class == FailureClass.UNRECOVERABLE
    assert "KILLSWITCH" in reason


def test_adversarial_altered_audit_trail_fails_integrity(recovery_setup):
    """21. Proves altered audit trail fails integrity verification."""
    engine, _, audit_file = recovery_setup
    engine.audit.record_event("EVENT_1", "dir-1", {"a": 1})
    engine.audit.record_event("EVENT_2", "dir-1", {"a": 2})

    # Alter second event in file
    lines = audit_file.read_text(encoding="utf-8").splitlines()
    d = json.loads(lines[1])
    d["details"]["a"] = 999  # Tamper details
    lines[1] = json.dumps(d)
    audit_file.write_text("\n".join(lines) + "\n", encoding="utf-8")

    ok, msg = engine.audit.verify_ledger_integrity()
    assert ok is False
    assert "HASH_MISMATCH" in msg


def test_adversarial_oracle_micro_service_mutation_blocked(recovery_setup):
    """22. Proves recovery engine rejects any attempt to mutate ORACLE-AI or MICRO-MARKET-ORACLE."""
    engine, _, _ = recovery_setup
    fail_class, reason = engine.classify_failure(
        error_type="RECOVERY_ATTEMPT",
        error_msg="Attempting to restart ORACLE-AI process",
        context={"target": "ORACLE-AI", "action": "RESTART_PROCESS"}
    )
    assert fail_class == FailureClass.UNRECOVERABLE
    assert reason == "EXTERNAL_SERVICE_MUTATION_FORBIDDEN"
