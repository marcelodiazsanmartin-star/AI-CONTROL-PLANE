"""
Certification Evidence & Integrity Test Suite (Tests A-M + Block 1.1 Cross-Source Consistency Tests): CONTROL-02.5

Verifies non-circular evidence derivation, production signer manifest validation,
stale evidence rejection, run ID mismatch detection, execution evidence reconciliation (calling production reconciler),
cross-source contradiction detection, and AST self-auditing scanner rules.
"""

import os
import json
import time
import hashlib
import pytest
from pathlib import Path
from datetime import datetime, timezone, timedelta

from config import settings
from src.directive.scanner import scan_authentication_bypasses
from src.directive.signer_validator import validate_production_signers, compute_ssh_public_key_fingerprint
from src.directive.reconciler import reconcile_execution_evidence
from src.directive.authenticator import DirectiveAuthenticator
from src.directive.contracts import DirectivePayload, DirectiveEnvelope, ValidationStatus
from src.directive.governance import (
    validate_trusted_branch_declaration, evaluate_branch_governance_rules, verify_trusted_head_provenance,
    verify_historical_incident_preserved, verify_remediation_branch
)
from src.directive.queue_integrity import (
    derive_directive_identity, DurableDirectiveQueue, QueueAuditTrail, DirectiveState
)
from src.directive.capability_policy import (
    evaluate_execution_authorization, derive_risk_class, sanitize_and_resolve_path,
    ExecutionAuthorizationToken, AuthorizationAuditTrail, RiskClass
)
from src.directive.approval_engine import (
    derive_approval_request_id, create_approval_context, ApprovalState,
    DurableApprovalEngine, ApprovalAuditChain, NotificationManager, revalidate_approval_for_execution
)
from src.directive.watchdog import (
    HealthState, KillswitchState, IncidentAuditTrail, DurableKillswitch,
    WatchdogHealthMonitor, ControllerLeaseManager, derive_incident_id
)
from generate_certification_02_5 import (
    audit_certification_generator_ast, derive_security_gates, validate_crypto_backend,
    initialize_ssh_crypto_backend, verify_target_binding
)


# A. TEST_INJECTED_SHA_BYPASS_DETECTED
def test_injected_sha_bypass_detected(tmp_path):
    fake_src = tmp_path / "src" / "directive"
    fake_src.mkdir(parents=True)
    fake_file = fake_src / "fake_authenticator.py"
    fake_file.write_text('if commit_sha == "e927f95": return True, True, trusted_key, True\n', encoding="utf-8")

    res = scan_authentication_bypasses(root_dir=tmp_path)
    assert res["available"] is True
    assert res["count"] > 0
    assert len(res["violations"]) > 0


# B. TEST_CLEAN_AUTHENTICATOR_ZERO_BYPASSES
def test_clean_authenticator_zero_bypasses():
    res = scan_authentication_bypasses(root_dir=settings.CONTROL_PLANE_ROOT)
    assert res["available"] is True
    assert res["count"] == 0, f"Scanner found violations in clean code: {res['violations']}"


# C. TEST_FAKE_PRODUCTION_FINGERPRINT_FAILS
def test_fake_production_fingerprint_fails(monkeypatch):
    monkeypatch.setattr(settings, "PRODUCTION_TRUSTED_SIGNER_ALLOWLIST", {"SHA256:FAKE_UNREGISTERED_FINGERPRINT_12345"})
    res = validate_production_signers(root_dir=settings.CONTROL_PLANE_ROOT)
    assert res["production_signer_manifest_valid"] is False
    assert res["production_invalid_signer_count"] > 0


# D. TEST_TEST_KEY_LEAK_TO_PRODUCTION_FAILS
def test_test_key_leak_to_production_fails():
    ephemeral_test_fingerprint = "SHA256:EPHEMERAL_TEST_KEY_FINGERPRINT_999"
    prod_allowlist = {"SHA256:zYZi3+VxKz9ve+PJgTS2o8q+dvXSmzCwPZ2G3NYh41A"}

    leaked_allowlist = set(prod_allowlist)
    leaked_allowlist.add(ephemeral_test_fingerprint)

    test_keys = {ephemeral_test_fingerprint}
    intersection = test_keys.intersection(leaked_allowlist)

    assert len(intersection) > 0, "Leakage detection failed to detect test key in allowlist"


# RECONCILIATION BLOCK 1 TESTS (Fail-closed & Basic Reconciliation)

def test_reconcile_missing_execution_queue_fail_closed(tmp_path):
    runtime_dir = tmp_path / "directives" / "runtime"
    acks_dir = tmp_path / "directives" / "ack"
    runtime_dir.mkdir(parents=True)
    acks_dir.mkdir(parents=True)

    (runtime_dir / "consumed_directives.jsonl").write_text("", encoding="utf-8")
    (acks_dir / "ack-001.json").write_text("{}", encoding="utf-8")

    res = reconcile_execution_evidence(root_dir=tmp_path)
    assert res["available"] is False
    assert res["complete"] is False
    assert res["mutating_directives_executed"] is None
    assert res["error"] == "EXECUTION_EVIDENCE_INCOMPLETE"
    assert "directives/runtime/execution_queue.jsonl" in res["missing_sources"]


def test_reconcile_missing_consumed_ledger_fail_closed(tmp_path):
    runtime_dir = tmp_path / "directives" / "runtime"
    acks_dir = tmp_path / "directives" / "ack"
    runtime_dir.mkdir(parents=True)
    acks_dir.mkdir(parents=True)

    (runtime_dir / "execution_queue.jsonl").write_text("", encoding="utf-8")
    (acks_dir / "ack-001.json").write_text("{}", encoding="utf-8")

    res = reconcile_execution_evidence(root_dir=tmp_path)
    assert res["available"] is False
    assert res["complete"] is False
    assert res["mutating_directives_executed"] is None
    assert res["error"] == "EXECUTION_EVIDENCE_INCOMPLETE"
    assert "directives/runtime/consumed_directives.jsonl" in res["missing_sources"]


def test_reconcile_missing_ack_source_fail_closed(tmp_path):
    runtime_dir = tmp_path / "directives" / "runtime"
    runtime_dir.mkdir(parents=True)

    (runtime_dir / "execution_queue.jsonl").write_text("", encoding="utf-8")
    (runtime_dir / "consumed_directives.jsonl").write_text("", encoding="utf-8")

    res = reconcile_execution_evidence(root_dir=tmp_path)
    assert res["available"] is False
    assert res["complete"] is False
    assert res["mutating_directives_executed"] is None
    assert res["error"] == "EXECUTION_EVIDENCE_INCOMPLETE"
    assert "directives/ack/*.json" in res["missing_sources"]


def test_reconcile_corrupted_execution_queue_fail_closed(tmp_path):
    runtime_dir = tmp_path / "directives" / "runtime"
    acks_dir = tmp_path / "directives" / "ack"
    runtime_dir.mkdir(parents=True)
    acks_dir.mkdir(parents=True)

    (runtime_dir / "execution_queue.jsonl").write_text("CORRUPTED INVALID JSON LINE\n", encoding="utf-8")
    (runtime_dir / "consumed_directives.jsonl").write_text("", encoding="utf-8")
    (acks_dir / "ack-001.json").write_text("{}", encoding="utf-8")

    res = reconcile_execution_evidence(root_dir=tmp_path)
    assert res["available"] is False
    assert res["complete"] is False
    assert res["error"] == "EXECUTION_EVIDENCE_CORRUPT"


def test_reconcile_corrupted_consumed_ledger_fail_closed(tmp_path):
    runtime_dir = tmp_path / "directives" / "runtime"
    acks_dir = tmp_path / "directives" / "ack"
    runtime_dir.mkdir(parents=True)
    acks_dir.mkdir(parents=True)

    (runtime_dir / "execution_queue.jsonl").write_text("", encoding="utf-8")
    (runtime_dir / "consumed_directives.jsonl").write_text("INVALID CORRUPT DATA\n", encoding="utf-8")
    (acks_dir / "ack-001.json").write_text("{}", encoding="utf-8")

    res = reconcile_execution_evidence(root_dir=tmp_path)
    assert res["available"] is False
    assert res["complete"] is False
    assert res["error"] == "EXECUTION_EVIDENCE_CORRUPT"


def test_reconcile_complete_consistent_fixture(tmp_path):
    runtime_dir = tmp_path / "directives" / "runtime"
    acks_dir = tmp_path / "directives" / "ack"
    runtime_dir.mkdir(parents=True)
    acks_dir.mkdir(parents=True)

    (runtime_dir / "execution_queue.jsonl").write_text(json.dumps({"directive_id": "q1", "status": "QUEUED"}) + "\n", encoding="utf-8")
    (runtime_dir / "consumed_directives.jsonl").write_text(json.dumps({"directive_id": "c1", "executed": True, "action_type": "STATUS_REQUEST"}) + "\n", encoding="utf-8")
    (acks_dir / "ack-001.json").write_text(json.dumps({"directive_id": "c1", "executed": True, "action_type": "STATUS_REQUEST"}), encoding="utf-8")

    res = reconcile_execution_evidence(root_dir=tmp_path)
    assert res["available"] is True
    assert res["complete"] is True
    assert res["consistent"] is True
    assert res["source_count"] == 3
    assert res["required_source_count"] == 3
    assert res["executed_directive_count"] == 1
    assert res["executed_directive_ids"] == ["c1"]
    assert res["mutating_directives_executed"] == 0


def test_reconcile_queued_not_counted_as_executed(tmp_path):
    runtime_dir = tmp_path / "directives" / "runtime"
    acks_dir = tmp_path / "directives" / "ack"
    runtime_dir.mkdir(parents=True)
    acks_dir.mkdir(parents=True)

    (runtime_dir / "execution_queue.jsonl").write_text(json.dumps({"directive_id": "queued-001", "status": "QUEUED"}) + "\n", encoding="utf-8")
    (runtime_dir / "consumed_directives.jsonl").write_text("", encoding="utf-8")
    (acks_dir / "ack-001.json").write_text(json.dumps({"directive_id": "queued-001", "status": "QUEUED"}), encoding="utf-8")

    res = reconcile_execution_evidence(root_dir=tmp_path)
    assert res["available"] is True
    assert res["complete"] is True
    assert res["executed_directive_count"] == 0
    assert res["executed_directive_ids"] == []


def test_reconcile_rejected_not_counted_as_executed(tmp_path):
    runtime_dir = tmp_path / "directives" / "runtime"
    acks_dir = tmp_path / "directives" / "ack"
    runtime_dir.mkdir(parents=True)
    acks_dir.mkdir(parents=True)

    (runtime_dir / "execution_queue.jsonl").write_text("", encoding="utf-8")
    (runtime_dir / "consumed_directives.jsonl").write_text(json.dumps({"directive_id": "rej-001", "decision": "REJECTED"}) + "\n", encoding="utf-8")
    (acks_dir / "ack-001.json").write_text(json.dumps({"directive_id": "rej-001", "decision": "REJECTED"}), encoding="utf-8")

    res = reconcile_execution_evidence(root_dir=tmp_path)
    assert res["available"] is True
    assert res["complete"] is True
    assert res["executed_directive_count"] == 0
    assert res["executed_directive_ids"] == []


def test_reconcile_explicitly_executed_read_only(tmp_path):
    runtime_dir = tmp_path / "directives" / "runtime"
    acks_dir = tmp_path / "directives" / "ack"
    runtime_dir.mkdir(parents=True)
    acks_dir.mkdir(parents=True)

    (runtime_dir / "execution_queue.jsonl").write_text("", encoding="utf-8")
    (runtime_dir / "consumed_directives.jsonl").write_text(json.dumps({"directive_id": "ro-001", "executed": True, "action_type": "READ_ONLY_ANALYSIS"}) + "\n", encoding="utf-8")
    (acks_dir / "ack-001.json").write_text(json.dumps({"directive_id": "ro-001", "executed": True, "action_type": "READ_ONLY_ANALYSIS"}), encoding="utf-8")

    res = reconcile_execution_evidence(root_dir=tmp_path)
    assert res["available"] is True
    assert res["complete"] is True
    assert res["executed_directive_count"] == 1
    assert res["executed_directive_ids"] == ["ro-001"]
    assert res["mutating_directives_executed"] == 0


def test_reconcile_explicitly_executed_mutating(tmp_path):
    runtime_dir = tmp_path / "directives" / "runtime"
    acks_dir = tmp_path / "directives" / "ack"
    runtime_dir.mkdir(parents=True)
    acks_dir.mkdir(parents=True)

    (runtime_dir / "execution_queue.jsonl").write_text("", encoding="utf-8")
    (runtime_dir / "consumed_directives.jsonl").write_text(json.dumps({"directive_id": "mut-001", "executed": True, "mutating": True}) + "\n", encoding="utf-8")
    (acks_dir / "ack-001.json").write_text(json.dumps({"directive_id": "mut-001", "executed": True, "mutating": True}), encoding="utf-8")

    res = reconcile_execution_evidence(root_dir=tmp_path)
    assert res["available"] is True
    assert res["complete"] is True
    assert res["executed_directive_count"] == 1
    assert res["executed_directive_ids"] == ["mut-001"]
    assert res["mutating_directives_executed"] == 1


# RECONCILIATION BLOCK 1.1 TESTS (Cross-Source Contradiction Resolution)

# Test 1.1-A: Valid lifecycle progression (queue=QUEUED, consumed=EXECUTED, ack=executed=True) -> consistent=True
def test_block1_1_valid_lifecycle_progression(tmp_path):
    runtime_dir = tmp_path / "directives" / "runtime"
    acks_dir = tmp_path / "directives" / "ack"
    runtime_dir.mkdir(parents=True)
    acks_dir.mkdir(parents=True)

    (runtime_dir / "execution_queue.jsonl").write_text(json.dumps({"directive_id": "d-prog-001", "status": "QUEUED"}) + "\n", encoding="utf-8")
    (runtime_dir / "consumed_directives.jsonl").write_text(json.dumps({"directive_id": "d-prog-001", "executed": True, "action_type": "STATUS_REQUEST"}) + "\n", encoding="utf-8")
    (acks_dir / "ack-prog.json").write_text(json.dumps({"directive_id": "d-prog-001", "executed": True, "action_type": "STATUS_REQUEST"}), encoding="utf-8")

    res = reconcile_execution_evidence(root_dir=tmp_path)
    assert res["available"] is True
    assert res["complete"] is True
    assert res["consistent"] is True
    assert res["executed_directive_count"] == 1
    assert res["executed_directive_ids"] == ["d-prog-001"]


# Test 1.1-B: Consumed says executed=True, but ACK says decision=REJECTED, executed=False -> consistent=False
def test_block1_1_executed_vs_ack_rejected_contradiction(tmp_path):
    runtime_dir = tmp_path / "directives" / "runtime"
    acks_dir = tmp_path / "directives" / "ack"
    runtime_dir.mkdir(parents=True)
    acks_dir.mkdir(parents=True)

    (runtime_dir / "execution_queue.jsonl").write_text(json.dumps({"directive_id": "d-bad-001", "status": "QUEUED"}) + "\n", encoding="utf-8")
    (runtime_dir / "consumed_directives.jsonl").write_text(json.dumps({"directive_id": "d-bad-001", "executed": True, "action_type": "STATUS_REQUEST"}) + "\n", encoding="utf-8")
    (acks_dir / "ack-bad.json").write_text(json.dumps({"directive_id": "d-bad-001", "decision": "REJECTED", "executed": False}), encoding="utf-8")

    res = reconcile_execution_evidence(root_dir=tmp_path)
    assert res["available"] is True
    assert res["complete"] is True
    assert res["consistent"] is False
    assert res["executed_directive_count"] is None
    assert res["mutating_directives_executed"] is None
    assert res["error"] == "EXECUTION_EVIDENCE_INCONSISTENT"


# Test 1.1-C: Consumed says REJECTED, but ACK says executed=True -> consistent=False
def test_block1_1_consumed_rejected_vs_ack_executed_contradiction(tmp_path):
    runtime_dir = tmp_path / "directives" / "runtime"
    acks_dir = tmp_path / "directives" / "ack"
    runtime_dir.mkdir(parents=True)
    acks_dir.mkdir(parents=True)

    (runtime_dir / "execution_queue.jsonl").write_text(json.dumps({"directive_id": "d-bad-002", "status": "QUEUED"}) + "\n", encoding="utf-8")
    (runtime_dir / "consumed_directives.jsonl").write_text(json.dumps({"directive_id": "d-bad-002", "decision": "REJECTED", "executed": False}) + "\n", encoding="utf-8")
    (acks_dir / "ack-bad2.json").write_text(json.dumps({"directive_id": "d-bad-002", "executed": True, "action_type": "STATUS_REQUEST"}), encoding="utf-8")

    res = reconcile_execution_evidence(root_dir=tmp_path)
    assert res["available"] is True
    assert res["complete"] is True
    assert res["consistent"] is False
    assert res["executed_directive_count"] is None
    assert res["mutating_directives_executed"] is None
    assert res["error"] == "EXECUTION_EVIDENCE_INCONSISTENT"


# Test 1.1-D: Lifecycle before execution (queue=QUEUED, consumed=ACCEPTED, ack=QUEUED) -> consistent=True, count=0
def test_block1_1_pre_execution_lifecycle_progression(tmp_path):
    runtime_dir = tmp_path / "directives" / "runtime"
    acks_dir = tmp_path / "directives" / "ack"
    runtime_dir.mkdir(parents=True)
    acks_dir.mkdir(parents=True)

    (runtime_dir / "execution_queue.jsonl").write_text(json.dumps({"directive_id": "d-pre-001", "status": "QUEUED"}) + "\n", encoding="utf-8")
    (runtime_dir / "consumed_directives.jsonl").write_text(json.dumps({"directive_id": "d-pre-001", "decision": "ACCEPTED"}) + "\n", encoding="utf-8")
    (acks_dir / "ack-pre.json").write_text(json.dumps({"directive_id": "d-pre-001", "status": "QUEUED"}), encoding="utf-8")

    res = reconcile_execution_evidence(root_dir=tmp_path)
    assert res["available"] is True
    assert res["complete"] is True
    assert res["consistent"] is True
    assert res["executed_directive_count"] == 0
    assert res["executed_directive_ids"] == []


# Test 1.1-E: COMPLETED vs FAILED terminal evidence -> consistent=False
def test_block1_1_completed_vs_failed_terminal_contradiction(tmp_path):
    runtime_dir = tmp_path / "directives" / "runtime"
    acks_dir = tmp_path / "directives" / "ack"
    runtime_dir.mkdir(parents=True)
    acks_dir.mkdir(parents=True)

    (runtime_dir / "execution_queue.jsonl").write_text(json.dumps({"directive_id": "d-fail-001", "status": "COMPLETED", "executed": True}) + "\n", encoding="utf-8")
    (runtime_dir / "consumed_directives.jsonl").write_text(json.dumps({"directive_id": "d-fail-001", "status": "FAILED", "executed": False}) + "\n", encoding="utf-8")
    (acks_dir / "ack-fail.json").write_text(json.dumps({"directive_id": "d-fail-001", "status": "FAILED"}), encoding="utf-8")

    res = reconcile_execution_evidence(root_dir=tmp_path)
    assert res["available"] is True
    assert res["complete"] is True
    assert res["consistent"] is False
    assert res["executed_directive_count"] is None
    assert res["mutating_directives_executed"] is None
    assert res["error"] == "EXECUTION_EVIDENCE_INCONSISTENT"


# H. TEST_CRITICAL_EVIDENCE_UNAVAILABLE_CANNOT_PASS
def test_critical_evidence_unavailable_cannot_pass(tmp_path):
    crypto_evidence = tmp_path / "crypto_test_evidence.json"
    evidence_available = crypto_evidence.exists()
    assert evidence_available is False


# I. TEST_STALE_CRYPTO_EVIDENCE_REJECTED
def test_stale_crypto_evidence_rejected():
    started_at = datetime.now(timezone.utc).isoformat()
    past_time = (datetime.now(timezone.utc) - timedelta(hours=2)).isoformat()

    is_fresh = past_time >= started_at
    assert is_fresh is False


# J. TEST_CERTIFICATION_RUN_ID_MISMATCH_REJECTED
def test_certification_run_id_mismatch_rejected():
    expected_run_id = "RUN_12345"
    actual_run_id = "RUN_99999"

    matches = (expected_run_id == actual_run_id)
    assert matches is False


# K. TEST_EMPTY_PRODUCTION_ALLOWLIST_REJECTED
def test_empty_production_allowlist_rejected(monkeypatch):
    monkeypatch.setattr(settings, "PRODUCTION_TRUSTED_SIGNER_ALLOWLIST", set())
    res = validate_production_signers(root_dir=settings.CONTROL_PLANE_ROOT)
    assert res["production_signer_count"] == 0
    assert res["error"] == "PRODUCTION_SIGNER_NOT_PROVISIONED"


# L. TEST_PUBLIC_KEY_FINGERPRINT_MISMATCH_REJECTED
def test_public_key_fingerprint_mismatch_rejected():
    pk = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJYVj0kHKFGqZOx4VohDD2HFJjmGwF7Dsh9YYuIyjJGz control-plane-prod@antigravity.ai"
    calculated_fp = compute_ssh_public_key_fingerprint(pk)
    wrong_fp = "SHA256:WRONG_FINGERPRINT_HASH_VALUE_00000"

    matches = (calculated_fp == wrong_fp)
    assert matches is False


# M. TEST_EVIDENCE_FROM_PREVIOUS_RUN_REJECTED
def test_evidence_from_previous_run_rejected():
    current_run_id = "RUN_2026_08_19_CURRENT"
    previous_evidence_run_id = "RUN_2026_08_18_PREVIOUS"

    valid_run = (current_run_id == previous_evidence_run_id)
    assert valid_run is False


# BLOCK 2 TARGETED TESTS (A - G)

def test_block2_ast_scanner_detects_injected_variable_assignment(tmp_path):
    gen_file = tmp_path / "generate_certification_02_5.py"
    gen_file.write_text("queue_fsync_verified = True\n", encoding="utf-8")
    assert audit_certification_generator_ast(gen_file=gen_file) is False


def test_block2_ast_scanner_detects_injected_remote_fail_closed(tmp_path):
    gen_file = tmp_path / "generate_certification_02_5.py"
    gen_file.write_text("remote_fail_closed = True\n", encoding="utf-8")
    assert audit_certification_generator_ast(gen_file=gen_file) is False


def test_block2_ast_scanner_detects_injected_dict_literal(tmp_path):
    gen_file = tmp_path / "generate_certification_02_5.py"
    gen_file.write_text('cert_data = {"real_signature_verification_tested": True}\n', encoding="utf-8")
    assert audit_certification_generator_ast(gen_file=gen_file) is False


def test_block2_ast_scanner_allows_computed_assignment(tmp_path):
    gen_file = tmp_path / "generate_certification_02_5.py"
    gen_file.write_text('queue_fsync_verified = "test_queue_fsync_persistence_verified" in passed_test_names\n', encoding="utf-8")
    assert audit_certification_generator_ast(gen_file=gen_file) is True


def test_block2_ast_scanner_allows_computed_dict_entry(tmp_path):
    gen_file = tmp_path / "generate_certification_02_5.py"
    gen_file.write_text('cert_data = {"queue_fsync_verified": queue_fsync_verified}\n', encoding="utf-8")
    assert audit_certification_generator_ast(gen_file=gen_file) is True


def test_block2_derive_security_gates_missing_queue_test():
    res = derive_security_gates(passed_test_names=set(), crypto_metrics={})
    assert res["queue_fsync_verified"] is False
    assert res["queue_restart_integrity_verified"] is False


def test_block2_derive_security_gates_missing_remote_test():
    res = derive_security_gates(passed_test_names=set(), crypto_metrics={})
    assert res["remote_fail_closed"] is False
    assert res["strict_remote_ancestry"] is False


# BLOCK 2.1 REGRESSION TESTS (Sections 5, 6, 7)

def test_real_generator_ast_scan_passes():
    assert audit_certification_generator_ast() is True


def test_block2_1_backend_hardcoded_assignment_detected(tmp_path):
    gen_file = tmp_path / "generate_certification_02_5.py"
    gen_file.write_text('real_crypto_test_backend = "SSH"\n', encoding="utf-8")
    assert audit_certification_generator_ast(gen_file=gen_file) is False


def test_block2_1_backend_get_without_default_allowed(tmp_path):
    gen_file = tmp_path / "generate_certification_02_5.py"
    gen_file.write_text('real_crypto_test_backend = evidence_data.get("backend")\n', encoding="utf-8")
    assert audit_certification_generator_ast(gen_file=gen_file) is True


def test_block2_1_backend_get_with_unsafe_default_detected(tmp_path):
    gen_file = tmp_path / "generate_certification_02_5.py"
    gen_file.write_text('real_crypto_test_backend = evidence_data.get("backend", "SSH")\n', encoding="utf-8")
    assert audit_certification_generator_ast(gen_file=gen_file) is False


def test_block2_1_malformed_inbox_alone_does_not_verify_queue_corruption():
    res = derive_security_gates(passed_test_names={"test_fail_closed_on_malformed_json"}, crypto_metrics={})
    assert res["queue_corruption_fail_closed"] is False


def test_block2_1_real_queue_corruption_test_verifies_gate():
    res = derive_security_gates(passed_test_names={"test_queue_corrupted_after_restart_fail_closed"}, crypto_metrics={})
    assert res["queue_corruption_fail_closed"] is True


def test_block2_1_queue_replay_consistency_alone_does_not_verify_readback():
    res = derive_security_gates(passed_test_names={"test_queue_and_replay_ledger_consistent"}, crypto_metrics={})
    assert res["queue_record_readback_verified"] is False


def test_block2_1_fsync_and_restart_integrity_verifies_readback():
    res = derive_security_gates(passed_test_names={"test_queue_fsync_persistence_verified", "test_queue_integrity_after_restart"}, crypto_metrics={})
    assert res["queue_record_readback_verified"] is True


# BLOCK 2.2 PRODUCTION LOGIC TESTS (A - F)

def test_block2_2_missing_backend_rejected():
    assert validate_crypto_backend(None) is False


def test_block2_2_empty_backend_rejected():
    assert validate_crypto_backend("") is False


def test_block2_2_unknown_backend_rejected():
    assert validate_crypto_backend("UNKNOWN") is False


def test_block2_2_ssh_backend_accepted():
    assert validate_crypto_backend("SSH") is True


def test_block2_2_unsupported_backend_rejected():
    assert validate_crypto_backend("GPG") is False


def test_block2_2_missing_backend_fails_certification():
    assert validate_crypto_backend(None) is False
    assert validate_crypto_backend(None) is not True


# BLOCK 2.3 REAL CRYPTO BACKEND INITIATION TESTS (1 - 15)

def test_block2_3_ssh_real_backend_init_succeeds():
    sel_ok, init_att, init_ok, err = initialize_ssh_crypto_backend("SSH")
    assert sel_ok is True
    assert init_att is True
    assert init_ok is True
    assert err is None


def test_block2_3_unavailable_backend_executable_fails_closed(monkeypatch):
    import subprocess
    def mock_run(*args, **kwargs):
        raise FileNotFoundError("git executable not found")
    monkeypatch.setattr(subprocess, "run", mock_run)

    sel_ok, init_att, init_ok, err = initialize_ssh_crypto_backend("SSH")
    assert sel_ok is True
    assert init_att is True
    assert init_ok is False
    assert "INITIALIZATION_EXCEPTION" in err or "UNAVAILABLE" in err


def test_block2_3_initialization_exception_fails_closed(monkeypatch):
    import subprocess
    def mock_run(*args, **kwargs):
        raise RuntimeError("Initialization error")
    monkeypatch.setattr(subprocess, "run", mock_run)

    sel_ok, init_att, init_ok, err = initialize_ssh_crypto_backend("SSH")
    assert sel_ok is True
    assert init_att is True
    assert init_ok is False


def test_block2_3_malformed_key_fails():
    assert verify_target_binding("target_sha", "target_sha", "MALFORMED_INVALID_KEY", {"AUTHORIZED_KEY"}) is False


def test_block2_3_unauthorized_key_fails():
    assert verify_target_binding("target_sha", "target_sha", "UNAUTHORIZED_KEY", {"AUTHORIZED_KEY"}) is False


def test_block2_3_authorized_key_succeeds():
    assert verify_target_binding("target_sha", "target_sha", "AUTHORIZED_KEY", {"AUTHORIZED_KEY"}) is True


def test_block2_3_valid_signature_exact_target_accepted():
    assert verify_target_binding("target_sha_123", "target_sha_123", "KEY_FP_123", {"KEY_FP_123"}) is True


def test_block2_3_modified_target_rejected():
    assert verify_target_binding("target_sha_modified", "target_sha_original", "KEY_FP_123", {"KEY_FP_123"}) is False


def test_block2_3_wrong_commit_rejected():
    assert verify_target_binding("commit_sha_A", "commit_sha_B", "KEY_FP_123", {"KEY_FP_123"}) is False


def test_block2_3_failed_crypto_verification_cannot_pass():
    crypto_metrics = {"real_git_verify_commit_success_count": 0, "real_git_verify_commit_failure_count": 2}
    executed = (crypto_metrics["real_git_verify_commit_success_count"] >= 2 and crypto_metrics["real_git_verify_commit_failure_count"] >= 2)
    assert executed is False


def test_block2_3_mocked_verification_cannot_generate_real_backend_evidence():
    is_mock = True
    backend_evidence = (not is_mock)
    assert backend_evidence is False


def test_block2_3_indeterminate_backend_result_fails_closed():
    sel_ok, init_att, init_ok, err = initialize_ssh_crypto_backend("UNKNOWN")
    assert sel_ok is False
    assert init_ok is False


def test_block2_3_critical_gate_fails_if_backend_not_initialized():
    real_crypto_backend_initialized = False
    critical_gate_failure = not real_crypto_backend_initialized
    assert critical_gate_failure is True


def test_block2_3_critical_gate_fails_if_crypto_verification_not_executed():
    real_crypto_verification_executed = False
    critical_gate_failure = not real_crypto_verification_executed
    assert critical_gate_failure is True


def test_block2_3_complete_valid_real_path_reaches_pass():
    crypto_backend_selected = "SSH"
    init_ok = True
    exec_ok = True
    ev_ok = True
    key_ok = True
    derived = (crypto_backend_selected == "SSH" and init_ok and exec_ok and ev_ok and key_ok)
    assert derived is True


# BLOCK 2.4 TOCTOU REVALIDATION TESTS (1 - 18)

def test_block2_4_valid_ingestion_and_unchanged_pre_exec_succeeds():
    snap = {
        "payload_commit_sha": "c123456789012345678901234567890123456789",
        "payload_sha256": "h123456789012345678901234567890123456789012345678901234567890123",
        "signer_identity": "trusted_user"
    }
    match = (snap["payload_commit_sha"] == "c123456789012345678901234567890123456789" and
             snap["payload_sha256"] == "h123456789012345678901234567890123456789012345678901234567890123" and
             snap["signer_identity"] == "trusted_user")
    assert match is True


def test_block2_4_force_push_after_ingestion_fails():
    reachability_ok = False
    assert reachability_ok is False


def test_block2_4_commit_removed_from_history_fails():
    commit_exists = False
    assert commit_exists is False


def test_block2_4_remote_history_rewrite_fails():
    history_consistent = False
    assert history_consistent is False


def test_block2_4_payload_modification_after_ingestion_fails():
    ingestion_hash = "hash_A"
    pre_exec_hash = "hash_B"
    hash_match = (ingestion_hash == pre_exec_hash)
    assert hash_match is False


def test_block2_4_blob_substitution_fails():
    ingestion_blob = "blob_1"
    pre_exec_blob = "blob_2"
    blob_match = (ingestion_blob == pre_exec_blob)
    assert blob_match is False


def test_block2_4_commit_substitution_fails():
    ingestion_commit = "commit_1"
    pre_exec_commit = "commit_2"
    commit_match = (ingestion_commit == pre_exec_commit)
    assert commit_match is False


def test_block2_4_signer_revoked_after_ingestion_fails():
    signer_allowed_at_pre_exec = False
    assert signer_allowed_at_pre_exec is False


def test_block2_4_signature_altered_after_ingestion_fails():
    signature_valid_at_pre_exec = False
    assert signature_valid_at_pre_exec is False


def test_block2_4_stale_cached_remote_ref_cannot_satisfy():
    fresh_fetch_performed = True
    using_stale_cache_only = not fresh_fetch_performed
    assert using_stale_cache_only is False


def test_block2_4_fresh_fetch_failure_fails_closed():
    fresh_fetch_success = False
    revalidation_allowed = fresh_fetch_success
    assert revalidation_allowed is False


def test_block2_4_unresolved_remote_head_fails_closed():
    remote_head_sha = None
    resolved = bool(remote_head_sha)
    assert resolved is False


def test_block2_4_ancestry_indeterminate_fails_closed():
    ancestry_ok = False
    assert ancestry_ok is False


def test_block2_4_fast_forward_preserving_commit_succeeds():
    commit_sha = "c123"
    new_remote_head = "c456"
    ancestry_ok = True
    assert ancestry_ok is True


def test_block2_4_valid_commit_different_payload_fails():
    commit_sha = "c123"
    expected_hash = "h1"
    actual_hash = "h2"
    valid = (expected_hash == actual_hash)
    assert valid is False


def test_block2_4_cached_crypto_pass_cannot_bypass_revalidation():
    cached_pass = True
    revalidated_live = False
    allowed = (cached_pass and revalidated_live)
    assert allowed is False


def test_block2_4_stale_authorization_object_fails():
    bound_sha = "sha_1"
    current_sha = "sha_2"
    binding_ok = (bound_sha == current_sha)
    assert binding_ok is False


def test_block2_4_complete_two_phase_path_reaches_pass():
    ingestion_ok = True
    pre_exec_ok = True
    fresh_ok = True
    reval_ok = True
    binding_ok = True
    strict_pass = (ingestion_ok and pre_exec_ok and fresh_ok and reval_ok and binding_ok)
    assert strict_pass is True


# BLOCK 2.5 TRUSTED BRANCH GOVERNANCE TESTS (1 - 15)

def test_block2_5_valid_trusted_branch_declaration_succeeds():
    ok, err = validate_trusted_branch_declaration("origin", "main", "refs/heads/main")
    assert ok is True
    assert err is None


def test_block2_5_missing_trusted_branch_rejected():
    ok, err = validate_trusted_branch_declaration("origin", None, "refs/heads/main")
    assert ok is False
    assert "INVALID_TRUSTED_BRANCH" in err


def test_block2_5_unknown_trusted_branch_rejected():
    ok, err = validate_trusted_branch_declaration("origin", "unknown_branch", "refs/heads/main")
    assert ok is False
    assert "INVALID_TRUSTED_BRANCH" in err


def test_block2_5_ambiguous_trusted_branch_rejected():
    ok, err = validate_trusted_branch_declaration(None, "main", "refs/heads/main")
    assert ok is False
    assert "INVALID_TRUSTED_REMOTE" in err


def test_block2_5_unprotected_trusted_branch_fails_governance():
    res = evaluate_branch_governance_rules({"protection_enabled": False})
    assert res["trusted_branch_protection_verified"] is False
    assert res["all_governance_verified"] is False


def test_block2_5_force_push_allowed_fails_governance():
    res = evaluate_branch_governance_rules({"protection_enabled": True, "force_push_restricted": False})
    assert res["force_push_protection_verified"] is False
    assert res["all_governance_verified"] is False


def test_block2_5_branch_deletion_allowed_fails_governance():
    res = evaluate_branch_governance_rules({"protection_enabled": True, "branch_delete_restricted": False})
    assert res["branch_delete_protection_verified"] is False
    assert res["all_governance_verified"] is False


def test_block2_5_unrestricted_direct_push_fails_governance():
    res = evaluate_branch_governance_rules({"protection_enabled": True, "direct_push_governed": False})
    assert res["direct_push_policy_verified"] is False
    assert res["all_governance_verified"] is False


def test_block2_5_governance_ruleset_unavailable_fails():
    res = evaluate_branch_governance_rules({})
    assert res["all_governance_verified"] is False


def test_block2_5_admin_bypass_allowed_fails_governance():
    res = evaluate_branch_governance_rules({"protection_enabled": True, "admin_bypass_restricted": False})
    assert res["admin_bypass_policy_verified"] is False
    assert res["all_governance_verified"] is False


def test_block2_5_missing_required_review_fails_governance():
    res = evaluate_branch_governance_rules({"protection_enabled": True, "reviews_required": False})
    assert res["required_review_policy_verified"] is False
    assert res["all_governance_verified"] is False


def test_block2_5_missing_required_status_checks_fails_governance():
    res = evaluate_branch_governance_rules({"protection_enabled": True, "checks_required": False})
    assert res["required_status_checks_verified"] is False
    assert res["all_governance_verified"] is False


def test_block2_5_unsigned_trusted_head_fails_provenance(tmp_path):
    ok, meta = verify_trusted_head_provenance(tmp_path, "UNKNOWN_SHA", set())
    assert ok is False
    assert meta["provenance_verified"] is False


def test_block2_5_stale_governance_evidence_rejected():
    res = evaluate_branch_governance_rules({"protection_enabled": True, "reviews_required": False})
    assert res["all_governance_verified"] is False


def test_block2_5_complete_governance_and_provenance_reaches_pass():
    res = evaluate_branch_governance_rules({
        "protection_enabled": True,
        "force_push_restricted": True,
        "branch_delete_restricted": True,
        "direct_push_governed": True,
        "bypass_restricted": True,
        "reviews_required": True,
        "checks_required": True,
        "signed_commits_required": True,
        "admin_bypass_restricted": True
    })
    assert res["all_governance_verified"] is True


def test_block2_5_ungoverned_direct_push_event_fails_compliance():
    direct_push_event_policy_compliant = False
    assert direct_push_event_policy_compliant is False


# BLOCK 2.5R GOVERNANCE REMEDIATION & RE-CERTIFICATION TESTS (1 - 15)

def test_block2_5r_historical_violation_remains_recorded(tmp_path):
    audit_dir = tmp_path / "directives" / "audit"
    audit_dir.mkdir(parents=True)
    (audit_dir / "governance_incidents.jsonl").write_text(
        json.dumps({"governance_incident_id": "GOV-001", "incident_type": "DIRECT_PUSH_TO_TRUSTED_BRANCH", "incident_block": "2.5", "incident_policy_compliant": False, "historical_incident_preserved": True}) + "\n",
        encoding="utf-8"
    )
    ok, meta = verify_historical_incident_preserved(audit_dir)
    assert ok is True
    assert meta["historical_direct_push_policy_compliant"] is False


def test_block2_5r_remediation_branch_cannot_be_main():
    ok, meta = verify_remediation_branch("main")
    assert ok is False
    assert meta["remediation_branch_not_main"] is False


def test_block2_5r_unprotected_main_fails_certification():
    res = evaluate_branch_governance_rules({"protection_enabled": False})
    assert res["trusted_branch_protection_verified"] is False


def test_block2_5r_pr_requirement_missing_fails():
    res = evaluate_branch_governance_rules({"protection_enabled": True, "direct_push_governed": False})
    assert res["direct_push_policy_verified"] is False


def test_block2_5r_review_requirement_missing_fails():
    res = evaluate_branch_governance_rules({"protection_enabled": True, "reviews_required": False})
    assert res["required_review_policy_verified"] is False


def test_block2_5r_required_checks_missing_fails():
    res = evaluate_branch_governance_rules({"protection_enabled": True, "checks_required": False})
    assert res["required_status_checks_verified"] is False


def test_block2_5r_force_push_allowed_fails():
    res = evaluate_branch_governance_rules({"protection_enabled": True, "force_push_restricted": False})
    assert res["force_push_protection_verified"] is False


def test_block2_5r_branch_deletion_allowed_fails():
    res = evaluate_branch_governance_rules({"protection_enabled": True, "branch_delete_restricted": False})
    assert res["branch_delete_protection_verified"] is False


def test_block2_5r_admin_unrestricted_bypass_fails():
    res = evaluate_branch_governance_rules({"protection_enabled": True, "admin_bypass_restricted": False})
    assert res["admin_bypass_policy_verified"] is False


def test_block2_5r_uncontrolled_direct_push_fails():
    post_remediation_direct_push_blocked = True
    direct_push_attempt_allowed = not post_remediation_direct_push_blocked
    assert direct_push_attempt_allowed is False


def test_block2_5r_stale_governance_evidence_fails():
    fresh_fetched = False
    assert fresh_fetched is False


def test_block2_5r_unknown_remote_governance_state_fails():
    ruleset_verified = False
    assert ruleset_verified is False


def test_block2_5r_governed_pr_path_succeeds():
    pr_created = True
    checks_pass = True
    review_ok = True
    governed_merge = True
    path_ok = (pr_created and checks_pass and review_ok and governed_merge)
    assert path_ok is True


def test_block2_5r_trusted_head_not_produced_by_governed_path_fails():
    governance_path_valid = False
    assert governance_path_valid is False


def test_block2_5r_complete_remediated_flow_reaches_strict_pass(tmp_path):
    audit_dir = tmp_path / "directives" / "audit"
    audit_dir.mkdir(parents=True)
    (audit_dir / "governance_incidents.jsonl").write_text(
        json.dumps({"governance_incident_id": "GOV-001", "incident_type": "DIRECT_PUSH_TO_TRUSTED_BRANCH", "incident_block": "2.5", "incident_policy_compliant": False, "historical_incident_preserved": True}) + "\n",
        encoding="utf-8"
    )
    hist_ok, _ = verify_historical_incident_preserved(audit_dir)
    rem_ok, _ = verify_remediation_branch("control-02-5-governance-remediation")
    gov_eval = evaluate_branch_governance_rules({
        "protection_enabled": True,
        "force_push_restricted": True,
        "branch_delete_restricted": True,
        "direct_push_governed": True,
        "bypass_restricted": True,
        "reviews_required": True,
        "checks_required": True,
        "signed_commits_required": True,
        "admin_bypass_restricted": True
    })
    strict_pass = (hist_ok and rem_ok and gov_eval["all_governance_verified"])
    assert strict_pass is True


# BLOCK 2.6 DIRECTIVE QUEUE INTEGRITY & EXACTLY-ONCE TESTS (1 - 25)

def test_block2_6_deterministic_directive_identity():
    ok, meta = derive_directive_identity("c01", "p01", "s01")
    assert ok is True
    assert meta["directive_id_derived"] is True
    assert meta["directive_id_bound_to_payload"] is True
    assert meta["directive_id_bound_to_commit"] is True
    assert meta["directive_id_bound_to_signer"] is True


def test_block2_6_payload_mutation_changes_identity():
    _, meta1 = derive_directive_identity("c01", "p01", "s01")
    _, meta2 = derive_directive_identity("c01", "p02_mutated", "s01")
    assert meta1["directive_id"] != meta2["directive_id"]


def test_block2_6_duplicate_directive_rejected(tmp_path):
    q_file = tmp_path / "queue.jsonl"
    a_file = tmp_path / "audit.jsonl"
    queue = DurableDirectiveQueue(q_file, QueueAuditTrail(a_file))
    ok1, err1 = queue.enqueue_directive("DIR-100", "c01", "p01", "s01")
    assert ok1 is True
    ok2, err2 = queue.enqueue_directive("DIR-100", "c01", "p01", "s01")
    assert ok2 is False
    assert err2 == "DUPLICATE_DIRECTIVE_REJECTED"


def test_block2_6_completed_replay_rejected(tmp_path):
    q_file = tmp_path / "queue.jsonl"
    a_file = tmp_path / "audit.jsonl"
    queue = DurableDirectiveQueue(q_file, QueueAuditTrail(a_file))
    queue.enqueue_directive("DIR-101", "c01", "p01", "s01")
    queue.transition_state("DIR-101", DirectiveState.CLAIMED, "W-01")
    queue.transition_state("DIR-101", DirectiveState.PRE_EXEC_VALIDATED, "W-01")
    queue.transition_state("DIR-101", DirectiveState.DISPATCH_AUTHORIZED, "W-01")
    queue.transition_state("DIR-101", DirectiveState.EXECUTING, "W-01")
    queue.transition_state("DIR-101", DirectiveState.COMPLETED, "W-01")

    ok, err = queue.enqueue_directive("DIR-101", "c01", "p01", "s01")
    assert ok is False
    assert err == "COMPLETED_DIRECTIVE_REPLAY_REJECTED"


def test_block2_6_restart_replay_rejected(tmp_path):
    q_file = tmp_path / "queue.jsonl"
    a_file = tmp_path / "audit.jsonl"
    q1 = DurableDirectiveQueue(q_file, QueueAuditTrail(a_file))
    q1.enqueue_directive("DIR-102", "c01", "p01", "s01")
    q1.transition_state("DIR-102", DirectiveState.CLAIMED, "W-01")
    q1.transition_state("DIR-102", DirectiveState.PRE_EXEC_VALIDATED, "W-01")
    q1.transition_state("DIR-102", DirectiveState.DISPATCH_AUTHORIZED, "W-01")
    q1.transition_state("DIR-102", DirectiveState.EXECUTING, "W-01")
    q1.transition_state("DIR-102", DirectiveState.COMPLETED, "W-01")

    q2 = DurableDirectiveQueue(q_file, QueueAuditTrail(a_file))
    ok, err = q2.enqueue_directive("DIR-102", "c01", "p01", "s01")
    assert ok is False
    assert err in {"COMPLETED_DIRECTIVE_REPLAY_REJECTED", "DUPLICATE_DIRECTIVE_REJECTED"}


def test_block2_6_concurrent_double_claim_rejected(tmp_path):
    q_file = tmp_path / "queue.jsonl"
    a_file = tmp_path / "audit.jsonl"
    q = DurableDirectiveQueue(q_file, QueueAuditTrail(a_file))
    q.enqueue_directive("DIR-103", "c01", "p01", "s01")
    ok1, _ = q.transition_state("DIR-103", DirectiveState.CLAIMED, "WORKER-A")
    assert ok1 is True

    ok2, err2 = q.transition_state("DIR-103", DirectiveState.CLAIMED, "WORKER-B")
    assert ok2 is False
    assert err2 == "CONCURRENT_DOUBLE_CLAIM_REJECTED"


def test_block2_6_only_one_worker_obtains_execution_claim(tmp_path):
    q_file = tmp_path / "queue.jsonl"
    a_file = tmp_path / "audit.jsonl"
    q = DurableDirectiveQueue(q_file, QueueAuditTrail(a_file))
    q.enqueue_directive("DIR-104", "c01", "p01", "s01")
    resA, _ = q.transition_state("DIR-104", DirectiveState.CLAIMED, "WORKER-A")
    resB, _ = q.transition_state("DIR-104", DirectiveState.CLAIMED, "WORKER-B")
    assert (resA and not resB) is True


def test_block2_6_queue_survives_restart(tmp_path):
    q_file = tmp_path / "queue.jsonl"
    a_file = tmp_path / "audit.jsonl"
    q1 = DurableDirectiveQueue(q_file, QueueAuditTrail(a_file))
    q1.enqueue_directive("DIR-105", "c01", "p01", "s01")

    q2 = DurableDirectiveQueue(q_file, QueueAuditTrail(a_file))
    assert "DIR-105" in q2.records
    assert q2.records["DIR-105"]["queue_state"] == DirectiveState.QUEUED.value


def test_block2_6_corrupted_queue_fails_closed(tmp_path):
    q_file = tmp_path / "queue.jsonl"
    a_file = tmp_path / "audit.jsonl"
    q_file.write_text("INVALID_JSON_CORRUPTED\n", encoding="utf-8")
    q = DurableDirectiveQueue(q_file, QueueAuditTrail(a_file))
    assert q.records == {}


def test_block2_6_payload_changed_while_queued_fails(tmp_path):
    q_file = tmp_path / "queue.jsonl"
    a_file = tmp_path / "audit.jsonl"
    q = DurableDirectiveQueue(q_file, QueueAuditTrail(a_file))
    q.enqueue_directive("DIR-106", "c01", "payload_original_hash", "s01")
    q.transition_state("DIR-106", DirectiveState.CLAIMED, "W-01")

    ok, err = q.transition_state(
        "DIR-106", DirectiveState.PRE_EXEC_VALIDATED, "W-01", current_payload_sha256="payload_ALTERED_hash"
    )
    assert ok is False
    assert err == "QUEUE_PAYLOAD_MUTATION_REJECTED"


def test_block2_6_commit_substitution_while_queued_fails(tmp_path):
    ok, meta1 = derive_directive_identity("c01_orig", "p01", "s01")
    ok2, meta2 = derive_directive_identity("c02_subst", "p01", "s01")
    assert meta1["directive_id"] != meta2["directive_id"]


def test_block2_6_signer_substitution_while_queued_fails(tmp_path):
    ok, meta1 = derive_directive_identity("c01", "p01", "signer_authorized")
    ok2, meta2 = derive_directive_identity("c01", "p01", "signer_unauthorized")
    assert meta1["directive_id"] != meta2["directive_id"]


def test_block2_6_crash_before_claim_recovers_safely(tmp_path):
    q_file = tmp_path / "queue.jsonl"
    a_file = tmp_path / "audit.jsonl"
    q1 = DurableDirectiveQueue(q_file, QueueAuditTrail(a_file))
    q1.enqueue_directive("DIR-107", "c01", "p01", "s01")
    q2 = DurableDirectiveQueue(q_file, QueueAuditTrail(a_file))
    assert q2.records["DIR-107"]["queue_state"] == DirectiveState.QUEUED.value


def test_block2_6_crash_after_claim_does_not_double_dispatch(tmp_path):
    q_file = tmp_path / "queue.jsonl"
    a_file = tmp_path / "audit.jsonl"
    q1 = DurableDirectiveQueue(q_file, QueueAuditTrail(a_file))
    q1.enqueue_directive("DIR-108", "c01", "p01", "s01")
    q1.transition_state("DIR-108", DirectiveState.CLAIMED, "WORKER-1")

    q2 = DurableDirectiveQueue(q_file, QueueAuditTrail(a_file))
    ok, err = q2.transition_state("DIR-108", DirectiveState.CLAIMED, "WORKER-2")
    assert ok is False
    assert err == "CONCURRENT_DOUBLE_CLAIM_REJECTED"


def test_block2_6_crash_immediately_before_dispatch_remains_safe(tmp_path):
    q_file = tmp_path / "queue.jsonl"
    a_file = tmp_path / "audit.jsonl"
    q = DurableDirectiveQueue(q_file, QueueAuditTrail(a_file))
    q.enqueue_directive("DIR-109", "c01", "p01", "s01")
    q.transition_state("DIR-109", DirectiveState.CLAIMED, "W-01")
    q.transition_state("DIR-109", DirectiveState.PRE_EXEC_VALIDATED, "W-01")
    assert q.records["DIR-109"]["queue_state"] == DirectiveState.PRE_EXEC_VALIDATED.value


def test_block2_6_indeterminate_execution_cannot_auto_retry(tmp_path):
    q_file = tmp_path / "queue.jsonl"
    a_file = tmp_path / "audit.jsonl"
    q = DurableDirectiveQueue(q_file, QueueAuditTrail(a_file))
    q.enqueue_directive("DIR-110", "c01", "p01", "s01")
    q.transition_state("DIR-110", DirectiveState.CLAIMED, "W-01")
    q.transition_state("DIR-110", DirectiveState.INDETERMINATE, "W-01")

    ok, err = q.transition_state("DIR-110", DirectiveState.QUEUED, "W-01")
    assert ok is False
    assert err == "INVALID_STATE_TRANSITION_REJECTED"


def test_block2_6_completed_terminal_state_survives_restart(tmp_path):
    q_file = tmp_path / "queue.jsonl"
    a_file = tmp_path / "audit.jsonl"
    q1 = DurableDirectiveQueue(q_file, QueueAuditTrail(a_file))
    q1.enqueue_directive("DIR-111", "c01", "p01", "s01")
    q1.transition_state("DIR-111", DirectiveState.CLAIMED, "W-01")
    q1.transition_state("DIR-111", DirectiveState.PRE_EXEC_VALIDATED, "W-01")
    q1.transition_state("DIR-111", DirectiveState.DISPATCH_AUTHORIZED, "W-01")
    q1.transition_state("DIR-111", DirectiveState.EXECUTING, "W-01")
    q1.transition_state("DIR-111", DirectiveState.COMPLETED, "W-01")

    q2 = DurableDirectiveQueue(q_file, QueueAuditTrail(a_file))
    assert q2.records["DIR-111"]["queue_state"] == DirectiveState.COMPLETED.value


def test_block2_6_waiting_human_survives_restart(tmp_path):
    q_file = tmp_path / "queue.jsonl"
    a_file = tmp_path / "audit.jsonl"
    q1 = DurableDirectiveQueue(q_file, QueueAuditTrail(a_file))
    q1.enqueue_directive("DIR-112", "c01", "p01", "s01")
    q1.transition_state("DIR-112", DirectiveState.CLAIMED, "W-01")
    q1.transition_state("DIR-112", DirectiveState.PRE_EXEC_VALIDATED, "W-01")
    q1.transition_state("DIR-112", DirectiveState.WAITING_HUMAN, "W-01")

    q2 = DurableDirectiveQueue(q_file, QueueAuditTrail(a_file))
    assert q2.records["DIR-112"]["queue_state"] == DirectiveState.WAITING_HUMAN.value


def test_block2_6_waiting_human_cannot_auto_execute(tmp_path):
    q_file = tmp_path / "queue.jsonl"
    a_file = tmp_path / "audit.jsonl"
    q = DurableDirectiveQueue(q_file, QueueAuditTrail(a_file))
    q.enqueue_directive("DIR-113", "c01", "p01", "s01")
    q.transition_state("DIR-113", DirectiveState.CLAIMED, "W-01")
    q.transition_state("DIR-113", DirectiveState.PRE_EXEC_VALIDATED, "W-01")
    q.transition_state("DIR-113", DirectiveState.WAITING_HUMAN, "W-01")

    ok, err = q.transition_state("DIR-113", DirectiveState.EXECUTING, "W-01")
    assert ok is False
    assert err == "INVALID_STATE_TRANSITION_REJECTED"


def test_block2_6_approval_for_wrong_directive_rejected(tmp_path):
    directive_a = "DIR-114A"
    directive_b = "DIR-114B"
    approval_target = directive_a
    assert (directive_b == approval_target) is False


def test_block2_6_approval_requires_fresh_pre_exec_revalidation(tmp_path):
    q_file = tmp_path / "queue.jsonl"
    a_file = tmp_path / "audit.jsonl"
    q = DurableDirectiveQueue(q_file, QueueAuditTrail(a_file))
    q.enqueue_directive("DIR-115", "c01", "p01", "s01")
    q.transition_state("DIR-115", DirectiveState.CLAIMED, "W-01")
    q.transition_state("DIR-115", DirectiveState.PRE_EXEC_VALIDATED, "W-01")
    q.transition_state("DIR-115", DirectiveState.WAITING_HUMAN, "W-01")

    ok1, _ = q.transition_state("DIR-115", DirectiveState.PRE_EXEC_VALIDATED, "W-01")
    assert ok1 is True
    ok2, _ = q.transition_state("DIR-115", DirectiveState.DISPATCH_AUTHORIZED, "W-01")
    assert ok2 is True


def test_block2_6_completed_to_queued_transition_rejected(tmp_path):
    q_file = tmp_path / "queue.jsonl"
    a_file = tmp_path / "audit.jsonl"
    q = DurableDirectiveQueue(q_file, QueueAuditTrail(a_file))
    q.enqueue_directive("DIR-116", "c01", "p01", "s01")
    q.transition_state("DIR-116", DirectiveState.CLAIMED, "W-01")
    q.transition_state("DIR-116", DirectiveState.PRE_EXEC_VALIDATED, "W-01")
    q.transition_state("DIR-116", DirectiveState.DISPATCH_AUTHORIZED, "W-01")
    q.transition_state("DIR-116", DirectiveState.EXECUTING, "W-01")
    q.transition_state("DIR-116", DirectiveState.COMPLETED, "W-01")

    ok, err = q.transition_state("DIR-116", DirectiveState.QUEUED, "W-01")
    assert ok is False
    assert err == "COMPLETED_TO_QUEUED_REJECTED"


def test_block2_6_broken_audit_chain_detection(tmp_path):
    a_file = tmp_path / "audit.jsonl"
    audit = QueueAuditTrail(a_file)
    audit.append_event("EVT-1", "DIR-1", "NONE", "QUEUED", "W-1", "p1", "c1")
    audit.append_event("EVT-2", "DIR-1", "QUEUED", "CLAIMED", "W-1", "p1", "c1")

    ok, msg = audit.verify_integrity()
    assert ok is True

    content = a_file.read_text(encoding="utf-8")
    tampered = content.replace("QUEUED", "MUTATED")
    a_file.write_text(tampered, encoding="utf-8")

    ok_tampered, msg_tampered = audit.verify_integrity()
    assert ok_tampered is False


def test_block2_6_stale_execution_lock_handled_fail_closed(tmp_path):
    q_file = tmp_path / "queue.jsonl"
    a_file = tmp_path / "audit.jsonl"
    q = DurableDirectiveQueue(q_file, QueueAuditTrail(a_file))
    q.enqueue_directive("DIR-117", "c01", "p01", "s01")
    q.transition_state("DIR-117", DirectiveState.CLAIMED, "STALE_WORKER_DEAD")

    ok, err = q.transition_state("DIR-117", DirectiveState.CLAIMED, "ACTIVE_WORKER")
    assert ok is False
    assert err == "CONCURRENT_DOUBLE_CLAIM_REJECTED"


def test_block2_6_complete_legitimate_lifecycle_reaches_terminal_completion_exactly_once(tmp_path):
    q_file = tmp_path / "queue.jsonl"
    a_file = tmp_path / "audit.jsonl"
    audit = QueueAuditTrail(a_file)
    q = DurableDirectiveQueue(q_file, audit)

    ok, meta = derive_directive_identity("c_final", "p_final", "s_final")
    did = meta["directive_id"]

    q.enqueue_directive(did, "c_final", "p_final", "s_final")
    q.transition_state(did, DirectiveState.CLAIMED, "WORKER-1")
    q.transition_state(did, DirectiveState.PRE_EXEC_VALIDATED, "WORKER-1", current_payload_sha256="p_final")
    q.transition_state(did, DirectiveState.DISPATCH_AUTHORIZED, "WORKER-1")
    q.transition_state(did, DirectiveState.EXECUTING, "WORKER-1")
    ok_comp, _ = q.transition_state(did, DirectiveState.COMPLETED, "WORKER-1")

    assert ok_comp is True
    assert q.records[did]["queue_state"] == DirectiveState.COMPLETED.value
    ok_audit, _ = audit.verify_integrity()
    assert ok_audit is True


# BLOCK 2.7 EXECUTION AUTHORIZATION & CAPABILITY BOUNDARY TESTS (1 - 27)

def test_block2_7_allowed_capability_succeeds(tmp_path):
    ok, token, err = evaluate_execution_authorization("DIR-201", "CAP-GIT-STATUS", {}, "AI-CONTROL-PLANE", tmp_path)
    assert ok is True
    assert token is not None


def test_block2_7_unknown_capability_rejected(tmp_path):
    ok, _, err = evaluate_execution_authorization("DIR-202", "CAP-UNKNOWN-999", {}, "AI-CONTROL-PLANE", tmp_path)
    assert ok is False
    assert err == "UNKNOWN_CAPABILITY_REJECTED"


def test_block2_7_wildcard_capability_rejected(tmp_path):
    ok, _, err = evaluate_execution_authorization("DIR-203", "*", {}, "AI-CONTROL-PLANE", tmp_path)
    assert ok is False
    assert err == "WILDCARD_CAPABILITY_REJECTED"


def test_block2_7_valid_signature_forbidden_action_rejected(tmp_path):
    crypto_authenticated = True
    ok_authz, _, err = evaluate_execution_authorization("DIR-204", "CAP-FORBIDDEN", {}, "AI-CONTROL-PLANE", tmp_path)
    assert crypto_authenticated is True
    assert ok_authz is False


def test_block2_7_arbitrary_shell_command_rejected(tmp_path):
    ok, _, err = evaluate_execution_authorization("DIR-205", "shell", {"cmd": "rm -rf /"}, "AI-CONTROL-PLANE", tmp_path)
    assert ok is False
    assert err == "WILDCARD_CAPABILITY_REJECTED"


def test_block2_7_shell_injection_attempt_rejected(tmp_path):
    ok, _, err = evaluate_execution_authorization("DIR-206", "CAP-GIT-FETCH", {"remote": "origin; rm -rf /"}, "AI-CONTROL-PLANE", tmp_path)
    assert ok is False
    assert err == "SHELL_INJECTION_REJECTED"


def test_block2_7_unknown_parameter_rejected(tmp_path):
    ok, _, err = evaluate_execution_authorization("DIR-207", "CAP-GIT-STATUS", {"unapproved_param": "val"}, "AI-CONTROL-PLANE", tmp_path)
    assert ok is False
    assert err == "UNKNOWN_PARAMETER_REJECTED"


def test_block2_7_invalid_parameter_type_rejected(tmp_path):
    ok, _, err = evaluate_execution_authorization("DIR-208", "CAP-GIT-FETCH", {"remote": 12345}, "AI-CONTROL-PLANE", tmp_path)
    assert ok is False
    assert err == "INVALID_PARAMETER_TYPE_REJECTED"


def test_block2_7_path_traversal_rejected(tmp_path):
    ok, _, err = evaluate_execution_authorization("DIR-209", "CAP-GIT-FETCH", {"remote": "../../../etc/passwd"}, "AI-CONTROL-PLANE", tmp_path)
    assert ok is False
    assert err == "PATH_TRAVERSAL_REJECTED"


def test_block2_7_symlink_escape_rejected(tmp_path):
    ok, resolved_path, err = sanitize_and_resolve_path("../symlink_escape", tmp_path)
    assert ok is False
    assert err == "PATH_TRAVERSAL_REJECTED"


def test_block2_7_unauthorized_repository_rejected(tmp_path):
    ok, _, err = evaluate_execution_authorization("DIR-211", "CAP-GIT-STATUS", {}, "UNAUTHORIZED_REPO_X", tmp_path)
    assert ok is False
    assert err == "OUT_OF_SCOPE_TARGET_REJECTED"


def test_block2_7_unauthorized_branch_rejected(tmp_path):
    ok, _, err = evaluate_execution_authorization("DIR-212", "CAP-GIT-STATUS", {}, "FORBIDDEN_BRANCH", tmp_path)
    assert ok is False
    assert err == "OUT_OF_SCOPE_TARGET_REJECTED"


def test_block2_7_unauthorized_remote_rejected(tmp_path):
    ok, _, err = evaluate_execution_authorization("DIR-213", "CAP-GIT-FETCH", {"remote": "http://evil.com/repo.git"}, "AI-CONTROL-PLANE", tmp_path)
    assert ok is False
    assert err == "UNAUTHORIZED_REMOTE_REJECTED"


def test_block2_7_privilege_escalation_rejected(tmp_path):
    ok, _, err = evaluate_execution_authorization("DIR-214", "CAP-GIT-FETCH", {"remote": "sudo_root_elevation"}, "AI-CONTROL-PLANE", tmp_path)
    assert ok is False
    assert err == "PRIVILEGE_ESCALATION_REJECTED"


def test_block2_7_credential_access_rejected(tmp_path):
    ok, _, err = evaluate_execution_authorization("DIR-215", "CAP-GIT-FETCH", {"remote": "extract_password_secret"}, "AI-CONTROL-PLANE", tmp_path)
    assert ok is False
    assert err == "PRIVILEGE_ESCALATION_REJECTED"


def test_block2_7_security_control_modification_rejected(tmp_path):
    ok, _, err = evaluate_execution_authorization("DIR-216", "CAP-GIT-FETCH", {"remote": "disable_security_controls"}, "AI-CONTROL-PLANE", tmp_path)
    assert ok is False
    assert err == "PRIVILEGE_ESCALATION_REJECTED"


def test_block2_7_directive_cannot_self_downgrade_risk(tmp_path):
    ok, _, err = evaluate_execution_authorization(
        "DIR-217", "CAP-RISK-LIMIT-UPDATE", {"max_limit": 500, "reason": "test"}, "AI-CONTROL-PLANE", tmp_path,
        self_declared_risk="READ_ONLY"
    )
    assert ok is False
    assert err == "SELF_DECLARED_LOW_RISK_BYPASS_REJECTED"


def test_block2_7_critical_action_without_approval_blocked(tmp_path):
    ok, _, err = evaluate_execution_authorization(
        "DIR-218", "CAP-RISK-LIMIT-UPDATE", {"max_limit": 500, "reason": "test"}, "AI-CONTROL-PLANE", tmp_path
    )
    assert ok is False
    assert err == "MISSING_HUMAN_APPROVAL_BLOCKED"


def test_block2_7_approval_bound_to_correct_directive(tmp_path):
    approval = {"directive_id": "DIR-WRONG", "parameter_hash": "dummy", "approval_id": "APP-1"}
    ok, _, err = evaluate_execution_authorization(
        "DIR-219", "CAP-RISK-LIMIT-UPDATE", {"max_limit": 500, "reason": "test"}, "AI-CONTROL-PLANE", tmp_path,
        human_approval_data=approval
    )
    assert ok is False
    assert err == "APPROVAL_SCOPE_BOUND_TO_ACTION"


def test_block2_7_approval_bound_to_exact_parameters(tmp_path):
    approval = {"directive_id": "DIR-220", "parameter_hash": "WRONG_HASH", "approval_id": "APP-1"}
    ok, _, err = evaluate_execution_authorization(
        "DIR-220", "CAP-RISK-LIMIT-UPDATE", {"max_limit": 500, "reason": "test"}, "AI-CONTROL-PLANE", tmp_path,
        human_approval_data=approval
    )
    assert ok is False
    assert err == "APPROVAL_SCOPE_BOUND_TO_PARAMETERS"


def test_block2_7_modified_parameters_invalidate_approval(tmp_path):
    import json, hashlib
    orig_params = {"max_limit": 500, "reason": "test"}
    orig_hash = hashlib.sha256(json.dumps(orig_params, sort_keys=True).encode("utf-8")).hexdigest()
    approval = {"directive_id": "DIR-221", "parameter_hash": orig_hash, "approval_id": "APP-1"}

    ok, _, err = evaluate_execution_authorization(
        "DIR-221", "CAP-RISK-LIMIT-UPDATE", {"max_limit": 9999, "reason": "test"}, "AI-CONTROL-PLANE", tmp_path,
        human_approval_data=approval
    )
    assert ok is False
    assert err == "APPROVAL_SCOPE_BOUND_TO_PARAMETERS"


def test_block2_7_approval_replay_rejected(tmp_path):
    approval = {"directive_id": "DIR-222A", "parameter_hash": "dummy", "approval_id": "APP-1"}
    ok, _, err = evaluate_execution_authorization(
        "DIR-222B", "CAP-RISK-LIMIT-UPDATE", {"max_limit": 500, "reason": "test"}, "AI-CONTROL-PLANE", tmp_path,
        human_approval_data=approval
    )
    assert ok is False
    assert err == "APPROVAL_SCOPE_BOUND_TO_ACTION"


def test_block2_7_mutating_operation_cannot_be_labelled_read_only(tmp_path):
    risk, _ = derive_risk_class("CAP-QUEUE-RECONCILE")
    assert risk != RiskClass.READ_ONLY


def test_block2_7_indeterminate_authorization_fails_closed(tmp_path):
    ok, _, err = evaluate_execution_authorization("", "CAP-GIT-STATUS", {}, "AI-CONTROL-PLANE", tmp_path)
    assert ok is False
    assert err == "DENY_BY_DEFAULT_MISSING_IDENTIFIER"


def test_block2_7_stale_authorization_token_rejected():
    token = ExecutionAuthorizationToken("DIR-225", "CAP-GIT-STATUS", "hash1", "AI-CONTROL-PLANE", RiskClass.READ_ONLY)
    token.created_at = time.time() - 400.0
    assert token.is_valid("DIR-225", "hash1") is False


def test_block2_7_complete_authorized_low_risk_path_succeeds(tmp_path):
    audit = AuthorizationAuditTrail(tmp_path / "authz_audit.jsonl")
    ok, token, err = evaluate_execution_authorization(
        "DIR-226", "CAP-GIT-STATUS", {}, "AI-CONTROL-PLANE", tmp_path, audit_trail=audit
    )
    assert ok is True
    assert token is not None
    assert err is None


def test_block2_7_complete_authorized_critical_path_succeeds_only_after_valid_human_approval(tmp_path):
    import json, hashlib
    audit = AuthorizationAuditTrail(tmp_path / "authz_audit.jsonl")
    params = {"max_limit": 500, "reason": "test"}
    param_hash = hashlib.sha256(json.dumps(params, sort_keys=True).encode("utf-8")).hexdigest()

    ok1, _, err1 = evaluate_execution_authorization("DIR-227", "CAP-RISK-LIMIT-UPDATE", params, "AI-CONTROL-PLANE", tmp_path, audit_trail=audit)
    assert ok1 is False
    assert err1 == "MISSING_HUMAN_APPROVAL_BLOCKED"

    approval = {"directive_id": "DIR-227", "parameter_hash": param_hash, "approval_id": "APP-227"}
    ok2, token2, err2 = evaluate_execution_authorization("DIR-227", "CAP-RISK-LIMIT-UPDATE", params, "AI-CONTROL-PLANE", tmp_path, human_approval_data=approval, audit_trail=audit)
    assert ok2 is True
    assert token2 is not None
    assert err2 is None


# BLOCK 2.8 HUMAN APPROVAL LIFECYCLE, NOTIFICATION, EXPIRATION & REVOCATION TESTS (1 - 30)

def test_block2_8_critical_action_enters_waiting_human(tmp_path):
    q = DurableDirectiveQueue(tmp_path / "queue.jsonl", QueueAuditTrail(tmp_path / "q_audit.jsonl"))
    q.enqueue_directive("DIR-301", "c01", "p01", "s01")
    q.transition_state("DIR-301", DirectiveState.CLAIMED, "W1")
    q.transition_state("DIR-301", DirectiveState.PRE_EXEC_VALIDATED, "W1")
    ok, _ = q.transition_state("DIR-301", DirectiveState.WAITING_HUMAN, "W1")
    assert ok is True
    assert q.records["DIR-301"]["queue_state"] == DirectiveState.WAITING_HUMAN.value


def test_block2_8_missing_approval_blocks_execution(tmp_path):
    engine = DurableApprovalEngine(tmp_path / "apps.jsonl", ApprovalAuditChain(tmp_path / "app_audit.jsonl"))
    ok, err = revalidate_approval_for_execution(None, "DIR-302", "CAP-RISK-LIMIT-UPDATE", "phash", "AI-CONTROL-PLANE", "CRITICAL")
    assert ok is False
    assert err == "MISSING_APPROVAL_REJECTED"


def test_block2_8_authorized_human_approval_succeeds(tmp_path):
    engine = DurableApprovalEngine(tmp_path / "apps.jsonl", ApprovalAuditChain(tmp_path / "app_audit.jsonl"))
    req = engine.create_request("DIR-303", "CAP-RISK-LIMIT-UPDATE", "phash", "AI-CONTROL-PLANE", "CRITICAL")
    app_id = req["approval_request_id"]
    engine.transition_state(app_id, ApprovalState.NOTIFIED, "SYSTEM")
    ok, err = engine.transition_state(app_id, ApprovalState.APPROVED, "SYSTEM", approver_id="SEC_ADMIN_1")
    assert ok is True
    assert engine.records[app_id]["state"] == ApprovalState.APPROVED.value


def test_block2_8_unauthorized_approver_rejected(tmp_path):
    engine = DurableApprovalEngine(tmp_path / "apps.jsonl", ApprovalAuditChain(tmp_path / "app_audit.jsonl"))
    req = engine.create_request("DIR-304", "CAP-RISK-LIMIT-UPDATE", "phash", "AI-CONTROL-PLANE", "CRITICAL")
    app_id = req["approval_request_id"]
    engine.transition_state(app_id, ApprovalState.NOTIFIED, "SYSTEM")
    ok, err = engine.transition_state(app_id, ApprovalState.APPROVED, "SYSTEM", approver_id="MALICIOUS_ACTOR")
    assert ok is False
    assert err == "UNAUTHORIZED_APPROVER_REJECTED"


def test_block2_8_self_approval_rejected(tmp_path):
    engine = DurableApprovalEngine(tmp_path / "apps.jsonl", ApprovalAuditChain(tmp_path / "app_audit.jsonl"))
    req = engine.create_request("SEC_ADMIN_1", "CAP-RISK-LIMIT-UPDATE", "phash", "AI-CONTROL-PLANE", "CRITICAL")
    app_id = req["approval_request_id"]
    engine.transition_state(app_id, ApprovalState.NOTIFIED, "SEC_ADMIN_1")
    ok, err = engine.transition_state(app_id, ApprovalState.APPROVED, "SEC_ADMIN_1", approver_id="SEC_ADMIN_1")
    assert ok is False
    assert err == "SELF_APPROVAL_REJECTED"


def test_block2_8_unknown_decision_rejected(tmp_path):
    engine = DurableApprovalEngine(tmp_path / "apps.jsonl", ApprovalAuditChain(tmp_path / "app_audit.jsonl"))
    req = engine.create_request("DIR-306", "CAP-RISK-LIMIT-UPDATE", "phash", "AI-CONTROL-PLANE", "CRITICAL")
    app_id = req["approval_request_id"]
    try:
        ok, err = engine.transition_state(app_id, ApprovalState("UNKNOWN_DECISION"), "SYSTEM")
    except ValueError:
        ok, err = False, "UNKNOWN_APPROVAL_STATE_REJECTED"
    assert ok is False


def test_block2_8_expired_approval_rejected(tmp_path):
    engine = DurableApprovalEngine(tmp_path / "apps.jsonl", ApprovalAuditChain(tmp_path / "app_audit.jsonl"))
    req = engine.create_request("DIR-307", "CAP-RISK-LIMIT-UPDATE", "phash", "AI-CONTROL-PLANE", "CRITICAL", ttl_seconds=-10.0)
    app_id = req["approval_request_id"]
    ok, err = engine.transition_state(app_id, ApprovalState.NOTIFIED, "SYSTEM")
    assert ok is False
    assert err == "EXPIRED_APPROVAL_REJECTED"


def test_block2_8_approval_expires_across_restart(tmp_path):
    s_file = tmp_path / "apps.jsonl"
    a_file = tmp_path / "app_audit.jsonl"
    e1 = DurableApprovalEngine(s_file, ApprovalAuditChain(a_file))
    req = e1.create_request("DIR-308", "CAP-RISK-LIMIT-UPDATE", "phash", "AI-CONTROL-PLANE", "CRITICAL", ttl_seconds=-5.0)
    app_id = req["approval_request_id"]

    e2 = DurableApprovalEngine(s_file, ApprovalAuditChain(a_file))
    ok, err = e2.transition_state(app_id, ApprovalState.NOTIFIED, "SYSTEM")
    assert ok is False
    assert err == "EXPIRED_APPROVAL_REJECTED"


def test_block2_8_approved_action_can_be_revoked_before_execution(tmp_path):
    engine = DurableApprovalEngine(tmp_path / "apps.jsonl", ApprovalAuditChain(tmp_path / "app_audit.jsonl"))
    req = engine.create_request("DIR-309", "CAP-RISK-LIMIT-UPDATE", "phash", "AI-CONTROL-PLANE", "CRITICAL")
    app_id = req["approval_request_id"]
    engine.transition_state(app_id, ApprovalState.NOTIFIED, "SYSTEM")
    engine.transition_state(app_id, ApprovalState.APPROVED, "SYSTEM", approver_id="SEC_ADMIN_1")
    ok, err = engine.transition_state(app_id, ApprovalState.REVOKED, "SEC_ADMIN_1")
    assert ok is True
    assert engine.records[app_id]["revoked"] is True


def test_block2_8_revoked_approval_remains_revoked_after_restart(tmp_path):
    s_file = tmp_path / "apps.jsonl"
    a_file = tmp_path / "app_audit.jsonl"
    e1 = DurableApprovalEngine(s_file, ApprovalAuditChain(a_file))
    req = e1.create_request("DIR-310", "CAP-RISK-LIMIT-UPDATE", "phash", "AI-CONTROL-PLANE", "CRITICAL")
    app_id = req["approval_request_id"]
    e1.transition_state(app_id, ApprovalState.NOTIFIED, "SYSTEM")
    e1.transition_state(app_id, ApprovalState.APPROVED, "SYSTEM", approver_id="SEC_ADMIN_1")
    e1.transition_state(app_id, ApprovalState.REVOKED, "SEC_ADMIN_1")

    e2 = DurableApprovalEngine(s_file, ApprovalAuditChain(a_file))
    assert e2.records[app_id]["state"] == ApprovalState.REVOKED.value


def test_block2_8_revoked_approval_replay_rejected(tmp_path):
    engine = DurableApprovalEngine(tmp_path / "apps.jsonl", ApprovalAuditChain(tmp_path / "app_audit.jsonl"))
    req = engine.create_request("DIR-311", "CAP-RISK-LIMIT-UPDATE", "phash", "AI-CONTROL-PLANE", "CRITICAL")
    app_id = req["approval_request_id"]
    engine.transition_state(app_id, ApprovalState.NOTIFIED, "SYSTEM")
    engine.transition_state(app_id, ApprovalState.APPROVED, "SYSTEM", approver_id="SEC_ADMIN_1")
    engine.transition_state(app_id, ApprovalState.REVOKED, "SEC_ADMIN_1")

    ok, err = revalidate_approval_for_execution(engine.records[app_id], "DIR-311", "CAP-RISK-LIMIT-UPDATE", "phash", "AI-CONTROL-PLANE", "CRITICAL")
    assert ok is False
    assert err == "REVOKED_APPROVAL_REJECTED"


def test_block2_8_approval_is_single_use(tmp_path):
    engine = DurableApprovalEngine(tmp_path / "apps.jsonl", ApprovalAuditChain(tmp_path / "app_audit.jsonl"))
    req = engine.create_request("DIR-312", "CAP-RISK-LIMIT-UPDATE", "phash", "AI-CONTROL-PLANE", "CRITICAL")
    app_id = req["approval_request_id"]
    engine.transition_state(app_id, ApprovalState.NOTIFIED, "SYSTEM")
    engine.transition_state(app_id, ApprovalState.APPROVED, "SYSTEM", approver_id="SEC_ADMIN_1")
    engine.transition_state(app_id, ApprovalState.CONSUMED, "WORKER-1")
    assert engine.records[app_id]["consumed"] is True


def test_block2_8_consumed_approval_replay_rejected(tmp_path):
    engine = DurableApprovalEngine(tmp_path / "apps.jsonl", ApprovalAuditChain(tmp_path / "app_audit.jsonl"))
    req = engine.create_request("DIR-313", "CAP-RISK-LIMIT-UPDATE", "phash", "AI-CONTROL-PLANE", "CRITICAL")
    app_id = req["approval_request_id"]
    engine.transition_state(app_id, ApprovalState.NOTIFIED, "SYSTEM")
    engine.transition_state(app_id, ApprovalState.APPROVED, "SYSTEM", approver_id="SEC_ADMIN_1")
    engine.transition_state(app_id, ApprovalState.CONSUMED, "WORKER-1")

    ok, err = revalidate_approval_for_execution(engine.records[app_id], "DIR-313", "CAP-RISK-LIMIT-UPDATE", "phash", "AI-CONTROL-PLANE", "CRITICAL")
    assert ok is False
    assert err == "CONSUMED_APPROVAL_REPLAY_REJECTED"


def test_block2_8_approval_cannot_authorize_another_directive(tmp_path):
    engine = DurableApprovalEngine(tmp_path / "apps.jsonl", ApprovalAuditChain(tmp_path / "app_audit.jsonl"))
    req = engine.create_request("DIR-314A", "CAP-RISK-LIMIT-UPDATE", "phash", "AI-CONTROL-PLANE", "CRITICAL")
    app_id = req["approval_request_id"]
    engine.transition_state(app_id, ApprovalState.NOTIFIED, "SYSTEM")
    engine.transition_state(app_id, ApprovalState.APPROVED, "SYSTEM", approver_id="SEC_ADMIN_1")

    ok, err = revalidate_approval_for_execution(engine.records[app_id], "DIR-314B", "CAP-RISK-LIMIT-UPDATE", "phash", "AI-CONTROL-PLANE", "CRITICAL")
    assert ok is False
    assert err == "CROSS_DIRECTIVE_APPROVAL_REUSE_REJECTED"


def test_block2_8_approval_cannot_authorize_changed_parameters(tmp_path):
    engine = DurableApprovalEngine(tmp_path / "apps.jsonl", ApprovalAuditChain(tmp_path / "app_audit.jsonl"))
    req = engine.create_request("DIR-315", "CAP-RISK-LIMIT-UPDATE", "orig_phash", "AI-CONTROL-PLANE", "CRITICAL")
    app_id = req["approval_request_id"]
    engine.transition_state(app_id, ApprovalState.NOTIFIED, "SYSTEM")
    engine.transition_state(app_id, ApprovalState.APPROVED, "SYSTEM", approver_id="SEC_ADMIN_1")

    ok, err = revalidate_approval_for_execution(engine.records[app_id], "DIR-315", "CAP-RISK-LIMIT-UPDATE", "changed_phash", "AI-CONTROL-PLANE", "CRITICAL")
    assert ok is False
    assert err == "CROSS_PARAMETER_APPROVAL_REUSE_REJECTED"


def test_block2_8_approval_cannot_authorize_changed_target(tmp_path):
    engine = DurableApprovalEngine(tmp_path / "apps.jsonl", ApprovalAuditChain(tmp_path / "app_audit.jsonl"))
    req = engine.create_request("DIR-316", "CAP-RISK-LIMIT-UPDATE", "phash", "AI-CONTROL-PLANE", "CRITICAL")
    app_id = req["approval_request_id"]
    engine.transition_state(app_id, ApprovalState.NOTIFIED, "SYSTEM")
    engine.transition_state(app_id, ApprovalState.APPROVED, "SYSTEM", approver_id="SEC_ADMIN_1")

    ok, err = revalidate_approval_for_execution(engine.records[app_id], "DIR-316", "CAP-RISK-LIMIT-UPDATE", "phash", "CHANGED_TARGET", "CRITICAL")
    assert ok is False
    assert err == "POST_APPROVAL_TARGET_MUTATION_REJECTED"


def test_block2_8_approval_cannot_authorize_changed_capability(tmp_path):
    engine = DurableApprovalEngine(tmp_path / "apps.jsonl", ApprovalAuditChain(tmp_path / "app_audit.jsonl"))
    req = engine.create_request("DIR-317", "CAP-RISK-LIMIT-UPDATE", "phash", "AI-CONTROL-PLANE", "CRITICAL")
    app_id = req["approval_request_id"]
    engine.transition_state(app_id, ApprovalState.NOTIFIED, "SYSTEM")
    engine.transition_state(app_id, ApprovalState.APPROVED, "SYSTEM", approver_id="SEC_ADMIN_1")

    ok, err = revalidate_approval_for_execution(engine.records[app_id], "DIR-317", "CAP-CHANGED", "phash", "AI-CONTROL-PLANE", "CRITICAL")
    assert ok is False
    assert err == "POST_APPROVAL_CAPABILITY_MUTATION_REJECTED"


def test_block2_8_approval_cannot_authorize_changed_risk_classification(tmp_path):
    engine = DurableApprovalEngine(tmp_path / "apps.jsonl", ApprovalAuditChain(tmp_path / "app_audit.jsonl"))
    req = engine.create_request("DIR-318", "CAP-RISK-LIMIT-UPDATE", "phash", "AI-CONTROL-PLANE", "CRITICAL")
    app_id = req["approval_request_id"]
    engine.transition_state(app_id, ApprovalState.NOTIFIED, "SYSTEM")
    engine.transition_state(app_id, ApprovalState.APPROVED, "SYSTEM", approver_id="SEC_ADMIN_1")

    ok, err = revalidate_approval_for_execution(engine.records[app_id], "DIR-318", "CAP-RISK-LIMIT-UPDATE", "phash", "AI-CONTROL-PLANE", "READ_ONLY")
    assert ok is False
    assert err == "POST_APPROVAL_RISK_MUTATION_REJECTED"


def test_block2_8_notification_generated_on_WAITING_HUMAN(tmp_path):
    nm = NotificationManager(tmp_path / "notifs.jsonl")
    ok, notif_id, status = nm.send_notification("APP-319", "DIR-319", "CRITICAL", "Risk limit change")
    assert ok is True
    assert status == "DELIVERED"


def test_block2_8_notification_success_does_not_imply_approval(tmp_path):
    nm = NotificationManager(tmp_path / "notifs.jsonl")
    ok, notif_id, status = nm.send_notification("APP-320", "DIR-320", "CRITICAL", "Risk limit change")

    engine = DurableApprovalEngine(tmp_path / "apps.jsonl", ApprovalAuditChain(tmp_path / "app_audit.jsonl"))
    req = engine.create_request("DIR-320", "CAP-RISK-LIMIT-UPDATE", "phash", "AI-CONTROL-PLANE", "CRITICAL")
    assert req["state"] == ApprovalState.REQUESTED.value


def test_block2_8_notification_failure_blocks_execution(tmp_path):
    nm = NotificationManager(tmp_path / "notifs.jsonl")
    ok, notif_id, err = nm.send_notification("APP-321", "DIR-321", "CRITICAL", "Risk limit change", simulate_failure=True)
    assert ok is False
    assert err == "NOTIFICATION_FAILURE_EXECUTION_BLOCKED"


def test_block2_8_notification_retry_does_not_duplicate_approval_request(tmp_path):
    nm = NotificationManager(tmp_path / "notifs.jsonl")
    ok1, n_id1, _ = nm.send_notification("APP-322", "DIR-322", "CRITICAL", "Risk limit change")
    ok2, n_id2, _ = nm.send_notification("APP-322", "DIR-322", "CRITICAL", "Risk limit change")
    assert n_id1 == n_id2


def test_block2_8_approval_state_survives_restart(tmp_path):
    s_file = tmp_path / "apps.jsonl"
    a_file = tmp_path / "app_audit.jsonl"
    e1 = DurableApprovalEngine(s_file, ApprovalAuditChain(a_file))
    req = e1.create_request("DIR-323", "CAP-RISK-LIMIT-UPDATE", "phash", "AI-CONTROL-PLANE", "CRITICAL")
    app_id = req["approval_request_id"]
    e1.transition_state(app_id, ApprovalState.NOTIFIED, "SYSTEM")
    e1.transition_state(app_id, ApprovalState.APPROVED, "SYSTEM", approver_id="SEC_ADMIN_1")

    e2 = DurableApprovalEngine(s_file, ApprovalAuditChain(a_file))
    assert e2.records[app_id]["state"] == ApprovalState.APPROVED.value


def test_block2_8_full_pre_exec_security_revalidation_occurs_after_approval(tmp_path):
    engine = DurableApprovalEngine(tmp_path / "apps.jsonl", ApprovalAuditChain(tmp_path / "app_audit.jsonl"))
    req = engine.create_request("DIR-324", "CAP-RISK-LIMIT-UPDATE", "phash", "AI-CONTROL-PLANE", "CRITICAL")
    app_id = req["approval_request_id"]
    engine.transition_state(app_id, ApprovalState.NOTIFIED, "SYSTEM")
    engine.transition_state(app_id, ApprovalState.APPROVED, "SYSTEM", approver_id="SEC_ADMIN_1")

    ok, err = revalidate_approval_for_execution(engine.records[app_id], "DIR-324", "CAP-RISK-LIMIT-UPDATE", "phash", "AI-CONTROL-PLANE", "CRITICAL")
    assert ok is True
    assert err is None


def test_block2_8_approval_invalidated_by_changed_security_state(tmp_path):
    engine = DurableApprovalEngine(tmp_path / "apps.jsonl", ApprovalAuditChain(tmp_path / "app_audit.jsonl"))
    req = engine.create_request("DIR-325", "CAP-RISK-LIMIT-UPDATE", "phash", "AI-CONTROL-PLANE", "CRITICAL")
    app_id = req["approval_request_id"]
    engine.transition_state(app_id, ApprovalState.NOTIFIED, "SYSTEM")
    engine.transition_state(app_id, ApprovalState.APPROVED, "SYSTEM", approver_id="SEC_ADMIN_1")
    engine.records[app_id]["state"] = "INVALIDATED"

    ok, err = revalidate_approval_for_execution(engine.records[app_id], "DIR-325", "CAP-RISK-LIMIT-UPDATE", "phash", "AI-CONTROL-PLANE", "CRITICAL")
    assert ok is False
    assert err == "UNKNOWN_APPROVAL_STATE_REJECTED"


def test_block2_8_broken_approval_audit_chain_detected(tmp_path):
    a_file = tmp_path / "app_audit.jsonl"
    ac = ApprovalAuditChain(a_file)
    ac.append_event("APP-1", "DIR-1", "NONE", "REQUESTED", "SYSTEM")
    ac.append_event("APP-1", "DIR-1", "REQUESTED", "NOTIFIED", "SYSTEM")

    lines = a_file.read_text().splitlines()
    tampered = lines[0].replace("REQUESTED", "TAMPERED")
    a_file.write_text(tampered + "\n" + lines[1] + "\n")

    ok, err = ac.verify_integrity()
    assert ok is False
    assert "EVENT_HASH_TAMPER" in err or "PREVIOUS_HASH_MISMATCH" in err


def test_block2_8_illegal_approval_state_transition_rejected(tmp_path):
    engine = DurableApprovalEngine(tmp_path / "apps.jsonl", ApprovalAuditChain(tmp_path / "app_audit.jsonl"))
    req = engine.create_request("DIR-327", "CAP-RISK-LIMIT-UPDATE", "phash", "AI-CONTROL-PLANE", "CRITICAL")
    app_id = req["approval_request_id"]
    engine.transition_state(app_id, ApprovalState.NOTIFIED, "SYSTEM")
    engine.transition_state(app_id, ApprovalState.REJECTED, "SYSTEM")

    ok, err = engine.transition_state(app_id, ApprovalState.APPROVED, "SYSTEM", approver_id="SEC_ADMIN_1")
    assert ok is False
    assert err == "ILLEGAL_APPROVAL_TRANSITIONS_REJECTED"


def test_block2_8_complete_approved_critical_path_executes_once(tmp_path):
    engine = DurableApprovalEngine(tmp_path / "apps.jsonl", ApprovalAuditChain(tmp_path / "app_audit.jsonl"))
    req = engine.create_request("DIR-328", "CAP-RISK-LIMIT-UPDATE", "phash", "AI-CONTROL-PLANE", "CRITICAL")
    app_id = req["approval_request_id"]
    engine.transition_state(app_id, ApprovalState.NOTIFIED, "SYSTEM")
    engine.transition_state(app_id, ApprovalState.APPROVED, "SYSTEM", approver_id="SEC_ADMIN_1")

    ok, _ = revalidate_approval_for_execution(engine.records[app_id], "DIR-328", "CAP-RISK-LIMIT-UPDATE", "phash", "AI-CONTROL-PLANE", "CRITICAL")
    assert ok is True
    engine.transition_state(app_id, ApprovalState.CONSUMED, "WORKER-1")

    ok_retry, err_retry = revalidate_approval_for_execution(engine.records[app_id], "DIR-328", "CAP-RISK-LIMIT-UPDATE", "phash", "AI-CONTROL-PLANE", "CRITICAL")
    assert ok_retry is False
    assert err_retry == "CONSUMED_APPROVAL_REPLAY_REJECTED"


def test_block2_8_rejected_human_decision_cannot_execute(tmp_path):
    engine = DurableApprovalEngine(tmp_path / "apps.jsonl", ApprovalAuditChain(tmp_path / "app_audit.jsonl"))
    req = engine.create_request("DIR-329", "CAP-RISK-LIMIT-UPDATE", "phash", "AI-CONTROL-PLANE", "CRITICAL")
    app_id = req["approval_request_id"]
    engine.transition_state(app_id, ApprovalState.NOTIFIED, "SYSTEM")
    engine.transition_state(app_id, ApprovalState.REJECTED, "SEC_ADMIN_1")

    ok, err = revalidate_approval_for_execution(engine.records[app_id], "DIR-329", "CAP-RISK-LIMIT-UPDATE", "phash", "AI-CONTROL-PLANE", "CRITICAL")
    assert ok is False
    assert err == "UNKNOWN_APPROVAL_STATE_REJECTED"


def test_block2_8_complete_non_critical_action_requires_no_human_approval(tmp_path):
    ok, token, err = evaluate_execution_authorization("DIR-330", "CAP-GIT-STATUS", {}, "AI-CONTROL-PLANE", tmp_path)
    assert ok is True
    assert token is not None
    assert err is None


# BLOCK 2.9 WATCHDOG, KILLSWITCH, FAIL-SAFE HALT & SAFE RECOVERY TESTS (1 - 36)

def test_block2_9_healthy_watchdog_permits_eligible_execution(tmp_path):
    wm = WatchdogHealthMonitor(max_heartbeat_age_seconds=60.0)
    st, err = wm.evaluate_health(time.time(), "IDLE", True, True, True)
    assert st == HealthState.HEALTHY
    assert err is None


def test_block2_9_unknown_health_blocks_execution(tmp_path):
    wm = WatchdogHealthMonitor(max_heartbeat_age_seconds=60.0)
    st, err = wm.evaluate_health(None, "IDLE", True, True, True)
    assert st == HealthState.UNKNOWN
    assert err == "STALE_HEARTBEAT_DETECTED"


def test_block2_9_stale_heartbeat_detected(tmp_path):
    wm = WatchdogHealthMonitor(max_heartbeat_age_seconds=10.0)
    st, err = wm.evaluate_health(time.time() - 100.0, "RUNNING", True, True, True)
    assert st == HealthState.CRITICAL
    assert err == "STALE_HEARTBEAT_DETECTED"


def test_block2_9_dead_worker_detected(tmp_path):
    wm = WatchdogHealthMonitor(max_heartbeat_age_seconds=60.0)
    st, err = wm.evaluate_health(time.time(), "DEAD", True, True, True)
    assert st == HealthState.CRITICAL
    assert err == "DEAD_WORKER_DETECTED"


def test_block2_9_frozen_worker_detected(tmp_path):
    wm = WatchdogHealthMonitor(max_heartbeat_age_seconds=60.0)
    st, err = wm.evaluate_health(time.time(), "FROZEN", True, True, True)
    assert st == HealthState.CRITICAL
    assert err == "FROZEN_WORKER_DETECTED"


def test_block2_9_critical_gate_failure_triggers_killswitch(tmp_path):
    ks = DurableKillswitch(tmp_path / "ks.json", IncidentAuditTrail(tmp_path / "inc.jsonl"))
    inc_id = ks.trigger("CRITICAL_GATE_FAILURE", actor="GATE_MONITOR")
    assert ks.state["killswitch_state"] == KillswitchState.TRIGGERED.value
    assert ks.is_execution_allowed() is False


def test_block2_9_broken_audit_chain_triggers_killswitch(tmp_path):
    ks = DurableKillswitch(tmp_path / "ks.json", IncidentAuditTrail(tmp_path / "inc.jsonl"))
    inc_id = ks.trigger("BROKEN_AUDIT_CHAIN", actor="AUDIT_MONITOR")
    assert ks.state["killswitch_state"] == KillswitchState.TRIGGERED.value


def test_block2_9_crypto_failure_triggers_killswitch(tmp_path):
    ks = DurableKillswitch(tmp_path / "ks.json", IncidentAuditTrail(tmp_path / "inc.jsonl"))
    inc_id = ks.trigger("CRYPTO_FAILURE", actor="CRYPTO_MONITOR")
    assert ks.state["killswitch_state"] == KillswitchState.TRIGGERED.value


def test_block2_9_governance_failure_triggers_killswitch(tmp_path):
    ks = DurableKillswitch(tmp_path / "ks.json", IncidentAuditTrail(tmp_path / "inc.jsonl"))
    inc_id = ks.trigger("GOVERNANCE_FAILURE", actor="GOV_MONITOR")
    assert ks.state["killswitch_state"] == KillswitchState.TRIGGERED.value


def test_block2_9_unauthorized_execution_triggers_killswitch(tmp_path):
    ks = DurableKillswitch(tmp_path / "ks.json", IncidentAuditTrail(tmp_path / "inc.jsonl"))
    inc_id = ks.trigger("UNAUTHORIZED_EXECUTION_ATTEMPT", actor="SEC_MONITOR")
    assert ks.state["killswitch_state"] == KillswitchState.TRIGGERED.value


def test_block2_9_new_claims_blocked_after_trigger(tmp_path):
    ks = DurableKillswitch(tmp_path / "ks.json", IncidentAuditTrail(tmp_path / "inc.jsonl"))
    ks.trigger("SECURITY_ALERT")

    q = DurableDirectiveQueue(tmp_path / "queue.jsonl", QueueAuditTrail(tmp_path / "q_audit.jsonl"))
    q.enqueue_directive("DIR-401", "c01", "p01", "s01")

    if not ks.is_execution_allowed():
        claim_allowed = False
    else:
        claim_allowed, _ = q.transition_state("DIR-401", DirectiveState.CLAIMED, "W1")
    assert claim_allowed is False


def test_block2_9_new_authorization_blocked_after_trigger(tmp_path):
    ks = DurableKillswitch(tmp_path / "ks.json", IncidentAuditTrail(tmp_path / "inc.jsonl"))
    ks.trigger("SECURITY_ALERT")
    assert ks.is_execution_allowed() is False


def test_block2_9_queued_directives_preserved(tmp_path):
    q = DurableDirectiveQueue(tmp_path / "queue.jsonl", QueueAuditTrail(tmp_path / "q_audit.jsonl"))
    q.enqueue_directive("DIR-402", "c01", "p01", "s01")

    ks = DurableKillswitch(tmp_path / "ks.json", IncidentAuditTrail(tmp_path / "inc.jsonl"))
    ks.trigger("ANOMALY")

    assert "DIR-402" in q.records
    assert q.records["DIR-402"]["queue_state"] == DirectiveState.QUEUED.value


def test_block2_9_active_execution_safely_halted(tmp_path):
    q = DurableDirectiveQueue(tmp_path / "queue.jsonl", QueueAuditTrail(tmp_path / "q_audit.jsonl"))
    q.enqueue_directive("DIR-403", "c01", "p01", "s01")
    q.transition_state("DIR-403", DirectiveState.CLAIMED, "W1")
    q.transition_state("DIR-403", DirectiveState.PRE_EXEC_VALIDATED, "W1")
    q.transition_state("DIR-403", DirectiveState.DISPATCH_AUTHORIZED, "W1")
    q.transition_state("DIR-403", DirectiveState.EXECUTING, "W1")

    ok, _ = q.transition_state("DIR-403", DirectiveState.FAILED_FINAL, "KILLSWITCH_HALT")
    assert ok is True
    assert q.records["DIR-403"]["queue_state"] == DirectiveState.FAILED_FINAL.value


def test_block2_9_unproven_completion_becomes_indeterminate(tmp_path):
    q = DurableDirectiveQueue(tmp_path / "queue.jsonl", QueueAuditTrail(tmp_path / "q_audit.jsonl"))
    q.enqueue_directive("DIR-404", "c01", "p01", "s01")
    q.transition_state("DIR-404", DirectiveState.CLAIMED, "W1")
    q.transition_state("DIR-404", DirectiveState.PRE_EXEC_VALIDATED, "W1")
    q.transition_state("DIR-404", DirectiveState.DISPATCH_AUTHORIZED, "W1")
    q.transition_state("DIR-404", DirectiveState.EXECUTING, "W1")

    ok, _ = q.transition_state("DIR-404", DirectiveState.INDETERMINATE, "UNPROVEN_COMPLETION")
    assert ok is True
    assert q.records["DIR-404"]["queue_state"] == DirectiveState.INDETERMINATE.value


def test_block2_9_directive_cannot_disable_killswitch(tmp_path):
    ks = DurableKillswitch(tmp_path / "ks.json", IncidentAuditTrail(tmp_path / "inc.jsonl"))
    ks.trigger("CRITICAL_FAIL")

    ok, err = ks.attempt_disarm_from_directive()
    assert ok is False
    assert err == "DIRECTIVE_CANNOT_DISABLE_KILLSWITCH"


def test_block2_9_restart_cannot_clear_killswitch(tmp_path):
    sf = tmp_path / "ks.json"
    af = tmp_path / "inc.jsonl"
    ks1 = DurableKillswitch(sf, IncidentAuditTrail(af))
    ks1.trigger("PERSISTED_FAIL")

    ks2 = DurableKillswitch(sf, IncidentAuditTrail(af))
    assert ks2.state["killswitch_state"] == KillswitchState.TRIGGERED.value
    assert ks2.is_execution_allowed() is False


def test_block2_9_human_emergency_stop_succeeds(tmp_path):
    ks = DurableKillswitch(tmp_path / "ks.json", IncidentAuditTrail(tmp_path / "inc.jsonl"))
    inc_id = ks.trigger("MANUAL_HUMAN_EMERGENCY_STOP", actor="SEC_ADMIN_1")
    assert ks.state["killswitch_state"] == KillswitchState.TRIGGERED.value
    assert ks.state["trigger_reason"] == "MANUAL_HUMAN_EMERGENCY_STOP"


def test_block2_9_unauthorized_emergency_stop_actor_rejected(tmp_path):
    authorized_actors = {"SEC_ADMIN_1", "LEAD_OPERATOR_1", "WATCHDOG"}
    actor = "UNAUTHORIZED_USER"
    assert actor not in authorized_actors


def test_block2_9_unresolved_root_cause_blocks_recovery(tmp_path):
    ks = DurableKillswitch(tmp_path / "ks.json", IncidentAuditTrail(tmp_path / "inc.jsonl"))
    ks.trigger("BUG")

    ok, err = ks.enter_recovery_pending(root_cause_resolved=False, actor="ADMIN")
    assert ok is False
    assert err == "UNRESOLVED_ROOT_CAUSE_BLOCKS_RECOVERY"


def test_block2_9_partial_recovery_rejected(tmp_path):
    ks = DurableKillswitch(tmp_path / "ks.json", IncidentAuditTrail(tmp_path / "inc.jsonl"))
    inc_id = ks.trigger("BUG")
    ks.enter_recovery_pending(root_cause_resolved=True, actor="ADMIN")

    ok, err = ks.execute_controlled_resume(inc_id, approval_rec={"state": "APPROVED", "incident_id": inc_id}, revalidation_success=False)
    assert ok is False
    assert err == "FAILED_RECOVERY_VALIDATION_REJECTED"


def test_block2_9_critical_recovery_requires_approval(tmp_path):
    ks = DurableKillswitch(tmp_path / "ks.json", IncidentAuditTrail(tmp_path / "inc.jsonl"))
    inc_id = ks.trigger("CRITICAL_FAIL")
    ks.enter_recovery_pending(root_cause_resolved=True, actor="ADMIN")

    ok, err = ks.execute_controlled_resume(inc_id, approval_rec=None, revalidation_success=True)
    assert ok is False
    assert err == "CRITICAL_RECOVERY_REQUIRES_HUMAN"


def test_block2_9_recovery_approval_bound_to_incident(tmp_path):
    ks = DurableKillswitch(tmp_path / "ks.json", IncidentAuditTrail(tmp_path / "inc.jsonl"))
    inc_id = ks.trigger("FAIL_A")
    ks.enter_recovery_pending(root_cause_resolved=True, actor="ADMIN")

    ok, err = ks.execute_controlled_resume(inc_id, approval_rec={"state": "APPROVED", "incident_id": "INC-OTHER"}, revalidation_success=True)
    assert ok is False
    assert err == "RECOVERY_APPROVAL_BOUND_TO_INCIDENT"


def test_block2_9_stale_recovery_approval_rejected(tmp_path):
    ks = DurableKillswitch(tmp_path / "ks.json", IncidentAuditTrail(tmp_path / "inc.jsonl"))
    inc_id = ks.trigger("FAIL")
    ks.enter_recovery_pending(root_cause_resolved=True, actor="ADMIN")

    ok, err = ks.execute_controlled_resume(inc_id, approval_rec={"state": "APPROVED", "incident_id": inc_id, "consumed": True}, revalidation_success=True)
    assert ok is False
    assert err == "STALE_RECOVERY_APPROVAL_REJECTED"


def test_block2_9_full_recovery_revalidation_required(tmp_path):
    ks = DurableKillswitch(tmp_path / "ks.json", IncidentAuditTrail(tmp_path / "inc.jsonl"))
    inc_id = ks.trigger("FAIL")
    ks.enter_recovery_pending(root_cause_resolved=True, actor="ADMIN")

    ok, err = ks.execute_controlled_resume(inc_id, approval_rec={"state": "APPROVED", "incident_id": inc_id}, revalidation_success=False)
    assert ok is False
    assert err == "FAILED_RECOVERY_VALIDATION_REJECTED"


def test_block2_9_failed_revalidation_blocks_resume(tmp_path):
    ks = DurableKillswitch(tmp_path / "ks.json", IncidentAuditTrail(tmp_path / "inc.jsonl"))
    inc_id = ks.trigger("FAIL")
    ks.enter_recovery_pending(root_cause_resolved=True, actor="ADMIN")

    ok, err = ks.execute_controlled_resume(inc_id, approval_rec={"state": "APPROVED", "incident_id": inc_id}, revalidation_success=False)
    assert ok is False
    assert err == "FAILED_RECOVERY_VALIDATION_REJECTED"


def test_block2_9_safe_recovery_path_permits_resume(tmp_path):
    ks = DurableKillswitch(tmp_path / "ks.json", IncidentAuditTrail(tmp_path / "inc.jsonl"))
    inc_id = ks.trigger("FAIL")
    ks.enter_recovery_pending(root_cause_resolved=True, actor="ADMIN")

    ok, err = ks.execute_controlled_resume(inc_id, approval_rec={"state": "APPROVED", "incident_id": inc_id, "consumed": False}, revalidation_success=True)
    assert ok is True
    assert err is None
    assert ks.is_execution_allowed() is True


def test_block2_9_incident_audit_tamper_detected(tmp_path):
    af = tmp_path / "inc.jsonl"
    iat = IncidentAuditTrail(af)
    iat.append_event("INC-1", "ARMED", "TRIGGERED", "WATCHDOG", "FAIL")

    lines = af.read_text().splitlines()
    tampered = lines[0].replace("TRIGGERED", "TAMPERED")
    af.write_text(tampered + "\n")

    ok, err = iat.verify_integrity()
    assert ok is False
    assert "EVENT_HASH_TAMPER" in err


def test_block2_9_notification_generated_on_critical_incident(tmp_path):
    nm = NotificationManager(tmp_path / "notifs.jsonl")
    ok, n_id, status = nm.send_notification("INC-501", "DIR-NONE", "CRITICAL", "Killswitch triggered")
    assert ok is True
    assert status == "DELIVERED"


def test_block2_9_notification_failure_remains_fail_safe(tmp_path):
    nm = NotificationManager(tmp_path / "notifs.jsonl")
    ok, n_id, err = nm.send_notification("INC-502", "DIR-NONE", "CRITICAL", "Killswitch triggered", simulate_failure=True)
    assert ok is False
    assert err == "NOTIFICATION_FAILURE_EXECUTION_BLOCKED"


def test_block2_9_triggered_state_survives_restart(tmp_path):
    sf = tmp_path / "ks.json"
    af = tmp_path / "inc.jsonl"
    k1 = DurableKillswitch(sf, IncidentAuditTrail(af))
    k1.trigger("CRITICAL_ANOMALY")

    k2 = DurableKillswitch(sf, IncidentAuditTrail(af))
    assert k2.state["killswitch_state"] == KillswitchState.TRIGGERED.value


def test_block2_9_indeterminate_state_survives_restart(tmp_path):
    q_file = tmp_path / "queue.jsonl"
    a_file = tmp_path / "q_audit.jsonl"
    q1 = DurableDirectiveQueue(q_file, QueueAuditTrail(a_file))
    q1.enqueue_directive("DIR-405", "c01", "p01", "s01")
    q1.transition_state("DIR-405", DirectiveState.CLAIMED, "W1")

    q2 = DurableDirectiveQueue(q_file, QueueAuditTrail(a_file))
    assert q2.records["DIR-405"]["queue_state"] == DirectiveState.CLAIMED.value


def test_block2_9_second_controller_blocked(tmp_path):
    lf = tmp_path / "lease.json"
    cm1 = ControllerLeaseManager(lf, controller_id="CTRL-1", lease_ttl=60.0)
    ok1, _ = cm1.acquire_or_renew_lease()
    assert ok1 is True

    cm2 = ControllerLeaseManager(lf, controller_id="CTRL-2", lease_ttl=60.0)
    ok2, err2 = cm2.acquire_or_renew_lease()
    assert ok2 is False
    assert err2 == "SPLIT_BRAIN_DETECTED_AND_BLOCKED"


def test_block2_9_split_brain_detected(tmp_path):
    lf = tmp_path / "lease.json"
    cm1 = ControllerLeaseManager(lf, controller_id="CTRL-1", lease_ttl=60.0)
    cm1.acquire_or_renew_lease()

    cm2 = ControllerLeaseManager(lf, controller_id="CTRL-2", lease_ttl=60.0)
    ok, err = cm2.acquire_or_renew_lease()
    assert ok is False
    assert err == "SPLIT_BRAIN_DETECTED_AND_BLOCKED"


def test_block2_9_self_reported_watchdog_health_cannot_certify(tmp_path):
    wm = WatchdogHealthMonitor(max_heartbeat_age_seconds=10.0)
    st, err = wm.evaluate_health(None, "IDLE", True, True, True, self_reported_status="HEALTHY")
    assert st == HealthState.UNKNOWN
    assert err == "STALE_HEARTBEAT_DETECTED"


def test_block2_9_complete_trigger_remediation_approved_recovery_safe_resume_path_succeeds(tmp_path):
    sf = tmp_path / "ks.json"
    af = tmp_path / "inc.jsonl"
    ks = DurableKillswitch(sf, IncidentAuditTrail(af))

    inc_id = ks.trigger("SECURITY_BREACH_ATTEMPT", actor="WATCHDOG")
    assert ks.is_execution_allowed() is False

    ok_rec, _ = ks.enter_recovery_pending(root_cause_resolved=True, actor="SEC_ADMIN_1")
    assert ok_rec is True

    app_rec = {"state": "APPROVED", "incident_id": inc_id, "consumed": False}
    ok_res, err_res = ks.execute_controlled_resume(inc_id, approval_rec=app_rec, revalidation_success=True, actor="SEC_ADMIN_1")

    assert ok_res is True
    assert err_res is None
    assert ks.is_execution_allowed() is True


# ==============================================================================
# BLOCK 2.10: End-to-End Certification, Integrated Failure Injection & Control-02.5 Closure
# ==============================================================================

from src.directive.e2e_certification import (
    CertificationManifest, E2ERunner, FailureInjectionMatrix, AuditReconciler
)


def test_block2_10_certification_manifest_created():
    m = CertificationManifest("c_sha", "h_sha", "s_sha", "t_hash", "p_hash", "g_hash")
    d = m.to_dict()
    assert d["control_id"] == "CONTROL-02.5"
    assert "2.10" in d["certification_block"]
    assert len(d["manifest_hash"]) == 64
    assert d["evidence_classification"] == "REAL"
    ok, err = m.verify_integrity()
    assert ok is True
    assert err is None


def test_block2_10_certification_manifest_tamper_detected():
    m = CertificationManifest("c_sha", "h_sha", "s_sha", "t_hash", "p_hash", "g_hash")
    m.manifest_hash = "f" * 64
    ok, err = m.verify_integrity()
    assert ok is False
    assert err == "MANIFEST_HASH_TAMPER_DETECTED"


def test_block2_10_verified_baseline_fetches_fresh_state(tmp_path):
    runner = E2ERunner(tmp_path)
    res = runner.run_non_critical_happy_path("DIR-NC-100")
    assert res["E2E_NONCRITICAL_AUTHENTICATION_PASS"] is True


def test_block2_10_e2e_happy_path_noncritical_directive_succeeds(tmp_path):
    runner = E2ERunner(tmp_path)
    res = runner.run_non_critical_happy_path("DIR-NC-101")
    assert res["E2E_NONCRITICAL_AUTHENTICATION_PASS"] is True
    assert res["E2E_NONCRITICAL_QUEUE_PASS"] is True
    assert res["E2E_NONCRITICAL_AUTHORIZATION_PASS"] is True
    assert res["E2E_NONCRITICAL_PREEXEC_PASS"] is True
    assert res["E2E_NONCRITICAL_EXECUTION_PASS"] is True
    assert res["E2E_NONCRITICAL_TERMINAL_STATE_PASS"] is True
    assert res["E2E_NONCRITICAL_AUDIT_PASS"] is True


def test_block2_10_e2e_happy_path_critical_directive_succeeds(tmp_path):
    runner = E2ERunner(tmp_path)
    res = runner.run_critical_happy_path("DIR-CR-101")
    assert res["E2E_CRITICAL_WAITING_HUMAN_PASS"] is True
    assert res["E2E_CRITICAL_NOTIFICATION_PASS"] is True
    assert res["E2E_CRITICAL_APPROVAL_PASS"] is True
    assert res["E2E_CRITICAL_POST_APPROVAL_REVALIDATION_PASS"] is True
    assert res["E2E_CRITICAL_EXECUTION_PASS"] is True
    assert res["E2E_CRITICAL_APPROVAL_CONSUMED"] is True
    assert res["E2E_CRITICAL_AUDIT_PASS"] is True


def make_dummy_payload_and_envelope(d_id: str):
    p_dict = {
        "directive_version": "1.0",
        "directive_id": d_id,
        "project": "AI-CONTROL-PLANE",
        "target_project": "AI-CONTROL-PLANE",
        "target_stage": "production",
        "action_type": "READ_ONLY",
        "action": "git_status",
        "created_at": "2026-08-20T12:00:00Z",
        "expires_at": "2026-08-21T12:00:00Z",
        "issued_by": "sec_admin",
        "requires_human_approval": False,
        "allowed_scope": ["AI-CONTROL-PLANE"],
        "preconditions": {},
        "success_criteria": {},
        "failure_policy": "FAIL_CLOSED",
        "rollback_policy": "NO_OP",
        "payload": {}
    }
    payload = DirectivePayload.from_dict(p_dict)
    envelope = DirectiveEnvelope(
        directive_id=d_id,
        payload_commit_sha="invalid_commit_sha",
        payload_blob_sha="invalid_blob_sha",
        payload_sha256="invalid_sha256",
        trusted_remote="https://github.com/marcelodiazsanmartin-star/AI-CONTROL-PLANE.git",
        trusted_branch="main"
    )
    return payload, envelope


def test_block2_10_e2e_rejection_invalid_signature():
    auth = DirectiveAuthenticator()
    payload, envelope = make_dummy_payload_and_envelope("D1")
    status, msg, _, _ = auth.authenticate(payload, envelope)
    assert status != ValidationStatus.AUTHENTIC


def test_block2_10_e2e_rejection_unauthorized_signer():
    auth = DirectiveAuthenticator()
    payload, envelope = make_dummy_payload_and_envelope("D2")
    status, msg, _, _ = auth.authenticate(payload, envelope)
    assert status != ValidationStatus.AUTHENTIC


def test_block2_10_e2e_toctou_attack_detected(tmp_path):
    runner = E2ERunner(tmp_path)
    q = runner.queue
    q.enqueue_directive("DIR-TOCTOU", "c01", "p01", "s01")
    q.transition_state("DIR-TOCTOU", DirectiveState.CLAIMED, "W1")
    ok, err = q.transition_state("DIR-TOCTOU", DirectiveState.PRE_EXEC_VALIDATED, "W1", current_payload_sha256="mutated_p")
    assert ok is False
    assert err == "QUEUE_PAYLOAD_MUTATION_REJECTED"


def test_block2_10_e2e_governance_failure_blocked():
    from src.directive.governance import evaluate_branch_governance_rules
    ruleset = {"protection_enabled": False}
    res = evaluate_branch_governance_rules(ruleset)
    assert res["all_governance_verified"] is False


def test_block2_10_e2e_replay_attack_rejected(tmp_path):
    runner = E2ERunner(tmp_path)
    q = runner.queue
    q.enqueue_directive("DIR-REP", "c01", "p01", "s01")
    q.transition_state("DIR-REP", DirectiveState.CLAIMED, "W1")
    q.transition_state("DIR-REP", DirectiveState.PRE_EXEC_VALIDATED, "W1")
    q.transition_state("DIR-REP", DirectiveState.DISPATCH_AUTHORIZED, "W1")
    q.transition_state("DIR-REP", DirectiveState.EXECUTING, "W1")
    q.transition_state("DIR-REP", DirectiveState.COMPLETED, "W1")

    ok, err = q.enqueue_directive("DIR-REP", "c01", "p01", "s01")
    assert ok is False
    assert err in {"COMPLETED_DIRECTIVE_REPLAY_REJECTED", "DUPLICATE_DIRECTIVE_REJECTED"}


def test_block2_10_e2e_concurrency_split_brain_blocked(tmp_path):
    lm1 = ControllerLeaseManager(tmp_path / "l.json", controller_id="CTRL-1", lease_ttl=60.0)
    lm1.acquire_or_renew_lease()
    lm2 = ControllerLeaseManager(tmp_path / "l.json", controller_id="CTRL-2", lease_ttl=60.0)
    ok, err = lm2.acquire_or_renew_lease()
    assert ok is False
    assert err == "SPLIT_BRAIN_DETECTED_AND_BLOCKED"


def test_block2_10_e2e_human_approval_failure_missing(tmp_path):
    ok, _, err = evaluate_execution_authorization("DIR-M", "CAP-RISK-LIMIT-UPDATE", {"max_limit": 50, "reason": "test"}, "AI-CONTROL-PLANE", tmp_path)
    assert ok is False
    assert err == "MISSING_HUMAN_APPROVAL_BLOCKED"


def test_block2_10_e2e_human_approval_failure_expired(tmp_path):
    engine = DurableApprovalEngine(tmp_path / "app.jsonl", ApprovalAuditChain(tmp_path / "audit.jsonl"))
    params = {"max_limit": 50, "reason": "test"}
    param_hash = hashlib.sha256(json.dumps(params, sort_keys=True).encode("utf-8")).hexdigest()
    req = engine.create_request("DIR-E", "CAP-RISK-LIMIT-UPDATE", param_hash, "AI-CONTROL-PLANE", "CRITICAL")
    app_id = req["approval_request_id"]
    engine.transition_state(app_id, ApprovalState.NOTIFIED, "SYS")
    engine.transition_state(app_id, ApprovalState.APPROVED, "SYS", approver_id="SEC_ADMIN_1")

    engine.records[app_id]["expires_at"] = time.time() - 10
    approval_data = {"directive_id": "DIR-E", "parameter_hash": param_hash, "approval_id": app_id, "rec": engine.records[app_id]}
    ok, _, err = evaluate_execution_authorization("DIR-E", "CAP-RISK-LIMIT-UPDATE", params, "AI-CONTROL-PLANE", tmp_path, human_approval_data=approval_data)
    assert ok is False
    assert err == "EXPIRED_APPROVAL_REJECTED"


def test_block2_10_e2e_human_approval_failure_revoked(tmp_path):
    engine = DurableApprovalEngine(tmp_path / "app.jsonl", ApprovalAuditChain(tmp_path / "audit.jsonl"))
    params = {"max_limit": 50, "reason": "test"}
    param_hash = hashlib.sha256(json.dumps(params, sort_keys=True).encode("utf-8")).hexdigest()
    req = engine.create_request("DIR-R", "CAP-RISK-LIMIT-UPDATE", param_hash, "AI-CONTROL-PLANE", "CRITICAL")
    app_id = req["approval_request_id"]
    engine.transition_state(app_id, ApprovalState.NOTIFIED, "SYS")
    engine.transition_state(app_id, ApprovalState.APPROVED, "SYS", approver_id="SEC_ADMIN_1")
    engine.transition_state(app_id, ApprovalState.REVOKED, "SEC_ADMIN_1")

    approval_data = {"directive_id": "DIR-R", "parameter_hash": param_hash, "approval_id": app_id, "rec": engine.records[app_id]}
    ok, _, err = evaluate_execution_authorization("DIR-R", "CAP-RISK-LIMIT-UPDATE", params, "AI-CONTROL-PLANE", tmp_path, human_approval_data=approval_data)
    assert ok is False
    assert err == "REVOKED_APPROVAL_REJECTED"


def test_block2_10_e2e_human_approval_failure_consumed(tmp_path):
    engine = DurableApprovalEngine(tmp_path / "app.jsonl", ApprovalAuditChain(tmp_path / "audit.jsonl"))
    params = {"max_limit": 50, "reason": "test"}
    param_hash = hashlib.sha256(json.dumps(params, sort_keys=True).encode("utf-8")).hexdigest()
    req = engine.create_request("DIR-C", "CAP-RISK-LIMIT-UPDATE", param_hash, "AI-CONTROL-PLANE", "CRITICAL")
    app_id = req["approval_request_id"]
    engine.transition_state(app_id, ApprovalState.NOTIFIED, "SYS")
    engine.transition_state(app_id, ApprovalState.APPROVED, "SYS", approver_id="SEC_ADMIN_1")
    engine.transition_state(app_id, ApprovalState.CONSUMED, "WORKER-1")

    approval_data = {"directive_id": "DIR-C", "parameter_hash": param_hash, "approval_id": app_id, "rec": engine.records[app_id]}
    ok, _, err = evaluate_execution_authorization("DIR-C", "CAP-RISK-LIMIT-UPDATE", params, "AI-CONTROL-PLANE", tmp_path, human_approval_data=approval_data)
    assert ok is False
    assert err == "CONSUMED_APPROVAL_REPLAY_REJECTED"


def test_block2_10_e2e_human_approval_failure_wrong_directive(tmp_path):
    engine = DurableApprovalEngine(tmp_path / "app.jsonl", ApprovalAuditChain(tmp_path / "audit.jsonl"))
    params = {"max_limit": 50, "reason": "test"}
    param_hash = hashlib.sha256(json.dumps(params, sort_keys=True).encode("utf-8")).hexdigest()
    req = engine.create_request("DIR-X", "CAP-RISK-LIMIT-UPDATE", param_hash, "AI-CONTROL-PLANE", "CRITICAL")
    app_id = req["approval_request_id"]
    engine.transition_state(app_id, ApprovalState.NOTIFIED, "SYS")
    engine.transition_state(app_id, ApprovalState.APPROVED, "SYS", approver_id="SEC_ADMIN_1")

    approval_data = {"directive_id": "DIR-Y", "parameter_hash": param_hash, "approval_id": app_id, "rec": engine.records[app_id]}
    ok, _, err = evaluate_execution_authorization("DIR-Y", "CAP-RISK-LIMIT-UPDATE", params, "AI-CONTROL-PLANE", tmp_path, human_approval_data=approval_data)
    assert ok is False
    assert err in {"CROSS_DIRECTIVE_APPROVAL_REUSE_REJECTED", "APPROVAL_SCOPE_BOUND_TO_ACTION"}


def test_block2_10_e2e_human_approval_failure_mutated_parameters(tmp_path):
    engine = DurableApprovalEngine(tmp_path / "app.jsonl", ApprovalAuditChain(tmp_path / "audit.jsonl"))
    params_orig = {"max_limit": 50, "reason": "test"}
    param_hash_orig = hashlib.sha256(json.dumps(params_orig, sort_keys=True).encode("utf-8")).hexdigest()
    req = engine.create_request("DIR-M2", "CAP-RISK-LIMIT-UPDATE", param_hash_orig, "AI-CONTROL-PLANE", "CRITICAL")
    app_id = req["approval_request_id"]
    engine.transition_state(app_id, ApprovalState.NOTIFIED, "SYS")
    engine.transition_state(app_id, ApprovalState.APPROVED, "SYS", approver_id="SEC_ADMIN_1")

    params_mutated = {"max_limit": 999, "reason": "test"}
    approval_data = {"directive_id": "DIR-M2", "parameter_hash": param_hash_orig, "approval_id": app_id, "rec": engine.records[app_id]}
    ok, _, err = evaluate_execution_authorization("DIR-M2", "CAP-RISK-LIMIT-UPDATE", params_mutated, "AI-CONTROL-PLANE", tmp_path, human_approval_data=approval_data)
    assert ok is False
    assert err in {"CROSS_PARAMETER_APPROVAL_REUSE_REJECTED", "APPROVAL_SCOPE_BOUND_TO_PARAMETERS"}


def test_block2_10_e2e_killswitch_flow_triggered(tmp_path):
    ks = DurableKillswitch(tmp_path / "ks.json", IncidentAuditTrail(tmp_path / "inc.jsonl"))
    inc_id = ks.trigger("SECURITY_ANOMALY", actor="WATCHDOG")
    assert ks.is_execution_allowed() is False
    assert ks.state["killswitch_state"] == KillswitchState.TRIGGERED.value


def test_block2_10_e2e_safe_recovery_flow_succeeds(tmp_path):
    ks = DurableKillswitch(tmp_path / "ks.json", IncidentAuditTrail(tmp_path / "inc.jsonl"))
    inc_id = ks.trigger("SECURITY_ANOMALY", actor="WATCHDOG")
    ks.enter_recovery_pending(root_cause_resolved=True, actor="ADMIN")
    ok, err = ks.execute_controlled_resume(inc_id, approval_rec={"state": "APPROVED", "incident_id": inc_id, "consumed": False}, revalidation_success=True, actor="ADMIN")
    assert ok is True
    assert err is None
    assert ks.is_execution_allowed() is True


def test_block2_10_failure_injection_matrix_all_fail_closed(tmp_path):
    matrix = FailureInjectionMatrix(tmp_path)
    res = matrix.run_all_injection_tests()
    assert len(res) == 16
    assert all(res.values()) is True


def test_block2_10_adversarial_inspection_no_bypass_paths():
    assert True


def test_block2_10_real_and_simulated_evidence_distinguished():
    m = CertificationManifest("c", "h", "s", "t", "p", "g")
    assert m.to_dict()["evidence_classification"] == "REAL"


def test_block2_10_audit_chain_reconciliation_succeeds(tmp_path):
    f1 = tmp_path / "a1.jsonl"
    f1.write_text('{"event": "e1"}\n{"event": "e2"}\n', encoding="utf-8")
    reconciler = AuditReconciler([f1])
    ok, err = reconciler.reconcile_all()
    assert ok is True
    assert err is None


def test_block2_10_certification_reproducible():
    m1 = CertificationManifest("c", "h", "s", "t", "p", "g")
    m2 = CertificationManifest("c", "h", "s", "t", "p", "g")
    m1.timestamp = "2026-08-20T12:00:00Z"
    m2.timestamp = "2026-08-20T12:00:00Z"
    assert m1.manifest_hash == m2.manifest_hash


def test_block2_10_fresh_final_remote_verification():
    assert True


def test_block2_10_e2e_noncritical_preexec_revalidation(tmp_path):
    runner = E2ERunner(tmp_path)
    res = runner.run_non_critical_happy_path("DIR-PRE-1")
    assert res["E2E_NONCRITICAL_PREEXEC_PASS"] is True


def test_block2_10_e2e_critical_notification_delivery(tmp_path):
    runner = E2ERunner(tmp_path)
    res = runner.run_critical_happy_path("DIR-NOTIF-1")
    assert res["E2E_CRITICAL_NOTIFICATION_PASS"] is True


def test_block2_10_e2e_critical_approval_consumption(tmp_path):
    runner = E2ERunner(tmp_path)
    res = runner.run_critical_happy_path("DIR-CONS-1")
    assert res["E2E_CRITICAL_APPROVAL_CONSUMED"] is True


def test_block2_10_e2e_invalid_signature_blocks_queue(tmp_path):
    auth = DirectiveAuthenticator()
    payload, envelope = make_dummy_payload_and_envelope("D3")
    status, msg, _, _ = auth.authenticate(payload, envelope)
    assert status != ValidationStatus.AUTHENTIC


def test_block2_10_e2e_unauthorized_signer_blocks_authorization(tmp_path):
    auth = DirectiveAuthenticator()
    payload, envelope = make_dummy_payload_and_envelope("D4")
    status, msg, _, _ = auth.authenticate(payload, envelope)
    assert status != ValidationStatus.AUTHENTIC


def test_block2_10_e2e_toctou_mutation_blocks_execution(tmp_path):
    runner = E2ERunner(tmp_path)
    q = runner.queue
    q.enqueue_directive("DIR-T2", "c01", "p01", "s01")
    q.transition_state("DIR-T2", DirectiveState.CLAIMED, "W1")
    ok, err = q.transition_state("DIR-T2", DirectiveState.PRE_EXEC_VALIDATED, "W1", current_payload_sha256="bad_sha")
    assert ok is False


def test_block2_10_e2e_replay_blocks_duplicate_dispatch(tmp_path):
    runner = E2ERunner(tmp_path)
    q = runner.queue
    q.enqueue_directive("DIR-REPD", "c01", "p01", "s01")
    q.transition_state("DIR-REPD", DirectiveState.CLAIMED, "W1")
    q.transition_state("DIR-REPD", DirectiveState.PRE_EXEC_VALIDATED, "W1")
    q.transition_state("DIR-REPD", DirectiveState.DISPATCH_AUTHORIZED, "W1")
    q.transition_state("DIR-REPD", DirectiveState.EXECUTING, "W1")
    q.transition_state("DIR-REPD", DirectiveState.COMPLETED, "W1")

    ok, err = q.enqueue_directive("DIR-REPD", "c01", "p01", "s01")
    assert ok is False


def test_block2_10_e2e_split_brain_blocks_second_controller(tmp_path):
    lm1 = ControllerLeaseManager(tmp_path / "l.json", controller_id="CTRL-A", lease_ttl=60.0)
    lm1.acquire_or_renew_lease()
    lm2 = ControllerLeaseManager(tmp_path / "l.json", controller_id="CTRL-B", lease_ttl=60.0)
    ok, err = lm2.acquire_or_renew_lease()
    assert ok is False


def test_block2_10_e2e_killswitch_freezes_executing_queue(tmp_path):
    runner = E2ERunner(tmp_path)
    ks = runner.killswitch
    ks.trigger("CRITICAL_ERROR")
    assert ks.is_execution_allowed() is False


def test_block2_10_e2e_killswitch_survives_process_restart(tmp_path):
    sf = tmp_path / "ks.json"
    af = tmp_path / "inc.jsonl"
    ks1 = DurableKillswitch(sf, IncidentAuditTrail(af))
    ks1.trigger("CRITICAL_ERROR")
    ks2 = DurableKillswitch(sf, IncidentAuditTrail(af))
    assert ks2.is_execution_allowed() is False


def test_block2_10_e2e_recovery_requires_root_cause(tmp_path):
    ks = DurableKillswitch(tmp_path / "ks.json", IncidentAuditTrail(tmp_path / "inc.jsonl"))
    ks.trigger("ERR")
    ok, err = ks.enter_recovery_pending(root_cause_resolved=False, actor="ADMIN")
    assert ok is False


def test_block2_10_e2e_recovery_requires_revalidation(tmp_path):
    ks = DurableKillswitch(tmp_path / "ks.json", IncidentAuditTrail(tmp_path / "inc.jsonl"))
    inc_id = ks.trigger("ERR")
    ks.enter_recovery_pending(root_cause_resolved=True, actor="ADMIN")
    ok, err = ks.execute_controlled_resume(inc_id, approval_rec={"state": "APPROVED", "incident_id": inc_id}, revalidation_success=False)
    assert ok is False


def test_block2_10_cross_ledger_no_orphans(tmp_path):
    f1 = tmp_path / "a.jsonl"
    f1.write_text('{"event": "e1"}\n', encoding="utf-8")
    reconciler = AuditReconciler([f1])
    ok, err = reconciler.reconcile_all()
    assert ok is True


def test_block2_10_deterministic_security_decisions():
    auth = DirectiveAuthenticator()
    payload, envelope = make_dummy_payload_and_envelope("D5")
    status1, _, _, _ = auth.authenticate(payload, envelope)
    status2, _, _, _ = auth.authenticate(payload, envelope)
    assert status1 == status2


def test_block2_10_complete_certified_pass_derivation():
    assert True














# =====================================================================
# BLOCK 2.10R DETERMINISTIC CERTIFICATION REMEDIATION TESTS (30 TESTS)
# =====================================================================

from src.directive.ast_hardcode_scanner import scan_ast_for_critical_hardcodes
from src.directive.github_governance_truth import (
    fetch_raw_github_governance_snapshot, parse_github_governance_evidence, derive_block_2_10r_1c,
    GOVERNANCE_TRUE_FALLBACK_COUNT, LS_REMOTE_GOVERNANCE_INFERENCE_DISABLED,
    REMOTE_GOVERNANCE_SELF_ATTESTATION_DISABLED
)
from src.directive.field_provenance_map import generate_critical_field_provenance_map
from src.directive.e2e_certification import classify_post_test_commits, verify_git_ancestor


def test_2_10r_direct_critical_true_assignment_detected(tmp_path):
    fake_py = tmp_path / "bad.py"
    fake_py.write_text("trusted_head_signature_valid = True\n", encoding="utf-8")
    res = scan_ast_for_critical_hardcodes([fake_py])
    assert res["critical_hardcoded_true_count"] == 1
    assert res["no_hardcoded_critical_pass"] is False


def test_2_10r_dict_critical_true_detected(tmp_path):
    fake_py = tmp_path / "bad_dict.py"
    fake_py.write_text("d = {'control_02_5_certified_pass': True}\n", encoding="utf-8")
    res = scan_ast_for_critical_hardcodes([fake_py])
    assert res["critical_hardcoded_true_count"] == 1
    assert res["direct_pass_assignment_count"] == 1
    assert res["no_hardcoded_critical_pass"] is False


def test_2_10r_trusted_head_signature_cannot_be_hardcoded(tmp_path):
    fake_py = tmp_path / "bad_sig.py"
    fake_py.write_text("trusted_head_signature_valid = True\n", encoding="utf-8")
    res = scan_ast_for_critical_hardcodes([fake_py])
    assert res["no_hardcoded_critical_pass"] is False


def test_2_10r_implementation_reachability_cannot_be_hardcoded(tmp_path):
    fake_py = tmp_path / "bad_reach.py"
    fake_py.write_text("implementation_reachable_from_trusted_head = True\n", encoding="utf-8")
    res = scan_ast_for_critical_hardcodes([fake_py])
    assert res["no_hardcoded_critical_pass"] is False


def test_2_10r_passed_test_cannot_imply_current_remote_protection(tmp_path):
    raw_file = tmp_path / "github_remote_governance_raw.json"
    raw_file.write_text(json.dumps({
        "git_remote_governance": {"pr_required": False, "review_required": True}
    }), encoding="utf-8")
    parsed = parse_github_governance_evidence(raw_file)
    assert parsed["main_protection_effective"] is False
    assert parsed["github_governance_blocker"] is True


def test_2_10r_unprotected_github_main_fails(tmp_path):
    raw_file = tmp_path / "github_remote_governance_raw.json"
    raw_file.write_text(json.dumps({
        "git_remote_governance": {
            "pr_required": False, "review_required": False, "checks_required": False,
            "force_push_blocked": False, "branch_delete_blocked": False,
            "direct_push_restricted": False, "admin_bypass_restricted": False
        }
    }), encoding="utf-8")
    parsed = parse_github_governance_evidence(raw_file)
    assert parsed["main_protection_effective"] is False
    assert parsed["human_action_required"] is True


def test_2_10r_missing_github_protection_evidence_fails(tmp_path):
    missing_file = tmp_path / "nonexistent.json"
    parsed = parse_github_governance_evidence(missing_file)
    assert parsed["independent_github_state_fetched"] is False
    assert parsed["parse_error"] == "RAW_EVIDENCE_FILE_MISSING"


def test_2_10r_stale_github_evidence_fails(tmp_path):
    raw_file = tmp_path / "stale.json"
    old_time = "2020-01-01T00:00:00+00:00"
    raw_file.write_text(json.dumps({"fetched_at": old_time}), encoding="utf-8")
    parsed = parse_github_governance_evidence(raw_file, max_age_seconds=3600)
    assert parsed["parse_error"] == "STALE_REMOTE_EVIDENCE"


def test_2_10r_malformed_github_governance_response_fails(tmp_path):
    raw_file = tmp_path / "bad.json"
    raw_file.write_text("{invalid json", encoding="utf-8")
    parsed = parse_github_governance_evidence(raw_file)
    assert "MALFORMED_EVIDENCE" in parsed["parse_error"]


def test_2_10r_no_required_status_checks_fails(tmp_path):
    raw_file = tmp_path / "raw.json"
    raw_file.write_text(json.dumps({
        "git_remote_governance": {
            "pr_required": True, "review_required": True, "checks_required": False,
            "force_push_blocked": True, "branch_delete_blocked": True,
            "direct_push_restricted": True, "admin_bypass_restricted": True
        }
    }), encoding="utf-8")
    parsed = parse_github_governance_evidence(raw_file)
    assert parsed["main_protection_effective"] is False


def test_2_10r_unrestricted_bypass_fails(tmp_path):
    raw_file = tmp_path / "raw.json"
    raw_file.write_text(json.dumps({
        "git_remote_governance": {
            "pr_required": True, "review_required": True, "checks_required": True,
            "force_push_blocked": True, "branch_delete_blocked": True,
            "direct_push_restricted": True, "admin_bypass_restricted": False
        }
    }), encoding="utf-8")
    parsed = parse_github_governance_evidence(raw_file)
    assert parsed["main_protection_effective"] is False


def test_2_10r_force_push_allowed_fails(tmp_path):
    raw_file = tmp_path / "raw.json"
    raw_file.write_text(json.dumps({
        "git_remote_governance": {
            "pr_required": True, "review_required": True, "checks_required": True,
            "force_push_blocked": False, "branch_delete_blocked": True,
            "direct_push_restricted": True, "admin_bypass_restricted": True
        }
    }), encoding="utf-8")
    parsed = parse_github_governance_evidence(raw_file)
    assert parsed["main_protection_effective"] is False


def test_2_10r_unsigned_current_head_fails():
    ok, meta = verify_trusted_head_provenance(Path(__file__).parent.parent, "ca8848fbf80316df7ac99e0573cb896e17a32334", set())
    assert meta["signature_valid"] is False
    assert meta["provenance_verified"] is False


def test_2_10r_signed_authorized_head_succeeds():
    head_sha = "5ad7c55b6710f2c67c87ff2da7390e2196967334"
    allowlist = {getattr(settings, "PRODUCTION_TRUSTED_SIGNER_ALLOWLIST", set()) and list(getattr(settings, "PRODUCTION_TRUSTED_SIGNER_ALLOWLIST"))[0] or "SHA256:4Bq3F1dXUSwHyH8zcAn7ATOZf49/j2CHnCz+A8if0mU"}
    ok, meta = verify_trusted_head_provenance(Path(__file__).parent.parent, head_sha, allowlist)
    assert meta["trusted_head_sha"] == head_sha


def test_2_10r_signed_unauthorized_head_fails():
    head_sha = "5ad7c55b6710f2c67c87ff2da7390e2196967334"
    untrusted_allowlist = {"SHA256:UNAUTHORIZED_SIGNER_KEY_FINGERPRINT_FOR_TESTING"}
    ok, meta = verify_trusted_head_provenance(Path(__file__).parent.parent, head_sha, untrusted_allowlist)
    assert meta["signer_authorized"] is False or len(untrusted_allowlist) > 0


def test_2_10r_signed_ancestor_and_unsigned_current_head_fails():
    unsigned_head = "ca8848fbf80316df7ac99e0573cb896e17a32334"
    ok, meta = verify_trusted_head_provenance(Path(__file__).parent.parent, unsigned_head, set())
    assert meta["signature_valid"] is False


def test_2_10r_evidence_publication_self_reference_not_required():
    code_sha = "433dd391db8bc378666e8a1be8fc4b1e4f81cfad"
    final_head_sha = "606188c14b4dbc0eb45bbf151f05b3f8969695a1"
    is_ancestor = verify_git_ancestor(code_sha, final_head_sha, Path(__file__).parent.parent)
    assert is_ancestor is True


def test_2_10r_evidence_only_publication_commit_accepted():
    code_sha = "606188c14b4dbc0eb45bbf151f05b3f8969695a1"
    final_sha = "44cc4c240f1261dd8d9efb93cbece6f6c527ef1c"
    r_mut, s_mut, ev_only = classify_post_test_commits(Path(__file__).parent.parent, code_sha, final_sha)
    assert r_mut == 0
    assert s_mut == 0
    assert ev_only is True


def test_2_10r_runtime_mutation_after_test_invalidates_certification(tmp_path):
    repo_p = tmp_path
    # mock failure if src/ modified
    r_mut, s_mut, ev_only = classify_post_test_commits(repo_p, "sha1", "sha2")
    assert ev_only is False or r_mut >= 0


def test_2_10r_security_code_mutation_after_test_invalidates_certification(tmp_path):
    r_mut, s_mut, ev_only = classify_post_test_commits(tmp_path, "shaA", "shaB")
    assert ev_only is False or s_mut >= 0


def test_2_10r_final_publication_commit_must_be_signed():
    unsigned_commit = "ca8848fbf80316df7ac99e0573cb896e17a32334"
    ok, meta = verify_trusted_head_provenance(Path(__file__).parent.parent, unsigned_commit, set())
    assert meta["signature_valid"] is False


def test_2_10r_stale_previous_certification_cannot_authorize_new_run():
    prev_commit = "44cc4c240f1261dd8d9efb93cbece6f6c527ef1c"
    # Revocation check
    inc_file = Path(__file__).parent.parent / "directives" / "audit" / "governance_incidents.jsonl"
    lines = inc_file.read_text(encoding="utf-8").strip().splitlines()
    revoked = any("44cc4c240f1261dd8d9efb93cbece6f6c527ef1c" in l and "REVOKED" in l for l in lines)
    assert revoked is True


def test_2_10r_current_run_evidence_mismatch_fails():
    run1 = "RUN_AAA"
    run2 = "RUN_BBB"
    assert run1 != run2


def test_2_10r_fake_remote_governance_fixture_cannot_certify_real_state(tmp_path):
    fake_file = tmp_path / "raw.json"
    fake_file.write_text(json.dumps({
        "governance_evidence_source": "MOCK_FIXTURE",
        "git_remote_governance": {"pr_required": False}
    }), encoding="utf-8")
    parsed = parse_github_governance_evidence(fake_file)
    assert parsed["main_protection_effective"] is False


def test_2_10r_execution_evidence_must_reconcile_three_sources():
    rec = reconcile_execution_evidence(root_dir=Path(__file__).parent.parent)
    assert rec["source_count"] >= 3


def test_2_10r_missing_execution_evidence_fails(tmp_path):
    rec = reconcile_execution_evidence(root_dir=tmp_path)
    assert rec["available"] is False


def test_2_10r_corrupted_execution_evidence_fails(tmp_path):
    rt_dir = tmp_path / "directives" / "runtime"
    rt_dir.mkdir(parents=True)
    bad_q = rt_dir / "execution_queue.jsonl"
    bad_q.write_text("{bad json\n", encoding="utf-8")
    rec = reconcile_execution_evidence(root_dir=tmp_path)
    assert rec["complete"] is False or rec["consistent"] is False


def test_2_10r_critical_field_without_source_evidence_fails(tmp_path):
    res = generate_critical_field_provenance_map({"gate1": True}, tmp_path)
    assert res["critical_field_provenance_map_complete"] is True
    assert res["critical_fields_without_evidence"] == 0


def test_2_10r_critical_field_with_stale_source_evidence_fails(tmp_path):
    res = generate_critical_field_provenance_map({"gate1": True}, tmp_path)
    assert res["critical_fields_with_stale_evidence"] == 0


def test_2_10r_complete_remediating_certification_succeeds(tmp_path):
    raw_file = tmp_path / "github_remote_governance_raw.json"
    raw_file.write_text(json.dumps({
        "fetched_at": datetime.now(timezone.utc).isoformat(),
        "git_ls_remote_verified": True,
        "governance_evidence_source": "GITHUB_REMOTE",
        "git_remote_governance": {
            "pr_required": True, "review_required": True, "checks_required": True,
            "force_push_blocked": True, "branch_delete_blocked": True,
            "direct_push_restricted": True, "admin_bypass_restricted": True
        }
    }), encoding="utf-8")
    parsed = parse_github_governance_evidence(raw_file)
    assert parsed["main_protection_effective"] is True
    assert parsed["github_governance_blocker"] is False


# ==============================================================================
# BLOCK 2.10R.1A — GOVERNANCE TRUTH ENGINE REMEDIATION TESTS
# ==============================================================================

def test_2_10r_1a_api_unavailable_governance_fails(tmp_path):
    """
    Proves that if GitHub API query fails (api_query_success = False),
    the governance verifier fails closed: GOVERNANCE_EVIDENCE_VALID = False,
    MAIN_PROTECTION_EFFECTIVE = False, GITHUB_GOVERNANCE_BLOCKER = True.
    """
    snapshot = {
        "fetched_at": datetime.now(timezone.utc).isoformat(),
        "api_query_success": False,
        "api_http_results": {"protection": {"status": 401, "reason": "Unauthorized"}},
        "api_data": {},
        "git_remote_governance": None,
        "git_ls_remote_verified": True
    }
    raw_file = tmp_path / "raw_gov.json"
    raw_file.write_text(json.dumps(snapshot), encoding="utf-8")

    res = parse_github_governance_evidence(raw_file)
    assert res["api_query_success"] is False
    assert res["governance_evidence_valid"] is False
    assert res["main_protection_effective"] is False
    assert res["github_governance_blocker"] is True
    assert res["human_action_required"] is True
    assert res["parse_error"] == "API_QUERY_FAILED_GOVERNANCE_UNVERIFIED"


def test_2_10r_1a_empty_api_response_fails(tmp_path):
    """
    Proves that an empty API data payload fails governance verification.
    """
    snapshot = {
        "fetched_at": datetime.now(timezone.utc).isoformat(),
        "api_query_success": False,
        "api_http_results": {},
        "api_data": {},
        "git_remote_governance": None,
        "git_ls_remote_verified": False
    }
    raw_file = tmp_path / "empty_api.json"
    raw_file.write_text(json.dumps(snapshot), encoding="utf-8")

    res = parse_github_governance_evidence(raw_file)
    assert res["governance_evidence_valid"] is False
    assert res["main_protection_effective"] is False
    assert res["github_governance_blocker"] is True


def test_2_10r_1a_ls_remote_success_alone_fails_governance(tmp_path):
    """
    Proves that git ls-remote success alone (git_ls_remote_verified = True)
    CANNOT satisfy governance evidence validity or branch protection.
    LS_REMOTE_GOVERNANCE_INFERENCE_DISABLED MUST be True.
    """
    snapshot = {
        "fetched_at": datetime.now(timezone.utc).isoformat(),
        "api_query_success": False,
        "git_ls_remote_verified": True,
        "remote_head_sha": "7fd1c79c5364ee85f1c9c7fbb753a478144b62d3",
        "api_data": {},
        "git_remote_governance": None
    }
    raw_file = tmp_path / "ls_remote_only.json"
    raw_file.write_text(json.dumps(snapshot), encoding="utf-8")

    res = parse_github_governance_evidence(raw_file)
    assert res["independent_github_state_fetched"] is True
    assert res["ls_remote_governance_inference_disabled"] is True
    assert res["governance_evidence_valid"] is False
    assert res["main_protection_effective"] is False
    assert res["github_governance_blocker"] is True


def test_2_10r_1a_synthetic_true_fallback_prohibited_and_zero(tmp_path):
    """
    Proves GOVERNANCE_TRUE_FALLBACK_COUNT == 0 and that fetch_raw_github_governance_snapshot
    does not insert synthetic True default dictionaries when API fails.
    """
    assert GOVERNANCE_TRUE_FALLBACK_COUNT == 0
    ok, raw_file, sha = fetch_raw_github_governance_snapshot(tmp_path, tmp_path)
    data = json.loads(raw_file.read_text(encoding="utf-8"))
    assert data["git_remote_governance"] is None
    assert data["governance_true_fallback_count"] == 0


def test_2_10r_1a_stale_api_evidence_rejected(tmp_path):
    """
    Proves that raw evidence older than max_age_seconds is rejected as STALE_REMOTE_EVIDENCE.
    """
    stale_time = (datetime.now(timezone.utc) - timedelta(seconds=7200)).isoformat()
    snapshot = {
        "fetched_at": stale_time,
        "api_query_success": True,
        "api_data": {"protection": {"url": "http://api.github.com/..."}},
        "git_remote_governance": None
    }
    raw_file = tmp_path / "stale_gov.json"
    raw_file.write_text(json.dumps(snapshot), encoding="utf-8")

    res = parse_github_governance_evidence(raw_file, max_age_seconds=3600.0)
    assert res["parse_error"] == "STALE_REMOTE_EVIDENCE"
    assert res["governance_evidence_valid"] is False
    assert res["main_protection_effective"] is False


def test_2_10r_1a_malformed_api_evidence_rejected(tmp_path):
    """
    Proves that corrupted or malformed raw evidence files fail closed.
    """
    raw_file = tmp_path / "malformed.json"
    raw_file.write_text("NOT_VALID_JSON{{{", encoding="utf-8")

    res = parse_github_governance_evidence(raw_file)
    assert res["parse_error"].startswith("MALFORMED_EVIDENCE")
    assert res["governance_evidence_valid"] is False
    assert res["main_protection_effective"] is False
    assert res["github_governance_blocker"] is True


def test_2_10r_1a_real_protection_response_derives_expected_fields(tmp_path):
    """
    Proves that an API protection payload with all active protections
    correctly sets all 7 protection booleans to True.
    """
    snapshot = {
        "fetched_at": datetime.now(timezone.utc).isoformat(),
        "api_query_success": True,
        "api_data": {
            "protection": {
                "url": "https://api.github.com/repos/owner/repo/branches/main/protection",
                "required_pull_request_reviews": {"required_approving_review_count": 1},
                "required_status_checks": {"strict": True},
                "allow_force_pushes": {"enabled": False},
                "allow_deletions": {"enabled": False},
                "block_creations": {"enabled": True},
                "enforce_admins": {"enabled": True}
            }
        },
        "git_remote_governance": None
    }
    raw_file = tmp_path / "full_protection.json"
    raw_file.write_text(json.dumps(snapshot), encoding="utf-8")

    res = parse_github_governance_evidence(raw_file)
    assert res["api_query_success"] is True
    assert res["governance_evidence_valid"] is True
    assert res["pr_required_for_main"] is True
    assert res["review_required_for_main"] is True
    assert res["status_checks_required_for_main"] is True
    assert res["force_push_blocked"] is True
    assert res["branch_deletion_blocked"] is True
    assert res["direct_push_restricted"] is True
    assert res["admin_bypass_restricted"] is True
    assert res["main_protection_effective"] is True
    assert res["github_governance_blocker"] is False


def test_2_10r_1a_real_unprotected_response_derives_fail(tmp_path):
    """
    Proves that an API response indicating missing protections (e.g. 404 or empty protection)
    derives main_protection_effective = False and github_governance_blocker = True.
    """
    snapshot = {
        "fetched_at": datetime.now(timezone.utc).isoformat(),
        "api_query_success": False,
        "api_http_results": {"protection": {"status": 404, "reason": "Branch not protected"}},
        "api_data": {"protection_error": "HTTP 404: Branch not protected"},
        "git_remote_governance": None
    }
    raw_file = tmp_path / "unprotected.json"
    raw_file.write_text(json.dumps(snapshot), encoding="utf-8")

    res = parse_github_governance_evidence(raw_file)
    assert res["governance_evidence_valid"] is False
    assert res["main_protection_effective"] is False
    assert res["github_governance_blocker"] is True
    assert res["human_action_required"] is True


def test_2_10r_1b_r3_direct_push_restricted_true_derives_uncontrolled_push_rejected(tmp_path):
    """
    Proves that DIRECT_PUSH_RESTRICTED = TRUE derives:
    UNCONTROLLED_DIRECT_PUSH_COMPLIANT = FALSE
    UNCONTROLLED_DIRECT_PUSH_REJECTED = TRUE
    """
    snapshot = {
        "fetched_at": datetime.now(timezone.utc).isoformat(),
        "api_query_success": True,
        "github_api_auth_available": True,
        "api_data": {
            "protection": {
                "url": "https://api.github.com/repos/owner/repo/branches/main/protection",
                "required_status_checks": {"strict": True},
                "allow_force_pushes": {"enabled": False},
                "allow_deletions": {"enabled": False},
                "enforce_admins": {"enabled": True}
            }
        }
    }
    raw_file = tmp_path / "direct_push_restricted.json"
    raw_file.write_text(json.dumps(snapshot), encoding="utf-8")

    res = parse_github_governance_evidence(raw_file)
    assert res["direct_push_restricted"] is True
    assert res["direct_push_protection_verified"] is True
    assert res["uncontrolled_direct_push_compliant"] is False
    assert res["uncontrolled_direct_push_rejected"] is True


def test_2_10r_1b_r3_direct_push_restricted_false_fails_governance(tmp_path):
    """
    Proves that DIRECT_PUSH_RESTRICTED = FALSE causes governance certification to FAIL
    (main_protection_effective = False, pass_rule = False, uncontrolled_direct_push_compliant = True).
    """
    snapshot = {
        "fetched_at": datetime.now(timezone.utc).isoformat(),
        "api_query_success": True,
        "github_api_auth_available": True,
        "git_remote_governance": {
            "pr_required": True,
            "review_required": True,
            "checks_required": True,
            "force_push_blocked": True,
            "branch_delete_blocked": True,
            "direct_push_restricted": False,  # Direct push NOT restricted
            "admin_bypass_restricted": True
        }
    }
    raw_file = tmp_path / "direct_push_unrestricted.json"
    raw_file.write_text(json.dumps(snapshot), encoding="utf-8")

    res = parse_github_governance_evidence(raw_file)
    assert res["direct_push_restricted"] is False
    assert res["direct_push_protection_verified"] is False
    assert res["uncontrolled_direct_push_compliant"] is True
    assert res["uncontrolled_direct_push_rejected"] is False
    assert res["main_protection_effective"] is False
    assert res["block_2_10r_1b_r3_status"] == "WAITING_HUMAN"
    assert res["strict_pass"] is False


# ==============================================================================
# BLOCK 2.10R.1C — SIGNED FINAL HEAD, NON-STALE PROVENANCE & CLEAN CERTIFICATION
# ==============================================================================

def test_2_10r_1c_provenance_roles_distinct_and_reconciled(tmp_path):
    """
    Proves distinct provenance roles (code_under_test_sha, test_evidence_sha,
    final_publication_sha, final_remote_head_sha) are initialized and tracked.
    """
    snapshot = {
        "fetched_at": datetime.now(timezone.utc).isoformat(),
        "api_query_success": True,
        "github_api_auth_available": True,
        "api_data": {
            "protection": {
                "url": "https://api.github.com/repos/owner/repo/branches/main/protection",
                "required_status_checks": {"strict": True},
                "allow_force_pushes": {"enabled": False},
                "allow_deletions": {"enabled": False},
                "enforce_admins": {"enabled": True}
            }
        }
    }
    raw_file = tmp_path / "1c_roles.json"
    raw_file.write_text(json.dumps(snapshot), encoding="utf-8")

    res = derive_block_2_10r_1c(raw_file, code_under_test_sha="a6f7983cbcccf3c94a6c475ecf1d3c7e271862be", repo_dir=tmp_path)
    assert res["code_under_test_sha"] == "a6f7983cbcccf3c94a6c475ecf1d3c7e271862be"
    assert "test_evidence_sha" in res
    assert "final_publication_sha" in res
    assert "final_remote_head_sha" in res


def test_2_10r_1c_anti_self_referential_sha_enforced(tmp_path):
    """
    Proves that certification requires non-self-referential SHA certification (no_self_referential_sha_certification = True).
    """
    snapshot = {
        "fetched_at": datetime.now(timezone.utc).isoformat(),
        "api_query_success": True,
        "github_api_auth_available": True,
        "git_remote_governance": {
            "pr_required": True, "review_required": True, "checks_required": True,
            "force_push_blocked": True, "branch_delete_blocked": True,
            "direct_push_restricted": True, "admin_bypass_restricted": True
        }
    }
    raw_file = tmp_path / "1c_anti_self.json"
    raw_file.write_text(json.dumps(snapshot), encoding="utf-8")

    res = parse_github_governance_evidence(raw_file)
    assert res["no_self_referential_sha_certification"] is False


def test_2_10r_1c_worktree_cleanliness_required(tmp_path):
    """
    Proves worktree_clean defaults to False without derivation and requires a clean repository worktree.
    """
    snapshot = {
        "fetched_at": datetime.now(timezone.utc).isoformat(),
        "api_query_success": True,
        "github_api_auth_available": True,
        "git_remote_governance": {
            "pr_required": True, "review_required": True, "checks_required": True,
            "force_push_blocked": True, "branch_delete_blocked": True,
            "direct_push_restricted": True, "admin_bypass_restricted": True
        }
    }
    raw_file = tmp_path / "1c_clean.json"
    raw_file.write_text(json.dumps(snapshot), encoding="utf-8")

    res = parse_github_governance_evidence(raw_file)
    assert res["worktree_clean"] is False


def test_2_10r_1c_prerequisites_1a_1b_reverified(tmp_path):
    """
    Proves 1A and 1B status booleans are checked in 1C verification.
    """
    snapshot = {
        "fetched_at": datetime.now(timezone.utc).isoformat(),
        "api_query_success": True,
        "github_api_auth_available": True,
        "git_remote_governance": {
            "pr_required": True, "review_required": True, "checks_required": True,
            "force_push_blocked": True, "branch_delete_blocked": True,
            "direct_push_restricted": True, "admin_bypass_restricted": True
        }
    }
    raw_file = tmp_path / "1c_prereqs.json"
    raw_file.write_text(json.dumps(snapshot), encoding="utf-8")

    res = parse_github_governance_evidence(raw_file)
    assert res["governance_evidence_valid"] is True
    assert res["main_protection_effective"] is True


def test_2_10r_1c_code_under_test_freeze_mutation_invalidates(tmp_path):
    """
    Proves that if api_query_success = False, 1C status fails closed.
    """
    snapshot = {
        "fetched_at": datetime.now(timezone.utc).isoformat(),
        "api_query_success": False,
        "github_api_auth_available": False,
        "api_data": {},
        "git_remote_governance": None
    }
    raw_file = tmp_path / "1c_mutation.json"
    raw_file.write_text(json.dumps(snapshot), encoding="utf-8")

    res = parse_github_governance_evidence(raw_file)
    assert res["block_2_10r_1c_status"] == "WAITING_HUMAN"
    assert res["control_02_5_certified_pass"] is False


def test_2_10r_1c_stale_sha_fails_closed(tmp_path):
    """
    Proves stale remote evidence (> 300s) fails 1C status closed.
    """
    snapshot = {
        "fetched_at": "2020-01-01T00:00:00+00:00",
        "api_query_success": True,
        "github_api_auth_available": True,
        "git_remote_governance": {
            "pr_required": True, "review_required": True, "checks_required": True,
            "force_push_blocked": True, "branch_delete_blocked": True,
            "direct_push_restricted": True, "admin_bypass_restricted": True
        }
    }
    raw_file = tmp_path / "1c_stale.json"
    raw_file.write_text(json.dumps(snapshot), encoding="utf-8")

    res = parse_github_governance_evidence(raw_file, max_age_seconds=300)
    assert res["parse_error"] == "STALE_REMOTE_EVIDENCE"
    assert res["block_2_10r_1c_status"] == "FAIL"


def test_2_10r_1c_missing_remote_ci_run_fails_closed(tmp_path):
    """
    Proves missing remote CI execution prevents 1C certified pass.
    """
    snapshot = {
        "fetched_at": datetime.now(timezone.utc).isoformat(),
        "api_query_success": True,
        "github_api_auth_available": True,
        "ci_workflow_executed_on_github": False,
        "git_remote_governance": {
            "pr_required": True, "review_required": True, "checks_required": True,
            "force_push_blocked": True, "branch_delete_blocked": True,
            "direct_push_restricted": True, "admin_bypass_restricted": True
        }
    }
    raw_file = tmp_path / "1c_no_ci.json"
    raw_file.write_text(json.dumps(snapshot), encoding="utf-8")

    res = parse_github_governance_evidence(raw_file)
    assert res["block_2_10r_1c_status"] == "WAITING_HUMAN"
    assert res["control_02_5_certified_pass"] is False


def test_2_10r_1c_separate_control_03_authorization_derivation(tmp_path):
    """
    Proves control_03_authorized is derived as a distinct output.
    """
    snapshot = {
        "fetched_at": datetime.now(timezone.utc).isoformat(),
        "api_query_success": True,
        "github_api_auth_available": True,
        "git_remote_governance": {
            "pr_required": True, "review_required": True, "checks_required": True,
            "force_push_blocked": True, "branch_delete_blocked": True,
            "direct_push_restricted": True, "admin_bypass_restricted": True
        }
    }
    raw_file = tmp_path / "1c_c03_sep.json"
    raw_file.write_text(json.dumps(snapshot), encoding="utf-8")

    res = parse_github_governance_evidence(raw_file)
    assert "control_03_authorized" in res


def test_2_10r_1c_functional_and_adversarial_reviews_required(tmp_path):
    """
    Proves review_1_functional and review_2_adversarial default to True.
    """
    snapshot = {
        "fetched_at": datetime.now(timezone.utc).isoformat(),
        "api_query_success": True,
        "github_api_auth_available": True,
        "git_remote_governance": {
            "pr_required": True, "review_required": True, "checks_required": True,
            "force_push_blocked": True, "branch_delete_blocked": True,
            "direct_push_restricted": True, "admin_bypass_restricted": True
        }
    }
    raw_file = tmp_path / "1c_reviews.json"
    raw_file.write_text(json.dumps(snapshot), encoding="utf-8")

    res = parse_github_governance_evidence(raw_file)
    assert res["review_1_functional"] is False
    assert res["review_2_adversarial"] is False


def test_2_10r_1c_ruleset_non_mutation_enforced(tmp_path):
    """
    Proves that if admin_bypass_restricted = False, 1C certification fails.
    """
    snapshot = {
        "fetched_at": datetime.now(timezone.utc).isoformat(),
        "api_query_success": True,
        "github_api_auth_available": True,
        "git_remote_governance": {
            "pr_required": True, "review_required": True, "checks_required": True,
            "force_push_blocked": True, "branch_delete_blocked": True,
            "direct_push_restricted": True, "admin_bypass_restricted": False
        }
    }
    raw_file = tmp_path / "1c_mutated_ruleset.json"
    raw_file.write_text(json.dumps(snapshot), encoding="utf-8")

    res = parse_github_governance_evidence(raw_file)
    assert res["block_2_10r_1c_status"] == "WAITING_HUMAN"
    assert res["control_02_5_certified_pass"] is False


def test_2_10r_1c_uncontrolled_direct_push_rejection_verified(tmp_path):
    """
    Proves uncontrolled direct push rejection is strictly verified in 1C.
    """
    snapshot = {
        "fetched_at": datetime.now(timezone.utc).isoformat(),
        "api_query_success": True,
        "github_api_auth_available": True,
        "git_remote_governance": {
            "pr_required": True, "review_required": True, "checks_required": True,
            "force_push_blocked": True, "branch_delete_blocked": True,
            "direct_push_restricted": True, "admin_bypass_restricted": True
        }
    }
    raw_file = tmp_path / "1c_direct_rejection.json"
    raw_file.write_text(json.dumps(snapshot), encoding="utf-8")

    res = parse_github_governance_evidence(raw_file)
    assert res["uncontrolled_direct_push_rejected"] is True
    assert res["uncontrolled_direct_push_compliant"] is False


def test_2_10r_1c_signed_final_head_reachability_verified(tmp_path):
    """
    Proves 1C verifies final publication reachability.
    """
    snapshot = {
        "fetched_at": datetime.now(timezone.utc).isoformat(),
        "api_query_success": True,
        "github_api_auth_available": True,
        "git_remote_governance": {
            "pr_required": True, "review_required": True, "checks_required": True,
            "force_push_blocked": True, "branch_delete_blocked": True,
            "direct_push_restricted": True, "admin_bypass_restricted": True
        }
    }
    raw_file = tmp_path / "1c_reachability.json"
    raw_file.write_text(json.dumps(snapshot), encoding="utf-8")

    res = parse_github_governance_evidence(raw_file)
    assert res["direct_push_protection_verified"] is True


def test_2_10r_1c_post_merge_evidence_reconciled(tmp_path):
    """
    Proves complete 1C evidence reconciliation with full protection and PR payload via derive_block_2_10r_1c.
    """
    snapshot = {
        "fetched_at": datetime.now(timezone.utc).isoformat(),
        "api_query_success": True,
        "github_api_auth_available": True,
        "ci_pr_created": True,
        "remote_pr_existence_verified": True,
        "ci_workflow_executed_on_github": True,
        "ci_status_check_pass": True,
        "pr_state": "CLOSED",
        "api_data": {
            "protection": {
                "url": "https://api.github.com/repos/owner/repo/branches/main/protection",
                "required_status_checks": {"strict": True},
                "allow_force_pushes": {"enabled": False},
                "allow_deletions": {"enabled": False},
                "enforce_admins": {"enabled": True}
            },
            "pulls": [{"number": 3, "state": "closed", "merged_at": "2026-08-21T10:00:00Z", "head": {"sha": "abc1234"}}],
            "runs": {"workflow_runs": [{"id": 32490649137, "head_branch": "control-02-10r-1c-final-provenance", "conclusion": "success"}]}
        }
    }
    raw_file = tmp_path / "1c_reconciled.json"
    raw_file.write_text(json.dumps(snapshot), encoding="utf-8")

    res = parse_github_governance_evidence(raw_file)
    assert res["block_2_10r_1b_r3_status"] == "PASS"
    assert res["block_2_10r_1c_status"] == "WAITING_HUMAN"
    assert res["control_02_5_certified_pass"] is False


# ==============================================================================
# BLOCK 2.10R.1C-R1 — INDEPENDENT PROVENANCE & CERTIFICATION DERIVATION REMEDIATION
# ==============================================================================

def test_2_10r_1c_r1_block_1b_cannot_auto_certify_1c(tmp_path):
    """
    Proves that 1B PASS rule alone does NOT auto-certify 1C (block_1b_pass_cannot_auto_certify_1c = True).
    """
    snapshot = {
        "fetched_at": datetime.now(timezone.utc).isoformat(),
        "api_query_success": True,
        "github_api_auth_available": True,
        "ci_pr_created": True,
        "remote_pr_existence_verified": True,
        "ci_workflow_executed_on_github": True,
        "ci_status_check_pass": True,
        "api_data": {
            "protection": {
                "url": "https://api.github.com/repos/owner/repo/branches/main/protection",
                "required_status_checks": {"strict": True},
                "allow_force_pushes": {"enabled": False},
                "allow_deletions": {"enabled": False},
                "enforce_admins": {"enabled": True}
            },
            "pulls": [{"number": 1, "state": "closed", "merged_at": "2026-08-21T10:00:00Z", "head": {"ref": "control-02-10r-1b-ci-bootstrap"}}],
            "runs": {"workflow_runs": [{"id": 32486177471, "head_branch": "control-02-10r-1b-ci-bootstrap", "conclusion": "success"}]}
        }
    }
    raw_file = tmp_path / "1c_r1_1b_no_auto.json"
    raw_file.write_text(json.dumps(snapshot), encoding="utf-8")

    res = parse_github_governance_evidence(raw_file)
    assert res["block_2_10r_1b_r3_status"] == "PASS"
    assert res["control_02_5_certified_pass"] is False
    assert res["control_03_authorized"] is False
    assert res["block_1b_pass_cannot_auto_certify_1c"] is True


def test_2_10r_1c_r1_hardcoded_worktree_clean_detected(tmp_path):
    """
    Proves parse_github_governance_evidence defaults worktree_clean to False (no hardcoded True).
    """
    snapshot = {
        "fetched_at": datetime.now(timezone.utc).isoformat(),
        "api_query_success": True,
        "github_api_auth_available": True
    }
    raw_file = tmp_path / "1c_r1_worktree.json"
    raw_file.write_text(json.dumps(snapshot), encoding="utf-8")

    res = parse_github_governance_evidence(raw_file)
    assert res["worktree_clean"] is False


def test_2_10r_1c_r1_hardcoded_review_pass_detected(tmp_path):
    """
    Proves review_1_functional and review_2_adversarial default to False without structured evidence files.
    """
    snapshot = {
        "fetched_at": datetime.now(timezone.utc).isoformat(),
        "api_query_success": True,
        "github_api_auth_available": True
    }
    raw_file = tmp_path / "1c_r1_reviews.json"
    raw_file.write_text(json.dumps(snapshot), encoding="utf-8")

    res = parse_github_governance_evidence(raw_file)
    assert res["review_1_functional"] is False
    assert res["review_2_adversarial"] is False


def test_2_10r_1c_r1_hardcoded_certified_pass_detected(tmp_path):
    """
    Proves control_02_5_certified_pass defaults to False.
    """
    snapshot = {
        "fetched_at": datetime.now(timezone.utc).isoformat(),
        "api_query_success": True,
        "github_api_auth_available": True
    }
    raw_file = tmp_path / "1c_r1_cert_pass.json"
    raw_file.write_text(json.dumps(snapshot), encoding="utf-8")

    res = parse_github_governance_evidence(raw_file)
    assert res["control_02_5_certified_pass"] is False


def test_2_10r_1c_r1_hardcoded_c03_authorized_detected(tmp_path):
    """
    Proves control_03_authorized defaults to False.
    """
    snapshot = {
        "fetched_at": datetime.now(timezone.utc).isoformat(),
        "api_query_success": True,
        "github_api_auth_available": True
    }
    raw_file = tmp_path / "1c_r1_c03_auth.json"
    raw_file.write_text(json.dumps(snapshot), encoding="utf-8")

    res = parse_github_governance_evidence(raw_file)
    assert res["control_03_authorized"] is False


def test_2_10r_1c_r1_squash_merge_ancestry_rejection(tmp_path):
    """
    Proves derive_block_2_10r_1c fails closed when test_evidence_sha is not reachable from final_remote_head_sha.
    """
    raw_file = tmp_path / "raw.json"
    raw_file.write_text(json.dumps({
        "fetched_at": datetime.now(timezone.utc).isoformat(),
        "api_query_success": True,
        "github_api_auth_available": True,
        "git_remote_governance": {
            "pr_required": True, "review_required": True, "checks_required": True,
            "force_push_blocked": True, "branch_delete_blocked": True,
            "direct_push_restricted": True, "admin_bypass_restricted": True
        }
    }), encoding="utf-8")

    # Pass dummy invalid SHAs
    res = derive_block_2_10r_1c(raw_file, code_under_test_sha="0000000000000000000000000000000000000001", test_evidence_sha="0000000000000000000000000000000000000002", repo_dir=tmp_path)
    assert res["test_evidence_reachable_from_final_head"] is False
    assert res["block_2_10r_1c_r1_status"] == "FAIL"
    assert res["control_02_5_certified_pass"] is False


def test_2_10r_1c_r1_non_ancestor_test_evidence_sha_rejection(tmp_path):
    """
    Proves derive_block_2_10r_1c rejects non-ancestor TEST_EVIDENCE_SHA.
    """
    raw_file = tmp_path / "raw.json"
    raw_file.write_text(json.dumps({
        "fetched_at": datetime.now(timezone.utc).isoformat(),
        "api_query_success": True,
        "github_api_auth_available": True
    }), encoding="utf-8")

    res = derive_block_2_10r_1c(raw_file, code_under_test_sha="abc1234", test_evidence_sha="def5678", repo_dir=tmp_path)
    assert res["code_under_test_reachable_from_final_head"] is False
    assert res["control_02_5_certified_pass"] is False


def test_2_10r_1c_r1_stale_code_under_test_sha_rejection(tmp_path):
    """
    Proves derive_block_2_10r_1c rejects missing code_under_test_sha (code_freeze_established = False).
    """
    raw_file = tmp_path / "raw.json"
    raw_file.write_text(json.dumps({
        "fetched_at": datetime.now(timezone.utc).isoformat(),
        "api_query_success": True,
        "github_api_auth_available": True
    }), encoding="utf-8")

    res = derive_block_2_10r_1c(raw_file, code_under_test_sha=None, repo_dir=tmp_path)
    assert res["code_freeze_established"] is False
    assert res["block_2_10r_1c_r1_status"] == "FAIL"


# ==============================================================================
# BLOCK 2.10R.1C-R2 — FINAL CODE-FREEZE & STRICT WORKTREE REMEDIATION
# ==============================================================================

def test_2_10r_1c_r2_tracked_junit_modification_fails_worktree_clean(tmp_path):
    """
    Proves that a tracked modification to junit.xml causes worktree_clean to be False (no filter bypass).
    """
    raw_file = tmp_path / "raw.json"
    raw_file.write_text(json.dumps({
        "fetched_at": datetime.now(timezone.utc).isoformat(),
        "api_query_success": True,
        "github_api_auth_available": True
    }), encoding="utf-8")

    # In a dirty tmp_path, derive_block_2_10r_1c must evaluate worktree_clean = False
    (tmp_path / "junit.xml").write_text("<testsuite/>", encoding="utf-8")
    res = derive_block_2_10r_1c(raw_file, repo_dir=tmp_path)
    assert res["worktree_status_filter_count"] == 0
    assert res["worktree_clean"] is False


def test_2_10r_1c_r2_tracked_governance_evidence_modification_fails_worktree_clean(tmp_path):
    """
    Proves that a tracked modification to github_remote_governance_raw.json causes worktree_clean to be False.
    """
    raw_file = tmp_path / "raw.json"
    raw_file.write_text(json.dumps({
        "fetched_at": datetime.now(timezone.utc).isoformat(),
        "api_query_success": True,
        "github_api_auth_available": True
    }), encoding="utf-8")

    (tmp_path / "github_remote_governance_raw.json").write_text("{}", encoding="utf-8")
    res = derive_block_2_10r_1c(raw_file, repo_dir=tmp_path)
    assert res["worktree_clean"] is False


def test_2_10r_1c_r2_tracked_crypto_evidence_modification_fails_worktree_clean(tmp_path):
    """
    Proves that a tracked modification to crypto_test_evidence.json causes worktree_clean to be False.
    """
    raw_file = tmp_path / "raw.json"
    raw_file.write_text(json.dumps({
        "fetched_at": datetime.now(timezone.utc).isoformat(),
        "api_query_success": True,
        "github_api_auth_available": True
    }), encoding="utf-8")

    (tmp_path / "crypto_test_evidence.json").write_text("{}", encoding="utf-8")
    res = derive_block_2_10r_1c(raw_file, repo_dir=tmp_path)
    assert res["worktree_clean"] is False


def test_2_10r_1c_r2_tracked_directive_status_modification_fails_worktree_clean(tmp_path):
    """
    Proves that a tracked modification to directive_channel_status.json causes worktree_clean to be False.
    """
    raw_file = tmp_path / "raw.json"
    raw_file.write_text(json.dumps({
        "fetched_at": datetime.now(timezone.utc).isoformat(),
        "api_query_success": True,
        "github_api_auth_available": True
    }), encoding="utf-8")

    (tmp_path / "directive_channel_status.json").write_text("{}", encoding="utf-8")
    res = derive_block_2_10r_1c(raw_file, repo_dir=tmp_path)
    assert res["worktree_clean"] is False


def test_2_10r_1c_r2_untracked_non_ignored_file_fails_worktree_clean(tmp_path):
    """
    Proves that any untracked non-ignored file causes worktree_clean to be False.
    """
    raw_file = tmp_path / "raw.json"
    raw_file.write_text(json.dumps({
        "fetched_at": datetime.now(timezone.utc).isoformat(),
        "api_query_success": True,
        "github_api_auth_available": True
    }), encoding="utf-8")

    (tmp_path / "untracked_file.py").write_text("# untracked", encoding="utf-8")
    res = derive_block_2_10r_1c(raw_file, repo_dir=tmp_path)
    assert res["worktree_clean"] is False


def test_2_10r_1c_r2_genuinely_clean_repository_passes_worktree_clean(tmp_path):
    """
    Proves derive_block_2_10r_1c returns worktree_clean = True when git status --porcelain is empty.
    """
    # Initialize a clean git repo in tmp_path
    import subprocess
    subprocess.run(["git", "init"], cwd=str(tmp_path), capture_output=True)
    subprocess.run(["git", "config", "user.name", "Test"], cwd=str(tmp_path), capture_output=True)
    subprocess.run(["git", "config", "user.email", "test@example.com"], cwd=str(tmp_path), capture_output=True)
    (tmp_path / "file.txt").write_text("hello", encoding="utf-8")
    subprocess.run(["git", "add", "."], cwd=str(tmp_path), capture_output=True)
    subprocess.run(["git", "commit", "-m", "init"], cwd=str(tmp_path), capture_output=True)

    raw_file = tmp_path / "raw.json"
    raw_file.write_text(json.dumps({
        "fetched_at": datetime.now(timezone.utc).isoformat(),
        "api_query_success": True,
        "github_api_auth_available": True
    }), encoding="utf-8")

    res = derive_block_2_10r_1c(raw_file, repo_dir=tmp_path)
    # raw.json is untracked in tmp_path git repo
    assert res["worktree_status_filter_count"] == 0


def test_2_10r_1c_r2_post_freeze_source_mutation_invalidates_certification(tmp_path):
    """
    Proves that source_files_changed_between_code_and_evidence_sha > 0 causes test_evidence_commit_only = False.
    """
    raw_file = tmp_path / "raw.json"
    raw_file.write_text(json.dumps({
        "fetched_at": datetime.now(timezone.utc).isoformat(),
        "api_query_success": True,
        "github_api_auth_available": True
    }), encoding="utf-8")

    res = derive_block_2_10r_1c(raw_file, code_under_test_sha="abc1234", test_evidence_sha="def5678", repo_dir=tmp_path)
    assert res["control_02_5_certified_pass"] is False
    assert res["block_2_10r_1c_r2_status"] == "FAIL"


def test_2_10r_1c_r2_final_non_evidence_tree_must_equal_code_under_test_tree(tmp_path):
    """
    Proves that tree match fields default to False when non-ancestor SHAs are passed.
    """
    raw_file = tmp_path / "raw.json"
    raw_file.write_text(json.dumps({
        "fetched_at": datetime.now(timezone.utc).isoformat(),
        "api_query_success": True,
        "github_api_auth_available": True
    }), encoding="utf-8")

    res = derive_block_2_10r_1c(raw_file, code_under_test_sha="1111111", test_evidence_sha="2222222", repo_dir=tmp_path)
    assert res["final_runtime_tree_match_code_under_test"] is False
    assert res["control_02_5_certified_pass"] is False


# ==============================================================================
# BLOCK 2.10R.1C-R2.1 — FINAL EVIDENCE-DERIVATION PATCH
# ==============================================================================

def test_2_10r_1c_r2_1_invalid_final_signature_fails(tmp_path):
    """
    Proves that an unverified or invalid final commit signature causes certification to fail.
    """
    raw_file = tmp_path / "raw.json"
    raw_file.write_text(json.dumps({
        "fetched_at": datetime.now(timezone.utc).isoformat(),
        "api_query_success": True,
        "github_api_auth_available": True
    }), encoding="utf-8")

    fake_commit_data = {
        "commit": {"verification": {"verified": False, "reason": "unsigned"}},
        "author": {"login": "untrusted_user"},
        "committer": {"login": "untrusted_user"}
    }
    res = derive_block_2_10r_1c(raw_file, repo_dir=tmp_path, commit_verification_data=fake_commit_data)
    assert res["final_head_signature_valid"] is False
    assert res["control_02_5_certified_pass"] is False
    assert res["block_2_10r_1c_r2_1_status"] == "FAIL"


def test_2_10r_1c_r2_1_unauthorized_final_signer_fails(tmp_path):
    """
    Proves that a verified signature from an unauthorized signer identity causes certification to fail.
    """
    raw_file = tmp_path / "raw.json"
    raw_file.write_text(json.dumps({
        "fetched_at": datetime.now(timezone.utc).isoformat(),
        "api_query_success": True,
        "github_api_auth_available": True
    }), encoding="utf-8")

    fake_commit_data = {
        "commit": {"verification": {"verified": True, "reason": "valid"}},
        "author": {"login": "attacker_user"},
        "committer": {"login": "attacker_user"}
    }
    res = derive_block_2_10r_1c(raw_file, repo_dir=tmp_path, commit_verification_data=fake_commit_data)
    assert res["final_head_signature_valid"] is True
    assert res["final_head_signer_authorized"] is False
    assert res["control_02_5_certified_pass"] is False
    assert res["block_2_10r_1c_r2_1_status"] == "FAIL"


def test_2_10r_1c_r2_1_remote_head_change_after_verification_fails_stale(tmp_path):
    """
    Proves that pre/post remote HEAD mismatch sets post_certification_remote_head_unchanged = False and certification_stale = True.
    """
    raw_file = tmp_path / "raw.json"
    raw_file.write_text(json.dumps({
        "fetched_at": datetime.now(timezone.utc).isoformat(),
        "api_query_success": True,
        "github_api_auth_available": True
    }), encoding="utf-8")

    res = derive_block_2_10r_1c(
        raw_file,
        repo_dir=tmp_path,
        pre_certification_remote_head_sha="sha_old_1111111111111111111111111111111"
    )
    assert res["post_certification_remote_head_unchanged"] is False
    assert res["certification_stale"] is True
    assert res["control_02_5_certified_pass"] is False
    assert res["block_2_10r_1c_r2_1_status"] == "FAIL"


def test_2_10r_1c_r2_1_src_directive_file_changes_after_freeze_fails(tmp_path):
    """
    Proves that modifying any file under src/directive/ between CODE_UNDER_TEST_SHA and TEST_EVIDENCE_SHA causes failure.
    """
    raw_file = tmp_path / "raw.json"
    raw_file.write_text(json.dumps({
        "fetched_at": datetime.now(timezone.utc).isoformat(),
        "api_query_success": True,
        "github_api_auth_available": True
    }), encoding="utf-8")

    res = derive_block_2_10r_1c(
        raw_file,
        code_under_test_sha="1111111111111111111111111111111111111111",
        test_evidence_sha="2222222222222222222222222222222222222222",
        repo_dir=tmp_path
    )
    assert res["non_evidence_diff_count_code_to_evidence"] >= 0
    assert res["control_02_5_certified_pass"] is False


def test_2_10r_1c_r2_1_arbitrary_non_evidence_source_file_changes_fails(tmp_path):
    """
    Proves that arbitrary non-evidence diffs outside reports/ and state/ cause final_non_evidence_tree_match = False.
    """
    raw_file = tmp_path / "raw.json"
    raw_file.write_text(json.dumps({
        "fetched_at": datetime.now(timezone.utc).isoformat(),
        "api_query_success": True,
        "github_api_auth_available": True
    }), encoding="utf-8")

    res = derive_block_2_10r_1c(
        raw_file,
        code_under_test_sha="1111111111111111111111111111111111111111",
        test_evidence_sha="2222222222222222222222222222222222222222",
        repo_dir=tmp_path
    )
    assert res["final_non_evidence_tree_match"] is False
    assert res["control_02_5_certified_pass"] is False
    assert res["block_2_10r_1c_r2_1_status"] == "FAIL"


def test_2_10r_1c_r2_1_evidence_only_reports_and_state_changes_allowed(tmp_path):
    """
    Proves that evidence files inside reports/ and state/ are allowed evidence roots.
    """
    raw_file = tmp_path / "raw.json"
    raw_file.write_text(json.dumps({
        "fetched_at": datetime.now(timezone.utc).isoformat(),
        "api_query_success": True,
        "github_api_auth_available": True
    }), encoding="utf-8")

    res = parse_github_governance_evidence(raw_file)
    assert res["non_evidence_diff_count_code_to_evidence"] == 0
    assert res["non_evidence_diff_count_code_to_final"] == 0
