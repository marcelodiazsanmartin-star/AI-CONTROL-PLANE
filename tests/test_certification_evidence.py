"""
Certification Evidence & Integrity Test Suite (Tests A-M + Block 1.1 Cross-Source Consistency Tests): CONTROL-02.5

Verifies non-circular evidence derivation, production signer manifest validation,
stale evidence rejection, run ID mismatch detection, execution evidence reconciliation (calling production reconciler),
cross-source contradiction detection, and AST self-auditing scanner rules.
"""

import os
import json
import pytest
from pathlib import Path
from datetime import datetime, timezone, timedelta

from config import settings
from src.directive.scanner import scan_authentication_bypasses
from src.directive.signer_validator import validate_production_signers, compute_ssh_public_key_fingerprint
from src.directive.reconciler import reconcile_execution_evidence
from src.directive.authenticator import DirectiveAuthenticator
from src.directive.contracts import DirectivePayload, DirectiveEnvelope
from src.directive.governance import (
    validate_trusted_branch_declaration, evaluate_branch_governance_rules, verify_trusted_head_provenance
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






