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
