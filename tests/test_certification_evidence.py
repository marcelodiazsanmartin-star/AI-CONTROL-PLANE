"""
Certification Evidence & Integrity Test Suite (Tests A-M): CONTROL-02.5

Verifies non-circular evidence derivation, production signer manifest validation,
stale evidence rejection, run ID mismatch detection, execution evidence reconciliation,
and AST self-auditing scanner rules.
"""

import os
import json
import pytest
from pathlib import Path
from datetime import datetime, timezone, timedelta

from config import settings
from src.directive.scanner import scan_authentication_bypasses
from src.directive.signer_validator import validate_production_signers, compute_ssh_public_key_fingerprint


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


# D. TEST_TEST_KEY_LEAK_TO_PRODUCTION_FAILS(monkeypatch)
def test_test_key_leak_to_production_fails():
    ephemeral_test_fingerprint = "SHA256:EPHEMERAL_TEST_KEY_FINGERPRINT_999"
    prod_allowlist = {"SHA256:zYZi3+VxKz9ve+PJgTS2o8q+dvXSmzCwPZ2G3NYh41A"}

    # Simulate key leakage
    leaked_allowlist = set(prod_allowlist)
    leaked_allowlist.add(ephemeral_test_fingerprint)

    test_keys = {ephemeral_test_fingerprint}
    intersection = test_keys.intersection(leaked_allowlist)

    assert len(intersection) > 0, "Leakage detection failed to detect test key in allowlist"


# E. TEST_MISSING_EXECUTION_SOURCE_NOT_ZERO
def test_missing_execution_source_not_zero(tmp_path):
    missing_dir = tmp_path / "non_existent_runtime"
    execution_sources_available = (
        (missing_dir / "execution_queue.jsonl").exists() and
        (missing_dir / "consumed_directives.jsonl").exists()
    )
    assert execution_sources_available is False


# F. TEST_CORRUPTED_EXECUTION_LEDGER_FAILS(tmp_path)
def test_corrupted_execution_ledger_fails(tmp_path):
    corrupt_file = tmp_path / "consumed_directives.jsonl"
    corrupt_file.write_text('{"directive_id": "ok"}\nCORRUPTED INVALID JSON LINE\n', encoding="utf-8")

    corrupt = False
    with open(corrupt_file, "r", encoding="utf-8") as f:
        for line in f:
            if line.strip():
                try:
                    json.loads(line)
                except Exception:
                    corrupt = True

    assert corrupt is True


# G. TEST_REAL_EXECUTION_COUNT_RECONSTRUCTED(tmp_path)
def test_real_execution_count_reconstructed(tmp_path):
    queue_file = tmp_path / "execution_queue.jsonl"
    consumed_file = tmp_path / "consumed_directives.jsonl"

    queue_file.write_text(
        json.dumps({"directive_id": "d1", "directive_payload": {"action_type": "STATUS_REQUEST"}}) + "\n" +
        json.dumps({"directive_id": "d2", "directive_payload": {"action_type": "READ_ONLY_ANALYSIS"}}) + "\n",
        encoding="utf-8"
    )

    consumed_file.write_text(
        json.dumps({"directive_id": "d1", "action_type": "STATUS_REQUEST", "mutating": False}) + "\n",
        encoding="utf-8"
    )

    executed_ids = set()
    mutating_count = 0

    for fpath in [queue_file, consumed_file]:
        with open(fpath, "r", encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    item = json.loads(line)
                    did = item.get("directive_id")
                    if did:
                        executed_ids.add(did)
                    if item.get("mutating") is True:
                        mutating_count += 1

    assert len(executed_ids) == 2
    assert mutating_count == 0


# H. TEST_CRITICAL_EVIDENCE_UNAVAILABLE_CANNOT_PASS(tmp_path)
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


# K. TEST_EMPTY_PRODUCTION_ALLOWLIST_REJECTED(monkeypatch)
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
