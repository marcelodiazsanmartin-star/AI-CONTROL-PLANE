"""
Real Cryptographic Integration Tests for CONTROL-02.5 (Round 3 Hardened)

Uses native Git SSH commit signing with ephemeral ED25519 keys generated per test suite.
ZERO monkeypatching of DirectiveAuthenticator.verify_commit_signature().
ZERO monkeypatching of subprocess.run() for Git verification.
Generates fresh reports/crypto_test_evidence.json bound to environment CERTIFICATION_RUN_ID.
"""

import os
import json
import shutil
import subprocess
import re
from pathlib import Path
from datetime import datetime, timezone, timedelta
import pytest

from config import settings
from src.directive.contracts import (
    DirectivePayload, DirectiveEnvelope, ValidationStatus
)
from src.directive.authenticator import DirectiveAuthenticator

# Global container for evidence cases
CRYPTO_EVIDENCE_CASES = {}


def get_ssh_keygen_bin() -> str:
    for candidate in [
        r"C:\Program Files\Git\usr\bin\ssh-keygen.exe",
        r"C:\Program Files (x86)\Git\usr\bin\ssh-keygen.exe",
        "ssh-keygen"
    ]:
        try:
            res = subprocess.run([candidate, "-?"], capture_output=True, text=True)
            if res.returncode in (0, 1):
                return candidate
        except Exception:
            pass
    return "ssh-keygen"


def setup_crypto_test_repo(tmp_path: Path) -> tuple:
    repo = tmp_path / "real_crypto_repo"
    repo.mkdir(parents=True, exist_ok=True)

    ssh_keygen_bin = get_ssh_keygen_bin()

    subprocess.run(["git", "-C", str(repo), "init"], capture_output=True, check=True)
    subprocess.run(["git", "-C", str(repo), "config", "user.name", "Test Signer"], capture_output=True, check=True)
    subprocess.run(["git", "-C", str(repo), "config", "user.email", "test@example.com"], capture_output=True, check=True)

    # 1. Ephemeral Trusted Key
    trusted_key_file = tmp_path / "id_ed25519_trusted"
    subprocess.run([ssh_keygen_bin, "-t", "ed25519", "-N", "", "-f", str(trusted_key_file)], capture_output=True, check=True)
    trusted_pub_file = tmp_path / "id_ed25519_trusted.pub"
    trusted_pub = trusted_pub_file.read_text(encoding="utf-8").strip()

    # 2. Ephemeral Untrusted Key
    untrusted_key_file = tmp_path / "id_ed25519_untrusted"
    subprocess.run([ssh_keygen_bin, "-t", "ed25519", "-N", "", "-f", str(untrusted_key_file)], capture_output=True, check=True)
    untrusted_pub_file = tmp_path / "id_ed25519_untrusted.pub"
    untrusted_pub = untrusted_pub_file.read_text(encoding="utf-8").strip()

    # Write allowed_signers file mapping test@example.com to BOTH keys so git verify-commit evaluates cryptographic validity
    allowed_signers_file = repo / "allowed_signers"
    allowed_signers_file.write_text(f"test@example.com {trusted_pub}\ntest@example.com {untrusted_pub}\n", encoding="utf-8")

    # Configure Git in test repo
    subprocess.run(["git", "-C", str(repo), "config", "gpg.format", "ssh"], capture_output=True, check=True)
    subprocess.run(["git", "-C", str(repo), "config", "user.signingkey", str(trusted_key_file)], capture_output=True, check=True)
    subprocess.run(["git", "-C", str(repo), "config", "gpg.ssh.allowedSignersFile", str(allowed_signers_file)], capture_output=True, check=True)

    # Extract exact SSH fingerprint of trusted key
    verify_cmd = subprocess.run([ssh_keygen_bin, "-l", "-f", str(trusted_pub_file)], capture_output=True, text=True, check=True)
    trusted_fingerprint = verify_cmd.stdout.strip().split()[1]

    # Extract exact SSH fingerprint of untrusted key
    verify_cmd2 = subprocess.run([ssh_keygen_bin, "-l", "-f", str(untrusted_pub_file)], capture_output=True, text=True, check=True)
    untrusted_fingerprint = verify_cmd2.stdout.strip().split()[1]

    return repo, trusted_key_file, untrusted_key_file, trusted_fingerprint, untrusted_fingerprint


def create_real_signed_directive_commit(
    repo: Path,
    directive_id: str,
    signed: bool = True,
    use_key_file: Path = None,
    custom_author: str = None
) -> tuple:
    inbox_dir = repo / "directives" / "inbox"
    inbox_dir.mkdir(parents=True, exist_ok=True)

    now_dt = datetime.now(timezone.utc)
    created_at = now_dt.isoformat()
    expires_at = (now_dt + timedelta(hours=1)).isoformat()

    directive_file = inbox_dir / f"{directive_id}.json"

    placeholder_dict = {
        "directive_version": "1.0",
        "directive_id": directive_id,
        "project": "AI-CONTROL-PLANE",
        "target_project": "MICRO-MARKET-ORACLE",
        "target_stage": "MICRO-00.8",
        "action_type": "STATUS_REQUEST",
        "action": "CHATGPT_AUDIT_MICRO_00_8",
        "created_at": created_at,
        "expires_at": expires_at,
        "issued_by": "CHATGPT",
        "source_repository": "AI-CONTROL-PLANE",
        "source_branch": "main",
        "source_commit_sha": "PENDING",
        "requires_human_approval": False,
        "allowed_scope": ["READ"],
        "preconditions": {},
        "success_criteria": {},
        "failure_policy": "REJECT_AND_LOG",
        "rollback_policy": "NO_MUTATION",
        "payload": {},
        "envelope": {
            "directive_id": directive_id,
            "payload_commit_sha": "PENDING",
            "payload_blob_sha": "UNKNOWN_BLOB",
            "payload_sha256": "UNKNOWN_HASH",
            "trusted_remote": "AI-CONTROL-PLANE",
            "trusted_branch": "main",
            "authentication_version": "2.0",
            "signature_present": signed,
            "signature_valid": signed,
            "signer_identity": "ephemeral_signer",
            "signer_allowed": True
        }
    }

    directive_file.write_text(json.dumps(placeholder_dict, indent=2), encoding="utf-8")
    subprocess.run(["git", "-C", str(repo), "add", "."], capture_output=True, check=True)

    commit_cmd = ["git", "-C", str(repo), "commit"]
    if signed:
        commit_cmd.append("-S")
        if use_key_file:
            subprocess.run(["git", "-C", str(repo), "config", "user.signingkey", str(use_key_file)], capture_output=True, check=True)
    else:
        commit_cmd.append("--no-gpg-sign")

    commit_cmd.extend(["-m", f"real commit {directive_id}"])
    if custom_author:
        commit_cmd.extend(["--author", custom_author])

    subprocess.run(commit_cmd, capture_output=True, check=True)

    commit_sha = subprocess.run(
        ["git", "-C", str(repo), "rev-parse", "HEAD"],
        capture_output=True,
        text=True,
        check=True
    ).stdout.strip()

    # Update payload & envelope commit_sha and amend commit
    full_dict = dict(placeholder_dict)
    full_dict["source_commit_sha"] = commit_sha
    full_dict["envelope"]["payload_commit_sha"] = commit_sha

    directive_file.write_text(json.dumps(full_dict, indent=2), encoding="utf-8")
    subprocess.run(["git", "-C", str(repo), "add", "."], capture_output=True, check=True)

    amend_cmd = ["git", "-C", str(repo), "commit", "--amend", "--no-edit"]
    if signed:
        amend_cmd.append("-S")
    else:
        amend_cmd.append("--no-gpg-sign")
    subprocess.run(amend_cmd, capture_output=True, check=True)

    actual_sha = subprocess.run(
        ["git", "-C", str(repo), "rev-parse", "HEAD"],
        capture_output=True,
        text=True,
        check=True
    ).stdout.strip()

    full_dict["source_commit_sha"] = actual_sha
    full_dict["envelope"]["payload_commit_sha"] = actual_sha
    directive_file.write_text(json.dumps(full_dict, indent=2), encoding="utf-8")

    subprocess.run(["git", "-C", str(repo), "add", "."], capture_output=True, check=True)
    amend_cmd2 = ["git", "-C", str(repo), "commit", "--amend", "--no-edit"]
    if signed:
        amend_cmd2.append("-S")
    else:
        amend_cmd2.append("--no-gpg-sign")
    subprocess.run(amend_cmd2, capture_output=True, check=True)

    final_sha = subprocess.run(
        ["git", "-C", str(repo), "rev-parse", "HEAD"],
        capture_output=True,
        text=True,
        check=True
    ).stdout.strip()

    full_dict["source_commit_sha"] = final_sha
    full_dict["envelope"]["payload_commit_sha"] = final_sha

    payload = DirectivePayload.from_dict(full_dict)
    envelope = DirectiveEnvelope.from_dict(full_dict["envelope"])

    return repo, final_sha, payload, envelope, directive_file


def _record_evidence_case(case_name: str, repo: Path, commit_sha: str, fingerprint: str = None, expected_returncode: int = 0):
    CRYPTO_EVIDENCE_CASES[case_name] = {
        "repo_path": str(repo),
        "commit_sha": commit_sha,
        "fingerprint": fingerprint,
        "expected_verify_returncode": expected_returncode
    }
    _write_fresh_crypto_evidence_file()


def _write_fresh_crypto_evidence_file():
    reports_dir = settings.CONTROL_PLANE_ROOT / "reports"
    reports_dir.mkdir(parents=True, exist_ok=True)
    evidence_file = reports_dir / "crypto_test_evidence.json"

    run_id = os.environ.get("CERTIFICATION_RUN_ID", "DEV_SESSION_LOCAL_RUN")
    gen_time = os.environ.get("CERTIFICATION_STARTED_AT", datetime.now(timezone.utc).isoformat())

    evidence_data = {
        "certification_run_id": run_id,
        "generated_at": gen_time,
        "backend": "SSH",
        "cases": CRYPTO_EVIDENCE_CASES
    }

    with open(evidence_file, "w", encoding="utf-8") as f:
        json.dump(evidence_data, f, indent=2)


# REQUIRED REAL TEST A: REAL_UNSIGNED_COMMIT_REJECTED
def test_real_unsigned_commit_rejected(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "REQUIRE_COMMIT_SIGNATURE_VERIFICATION", True)
    repo, trusted_key, untrusted_key, trusted_fp, untrusted_fp = setup_crypto_test_repo(tmp_path)
    repo, commit_sha, payload, envelope, directive_file = create_real_signed_directive_commit(
        repo, "unsigned-real-001", signed=False
    )

    _record_evidence_case("unsigned", repo, commit_sha, expected_returncode=1)

    auth = DirectiveAuthenticator(repo_root=repo)
    auth.query_remote_branch_head = lambda path: (commit_sha, None)

    val_status, val_msg, human_wait, meta = auth.authenticate(payload, envelope, directive_file)

    assert val_status == ValidationStatus.COMMIT_SIGNATURE_MISSING
    assert "COMMIT_SIGNATURE_MISSING" in val_msg
    assert meta["signature_present"] is False
    assert meta["signature_valid"] is False
    assert meta["signer_allowed"] is False


# REQUIRED REAL TEST B: REAL_VALID_TRUSTED_SIGNED_COMMIT_ACCEPTED
def test_real_valid_trusted_signed_commit_accepted(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "REQUIRE_COMMIT_SIGNATURE_VERIFICATION", True)
    repo, trusted_key, untrusted_key, trusted_fp, untrusted_fp = setup_crypto_test_repo(tmp_path)
    repo, commit_sha, payload, envelope, directive_file = create_real_signed_directive_commit(
        repo, "valid-trusted-001", signed=True, use_key_file=trusted_key
    )

    _record_evidence_case("trusted_signed", repo, commit_sha, fingerprint=trusted_fp, expected_returncode=0)

    monkeypatch.setattr(settings, "TRUSTED_SIGNER_ALLOWLIST", {trusted_fp, "test@example.com"})

    auth = DirectiveAuthenticator(repo_root=repo)
    auth.query_remote_branch_head = lambda path: (commit_sha, None)

    val_status, val_msg, human_wait, meta = auth.authenticate(payload, envelope, directive_file)

    assert val_status == ValidationStatus.AUTHENTIC or "WAITING_HUMAN" in val_msg
    assert meta["signature_present"] is True
    assert meta["signature_valid"] is True
    assert meta["signer_allowed"] is True


# REQUIRED REAL TEST C: REAL_VALID_UNTRUSTED_SIGNED_COMMIT_REJECTED
def test_real_valid_untrusted_signed_commit_rejected(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "REQUIRE_COMMIT_SIGNATURE_VERIFICATION", True)
    repo, trusted_key, untrusted_key, trusted_fp, untrusted_fp = setup_crypto_test_repo(tmp_path)

    repo, commit_sha, payload, envelope, directive_file = create_real_signed_directive_commit(
        repo, "valid-untrusted-001", signed=True, use_key_file=untrusted_key
    )

    _record_evidence_case("untrusted_signed", repo, commit_sha, fingerprint=untrusted_fp, expected_returncode=0)

    monkeypatch.setattr(settings, "TRUSTED_SIGNER_ALLOWLIST", {trusted_fp})

    auth = DirectiveAuthenticator(repo_root=repo)
    auth.query_remote_branch_head = lambda path: (commit_sha, None)

    val_status, val_msg, human_wait, meta = auth.authenticate(payload, envelope, directive_file)

    assert val_status == ValidationStatus.UNTRUSTED_COMMIT_SIGNER
    assert "UNTRUSTED_COMMIT_SIGNER" in val_msg
    assert meta["signature_present"] is True
    assert meta["signature_valid"] is True
    assert meta["signer_allowed"] is False


# REQUIRED REAL TEST D: REAL_INVALID_SIGNATURE_REJECTED
def test_real_invalid_signature_rejected(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "REQUIRE_COMMIT_SIGNATURE_VERIFICATION", True)
    repo, trusted_key, untrusted_key, trusted_fp, untrusted_fp = setup_crypto_test_repo(tmp_path)

    allowed_signers_file = repo / "allowed_signers"
    allowed_signers_file.write_text("", encoding="utf-8")

    repo, commit_sha, payload, envelope, directive_file = create_real_signed_directive_commit(
        repo, "invalid-sig-001", signed=True, use_key_file=trusted_key
    )

    _record_evidence_case("invalid_signature", repo, commit_sha, expected_returncode=1)

    auth = DirectiveAuthenticator(repo_root=repo)
    auth.query_remote_branch_head = lambda path: (commit_sha, None)

    val_status, val_msg, human_wait, meta = auth.authenticate(payload, envelope, directive_file)

    assert val_status == ValidationStatus.COMMIT_SIGNATURE_INVALID or "COMMIT_SIGNATURE_INVALID" in val_msg or meta["signature_valid"] is False
    assert meta["signature_present"] is True
    assert meta["signature_valid"] is False
    assert meta["signer_allowed"] is False


# REQUIRED REAL TEST E: AUTHOR_SPOOF_CANNOT_AUTHORIZE
def test_author_spoof_cannot_authorize(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "REQUIRE_COMMIT_SIGNATURE_VERIFICATION", True)
    repo, trusted_key, untrusted_key, trusted_fp, untrusted_fp = setup_crypto_test_repo(tmp_path)

    spoofed_author = "marcelodiazsanmartin-star <trusted@antigravity.ai>"
    repo, commit_sha, payload, envelope, directive_file = create_real_signed_directive_commit(
        repo, "author-spoof-001", signed=False, custom_author=spoofed_author
    )

    auth = DirectiveAuthenticator(repo_root=repo)
    auth.query_remote_branch_head = lambda path: (commit_sha, None)

    val_status, val_msg, human_wait, meta = auth.authenticate(payload, envelope, directive_file)

    assert val_status == ValidationStatus.COMMIT_SIGNATURE_MISSING
    assert meta["signer_allowed"] is False


# REQUIRED REAL TEST F: ENVELOPE_SELF_ATTESTATION_CANNOT_AUTHORIZE
def test_envelope_self_attestation_cannot_authorize(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "REQUIRE_COMMIT_SIGNATURE_VERIFICATION", True)
    repo, trusted_key, untrusted_key, trusted_fp, untrusted_fp = setup_crypto_test_repo(tmp_path)

    repo, commit_sha, payload, envelope, directive_file = create_real_signed_directive_commit(
        repo, "envelope-self-attest-001", signed=False
    )

    envelope.signature_present = True
    envelope.signature_valid = True
    envelope.signer_allowed = True
    envelope.signer_identity = trusted_fp

    auth = DirectiveAuthenticator(repo_root=repo)
    auth.query_remote_branch_head = lambda path: (commit_sha, None)

    val_status, val_msg, human_wait, meta = auth.authenticate(payload, envelope, directive_file)

    assert val_status == ValidationStatus.COMMIT_SIGNATURE_MISSING
    assert meta["signature_valid"] is False
    assert meta["signer_allowed"] is False
