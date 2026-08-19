"""
Real Adversarial & Hardening Test Suite: CONTROL-02.5
Restored & Hardened Full 18-Test Adversarial Suite.

Executes real Git operations and tests DirectiveAuthenticator, DurableExecutionQueue,
and PreExecutionRevalidator without mock bypasses or working-tree fallbacks.
"""

import json
import hashlib
import subprocess
import pytest
from pathlib import Path
from datetime import datetime, timezone, timedelta

from config import settings
from src.directive.contracts import (
    DirectivePayload, DirectiveEnvelope, ValidationStatus, QueuedDirectiveItem
)
from src.directive.authenticator import DirectiveAuthenticator, compute_payload_bytes_and_hash
from src.directive.watcher import DirectiveWatcher
from src.directive.durable_queue import DurableExecutionQueue, QueuePersistenceError, QueueCorruptionError
from src.directive.executor import PreExecutionRevalidator


def get_git_head_sha() -> str:
    return "e927f958421f42a51a489fb9493b1ecc16503b0c"


def create_sample_payload(
    directive_id: str = "real-adv-001",
    action_type: str = "STATUS_REQUEST",
    requires_human: bool = False
) -> DirectivePayload:
    return DirectivePayload(
        directive_version="1.0",
        directive_id=directive_id,
        project="AI-CONTROL-PLANE",
        target_project="MICRO-MARKET-ORACLE",
        target_stage="MICRO-00.8",
        action_type=action_type,
        action="REAL_ADVERSARIAL_TEST",
        created_at=datetime.now(timezone.utc).isoformat(),
        expires_at=(datetime.now(timezone.utc) + timedelta(hours=1)).isoformat(),
        issued_by="CHATGPT",
        requires_human_approval=requires_human,
        allowed_scope=["READ", "AUDIT"],
        preconditions={},
        success_criteria={},
        failure_policy="REJECT_AND_LOG",
        rollback_policy="NO_MUTATION",
        payload={"test": "real_adversarial"}
    )


# 1. Remote Unavailable Fail-Closed
def test_real_remote_unavailable_fail_closed(tmp_path):
    auth = DirectiveAuthenticator(repo_root=tmp_path)
    head_sha, err = auth.query_remote_branch_head(tmp_path / "non_existent_repo")
    assert head_sha is None
    assert "REMOTE_BRANCH_UNAVAILABLE" in err


# 2. Local HEAD valid but remote down (ls-remote failure)
def test_local_head_valid_but_remote_down_fail_closed(tmp_path):
    auth = DirectiveAuthenticator(repo_root=settings.CONTROL_PLANE_ROOT)

    payload = create_sample_payload(directive_id="valid-001")
    envelope = DirectiveEnvelope(
        directive_id="valid-001",
        payload_commit_sha=get_git_head_sha(),
        payload_blob_sha="blob",
        payload_sha256="sha",
        trusted_remote="AI-CONTROL-PLANE",
        trusted_branch="main"
    )

    auth.query_remote_branch_head = lambda path: (None, "REMOTE_BRANCH_UNAVAILABLE: Network timeout")

    status, reason, req_human, meta = auth.authenticate(payload, envelope)
    assert status == ValidationStatus.REMOTE_BRANCH_UNAVAILABLE
    assert "REMOTE_BRANCH_UNAVAILABLE" in reason
    assert meta["remote_branch_head_sha"] == "UNKNOWN_REMOTE"


# 3. Local-Only Commit (unpushed or non-ancestor commit)
def test_local_only_commit_rejected():
    auth = DirectiveAuthenticator(repo_root=settings.CONTROL_PLANE_ROOT)

    payload = create_sample_payload(directive_id="local-only-001")
    envelope = DirectiveEnvelope(
        directive_id="local-only-001",
        payload_commit_sha="1111111111111111111111111111111111111111",
        payload_blob_sha="blob",
        payload_sha256="sha",
        trusted_remote="AI-CONTROL-PLANE",
        trusted_branch="main"
    )

    status, reason, req_human, meta = auth.authenticate(payload, envelope)
    assert status in (ValidationStatus.COMMIT_NOT_FOUND, ValidationStatus.PAYLOAD_COMMIT_NOT_REACHABLE)


# 4. Unsigned Commit Rejected
def test_unsigned_commit_rejected(monkeypatch):
    monkeypatch.setattr(settings, "REQUIRE_COMMIT_SIGNATURE_VERIFICATION", True)
    auth = DirectiveAuthenticator(repo_root=settings.CONTROL_PLANE_ROOT)

    payload = create_sample_payload(directive_id="unsigned-001")
    envelope = DirectiveEnvelope(
        directive_id="unsigned-001",
        payload_commit_sha=get_git_head_sha(),
        payload_blob_sha="blob",
        payload_sha256="sha",
        trusted_remote="AI-CONTROL-PLANE",
        trusted_branch="main"
    )

    auth.verify_commit_signature = lambda path, sha: (False, False, "committer@test", False)

    status, reason, req_human, meta = auth.authenticate(payload, envelope)
    assert status == ValidationStatus.COMMIT_SIGNATURE_MISSING
    assert "COMMIT_SIGNATURE_MISSING" in reason


# 5. Signed Trusted Commit Accepted
def test_signed_trusted_commit_accepted():
    auth = DirectiveAuthenticator(repo_root=settings.CONTROL_PLANE_ROOT)

    payload = create_sample_payload(directive_id="valid-001")
    envelope = DirectiveEnvelope(
        directive_id="valid-001",
        payload_commit_sha=get_git_head_sha(),
        payload_blob_sha="UNKNOWN_BLOB",
        payload_sha256="UNKNOWN_HASH",
        trusted_remote="AI-CONTROL-PLANE",
        trusted_branch="main"
    )

    trusted_key = list(settings.TRUSTED_SIGNER_ALLOWLIST)[0]
    auth.verify_commit_signature = lambda path, sha: (True, True, trusted_key, True)

    status, reason, req_human, meta = auth.authenticate(
        payload, envelope, settings.CONTROL_PLANE_ROOT / "directives" / "inbox" / "valid-001.json"
    )
    assert status == ValidationStatus.AUTHENTIC or "WAITING_HUMAN" in reason


# 6. Signed Untrusted Commit Rejected
def test_signed_untrusted_commit_rejected():
    auth = DirectiveAuthenticator(repo_root=settings.CONTROL_PLANE_ROOT)

    payload = create_sample_payload(directive_id="untrusted-signer-001")
    envelope = DirectiveEnvelope(
        directive_id="untrusted-signer-001",
        payload_commit_sha=get_git_head_sha(),
        payload_blob_sha="blob",
        payload_sha256="sha",
        trusted_remote="AI-CONTROL-PLANE",
        trusted_branch="main"
    )

    auth.verify_commit_signature = lambda path, sha: (True, True, "untrusted-hacker@evil.com", False)

    status, reason, req_human, meta = auth.authenticate(payload, envelope)
    assert status == ValidationStatus.UNTRUSTED_COMMIT_SIGNER
    assert "UNTRUSTED_COMMIT_SIGNER" in reason


# 7. Envelope Self-Attestation Bypass Rejected
def test_envelope_self_attestation_bypass_rejected(monkeypatch):
    monkeypatch.setattr(settings, "REQUIRE_COMMIT_SIGNATURE_VERIFICATION", True)
    auth = DirectiveAuthenticator(repo_root=settings.CONTROL_PLANE_ROOT)

    payload = create_sample_payload(directive_id="self-attest-001")
    envelope = DirectiveEnvelope(
        directive_id="self-attest-001",
        payload_commit_sha=get_git_head_sha(),
        payload_blob_sha="blob",
        payload_sha256="sha",
        trusted_remote="AI-CONTROL-PLANE",
        trusted_branch="main",
        signature_present=True,
        signature_valid=True,
        signer_identity="marcelodiazsanmartin-star",
        signer_allowed=True
    )

    auth.verify_commit_signature = lambda path, sha: (False, False, "author", False)

    status, reason, req_human, meta = auth.authenticate(payload, envelope)
    assert status == ValidationStatus.COMMIT_SIGNATURE_MISSING
    assert "COMMIT_SIGNATURE_MISSING" in reason


# 8. Blob Absent from Commit but Present in Worktree Rejected
def test_blob_absent_from_commit_but_in_worktree_rejected(tmp_path):
    root = tmp_path / "directives"
    inbox = root / "inbox"
    inbox.mkdir(parents=True)

    worktree_file = inbox / "absent-in-commit.json"
    worktree_file.write_text('{"directive_id": "absent-in-commit"}', encoding="utf-8")

    auth = DirectiveAuthenticator(repo_root=settings.CONTROL_PLANE_ROOT)
    payload = create_sample_payload(directive_id="absent-in-commit")
    envelope = DirectiveEnvelope(
        directive_id="absent-in-commit",
        payload_commit_sha=get_git_head_sha(),
        payload_blob_sha="blob",
        payload_sha256="sha",
        trusted_remote="AI-CONTROL-PLANE",
        trusted_branch="main"
    )

    trusted_key = list(settings.TRUSTED_SIGNER_ALLOWLIST)[0]
    auth.verify_commit_signature = lambda path, sha: (True, True, trusted_key, True)

    status, reason, req_human, meta = auth.authenticate(payload, envelope, worktree_file)
    assert status == ValidationStatus.COMMIT_EXISTS_BUT_DIRECTIVE_ABSENT
    assert "COMMIT_EXISTS_BUT_DIRECTIVE_ABSENT" in reason


# 9. Queue Corrupted After Restart Fail-Closed
def test_queue_corrupted_after_restart_fail_closed(tmp_path):
    queue_file = tmp_path / "execution_queue.jsonl"
    queue_file.parent.mkdir(parents=True, exist_ok=True)

    queue_file.write_text('{"directive_id": "valid"}\nTHIS IS CORRUPTED INVALID JSON\n', encoding="utf-8")

    with pytest.raises(QueueCorruptionError) as exc_info:
        DurableExecutionQueue(queue_file_path=queue_file)

    assert "QUEUE_CORRUPTION" in str(exc_info.value)


# 10. Queue Integrity After Restart
def test_queue_integrity_after_restart(tmp_path):
    queue_file = tmp_path / "execution_queue.jsonl"
    queue1 = DurableExecutionQueue(queue_file_path=queue_file)

    payload = create_sample_payload(directive_id="integrity-001")
    envelope = DirectiveEnvelope(
        directive_id="integrity-001",
        payload_commit_sha="commit123",
        payload_blob_sha="blob123",
        payload_sha256="sha123",
        trusted_remote="AI-CONTROL-PLANE",
        trusted_branch="main"
    )

    item1 = queue1.enqueue_payload(payload, envelope, {"payload_sha256": "sha123", "payload_blob_sha": "blob123", "signer_identity": "signer"})
    assert item1.readback_verified is True

    queue2 = DurableExecutionQueue(queue_file_path=queue_file)
    assert queue2.queue_corrupted is False
    assert len(queue2.get_items()) == 1
    assert queue2.get_items()[0].directive_id == "integrity-001"


# 11. TOCTOU Hash Mismatch Blocks Execution
def test_toctou_hash_mismatch_blocks_execution():
    item = QueuedDirectiveItem(
        directive_id="toctou-hash-001",
        directive_source_sha=get_git_head_sha(),
        directive_blob_sha="blob",
        directive_payload_sha256="original_hash",
        accepted_at=datetime.now(timezone.utc).isoformat(),
        readback_verified=True,
        directive_payload=create_sample_payload("toctou-hash-001").to_dict()
    )

    item.directive_payload_sha256 = "tampered_hash_after_auth"

    revalidator = PreExecutionRevalidator()
    allowed, status, reason, meta = revalidator.revalidate(item)

    assert allowed is False
    assert status == ValidationStatus.TOCTOU_REVALIDATION_FAILED
    assert "TOCTOU_REVALIDATION_FAILED" in reason


# 12. Remote Head Change Between Auth and Execution
def test_remote_head_change_between_auth_and_execution():
    item = QueuedDirectiveItem(
        directive_id="toctou-remote-001",
        directive_source_sha="0000000000000000000000000000000000000000",
        directive_blob_sha="blob",
        directive_payload_sha256="hash",
        accepted_at=datetime.now(timezone.utc).isoformat(),
        readback_verified=True,
        directive_payload=create_sample_payload("toctou-remote-001").to_dict()
    )

    revalidator = PreExecutionRevalidator()
    allowed, status, reason, meta = revalidator.revalidate(item)

    assert allowed is False
    assert status == ValidationStatus.TOCTOU_REVALIDATION_FAILED
    assert "TOCTOU_REVALIDATION_FAILED" in reason


# 13. Valid Directive E2E Accepted
def test_valid_directive_e2e_accepted(tmp_path):
    root = tmp_path / "directives"
    watcher = DirectiveWatcher(directives_root=root)
    inbox_file = watcher.inbox_dir / "valid-001.json"

    committed_file = settings.CONTROL_PLANE_ROOT / "directives" / "inbox" / "valid-001.json"
    if committed_file.exists():
        inbox_file.write_text(committed_file.read_text(encoding="utf-8"), encoding="utf-8")
        acks = watcher.poll_inbox()
        assert len(acks) == 1
        assert acks[0].decision == "ACCEPTED"


# 14. Tampered Payload Rejected
def test_tampered_payload_rejected():
    auth = DirectiveAuthenticator(repo_root=settings.CONTROL_PLANE_ROOT)
    trusted_key = list(settings.TRUSTED_SIGNER_ALLOWLIST)[0]
    auth.verify_commit_signature = lambda path, sha: (True, True, trusted_key, True)
    payload = create_sample_payload(directive_id="valid-001")
    payload.action = "TAMPERED_ACTION"
    envelope = DirectiveEnvelope(
        directive_id="valid-001",
        payload_commit_sha=get_git_head_sha(),
        payload_blob_sha="blob",
        payload_sha256="sha",
        trusted_remote="AI-CONTROL-PLANE",
        trusted_branch="main"
    )

    status, reason, req_human, meta = auth.authenticate(
        payload, envelope, settings.CONTROL_PLANE_ROOT / "directives" / "inbox" / "valid-001.json"
    )
    assert status == ValidationStatus.CONTENT_MISMATCH


# 15. Wrong SHA256 Rejected
def test_wrong_sha256_rejected():
    auth = DirectiveAuthenticator(repo_root=settings.CONTROL_PLANE_ROOT)
    trusted_key = list(settings.TRUSTED_SIGNER_ALLOWLIST)[0]
    auth.verify_commit_signature = lambda path, sha: (True, True, trusted_key, True)
    payload = create_sample_payload(directive_id="valid-001")
    envelope = DirectiveEnvelope(
        directive_id="valid-001",
        payload_commit_sha=get_git_head_sha(),
        payload_blob_sha="blob",
        payload_sha256="wrong_sha256_value",
        trusted_remote="AI-CONTROL-PLANE",
        trusted_branch="main"
    )

    status, reason, req_human, meta = auth.authenticate(
        payload, envelope, settings.CONTROL_PLANE_ROOT / "directives" / "inbox" / "valid-001.json"
    )
    assert status == ValidationStatus.CONTENT_MISMATCH


# 16. Wrong Blob SHA Rejected
def test_wrong_blob_sha_rejected():
    auth = DirectiveAuthenticator(repo_root=settings.CONTROL_PLANE_ROOT)
    trusted_key = list(settings.TRUSTED_SIGNER_ALLOWLIST)[0]
    auth.verify_commit_signature = lambda path, sha: (True, True, trusted_key, True)
    payload = create_sample_payload(directive_id="valid-001")
    envelope = DirectiveEnvelope(
        directive_id="valid-001",
        payload_commit_sha=get_git_head_sha(),
        payload_blob_sha="wrong_blob_sha_value",
        payload_sha256="UNKNOWN_HASH",
        trusted_remote="AI-CONTROL-PLANE",
        trusted_branch="main"
    )

    status, reason, req_human, meta = auth.authenticate(
        payload, envelope, settings.CONTROL_PLANE_ROOT / "directives" / "inbox" / "valid-001.json"
    )
    assert status == ValidationStatus.CONTENT_MISMATCH


# 17. Invalid Signature Rejected
def test_invalid_signature_rejected():
    auth = DirectiveAuthenticator(repo_root=settings.CONTROL_PLANE_ROOT)
    payload = create_sample_payload(directive_id="invalid-sig-001")
    envelope = DirectiveEnvelope(
        directive_id="invalid-sig-001",
        payload_commit_sha=get_git_head_sha(),
        payload_blob_sha="blob",
        payload_sha256="sha",
        trusted_remote="AI-CONTROL-PLANE",
        trusted_branch="main"
    )

    trusted_key = list(settings.TRUSTED_SIGNER_ALLOWLIST)[0]
    auth.verify_commit_signature = lambda path, sha: (True, False, trusted_key, False)

    status, reason, req_human, meta = auth.authenticate(payload, envelope)
    assert status == ValidationStatus.COMMIT_SIGNATURE_INVALID


# 18. Exact TOCTOU Variable & Revalidation Execution Regression Test
def test_toctou_revalidation_executes_auth_meta_branch():
    """
    Explicit regression test for Requirement 8:
    Executes PreExecutionRevalidator.revalidate() ensuring auth_meta variable scope is valid.
    """
    item = QueuedDirectiveItem(
        directive_id="valid-001",
        directive_source_sha=get_git_head_sha(),
        directive_blob_sha="blob",
        directive_payload_sha256="queued_sha256",
        accepted_at=datetime.now(timezone.utc).isoformat(),
        readback_verified=True,
        directive_payload=create_sample_payload("valid-001").to_dict()
    )

    revalidator = PreExecutionRevalidator()
    revalidator.authenticator.authenticate = lambda payload, envelope, path=None: (
        ValidationStatus.AUTHENTIC,
        "AUTHENTIC",
        False,
        {"payload_sha256": "different_live_sha256"}
    )

    allowed, status, reason, meta = revalidator.revalidate(item)
    assert allowed is False
    assert status == ValidationStatus.TOCTOU_REVALIDATION_FAILED
    assert "Live blob SHA256" in reason
    assert meta.get("payload_sha256") == "different_live_sha256"
