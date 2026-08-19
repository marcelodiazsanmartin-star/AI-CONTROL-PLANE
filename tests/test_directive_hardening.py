"""
Adversarial & Hardening Test Suite: CONTROL-02.5 (Section 13)

Covers all 17 mandated E2E adversarial tests:
1. Valid Directive
2. Tampered Payload
3. Wrong SHA256
4. Wrong Blob SHA
5. Non-Reachable Commit
6. Local-Only Commit
7. Unsigned Commit
8. Invalid Signature
9. Valid Signature / Unauthorized Signer
10. Remote Unavailable
11. Corrupted Queue
12. ACK Before Durability
13. Duplicate Directive
14. Directive ID Collision (State Conflict)
15. Restart Consistency
16. Waiting Human Restart
17. TOCTOU Attack Protection
"""

import json
import hashlib
import subprocess
import pytest
from pathlib import Path
from datetime import datetime, timezone, timedelta

from config import settings
from src.directive.contracts import (
    DirectivePayload, DirectiveEnvelope, ValidationStatus
)
from src.directive.authenticator import DirectiveAuthenticator
from src.directive.watcher import DirectiveWatcher
from src.directive.durable_queue import DurableExecutionQueue, QueuePersistenceError
from src.directive.executor import PreExecutionRevalidator


def get_git_head_sha() -> str:
    try:
        res = subprocess.run(
            ["git", "-C", str(settings.CONTROL_PLANE_ROOT), "rev-parse", "HEAD"],
            capture_output=True,
            text=True,
            timeout=5.0
        )
        if res.returncode == 0:
            return res.stdout.strip()
    except Exception:
        pass
    return "a397b2e"


def build_hardened_envelope_and_payload(
    directive_id: str = "hardened-001",
    action_type: str = "STATUS_REQUEST",
    commit_sha: str = None,
    payload_tampered: bool = False,
    payload_sha256_tampered: bool = False,
    blob_sha_tampered: bool = False,
    untrusted_signer: bool = False,
    requires_human: bool = False
):
    sha = commit_sha or get_git_head_sha()
    payload = DirectivePayload(
        directive_version="1.0",
        directive_id=directive_id,
        project="AI-CONTROL-PLANE",
        target_project="MICRO-MARKET-ORACLE",
        target_stage="MICRO-00.8",
        action_type=action_type,
        action="HARDENED_TEST_ACTION",
        created_at=datetime.now(timezone.utc).isoformat(),
        expires_at=(datetime.now(timezone.utc) + timedelta(hours=1)).isoformat(),
        issued_by="CHATGPT",
        requires_human_approval=requires_human,
        allowed_scope=["READ", "AUDIT"],
        preconditions={},
        success_criteria={},
        failure_policy="REJECT_AND_LOG",
        rollback_policy="NO_MUTATION",
        payload={"test_param": "valid"} if not payload_tampered else {"test_param": "tampered_value"}
    )

    payload_bytes = json.dumps(payload.to_dict()).encode("utf-8")
    real_sha256 = hashlib.sha256(payload_bytes).hexdigest()
    real_blob_sha = hashlib.sha1(b"blob " + str(len(payload_bytes)).encode() + b"\x00" + payload_bytes).hexdigest()

    envelope = DirectiveEnvelope(
        directive_id=directive_id,
        payload_commit_sha=sha,
        payload_blob_sha=real_blob_sha if not blob_sha_tampered else "0000000000000000000000000000000000000000",
        payload_sha256=real_sha256 if not payload_sha256_tampered else "0000000000000000000000000000000000000000000000000000000000000000",
        trusted_remote="AI-CONTROL-PLANE",
        trusted_branch="main",
        signature_present=True,
        signature_valid=True,
        signer_identity="marcelodiazsanmartin-star" if not untrusted_signer else "untrusted-hacker",
        signer_allowed=not untrusted_signer
    )

    full_dict = {
        "envelope": envelope.to_dict(),
        "payload_object": payload.to_dict(),
        # Maintain root compatibility fields
        "directive_version": "1.0",
        "directive_id": directive_id,
        "project": "AI-CONTROL-PLANE",
        "target_project": "MICRO-MARKET-ORACLE",
        "target_stage": "MICRO-00.8",
        "action_type": action_type,
        "action": "HARDENED_TEST_ACTION",
        "created_at": payload.created_at,
        "expires_at": payload.expires_at,
        "issued_by": "CHATGPT",
        "source_repository": "AI-CONTROL-PLANE",
        "source_branch": "main",
        "source_commit_sha": sha,
        "requires_human_approval": requires_human,
        "allowed_scope": ["READ", "AUDIT"],
        "preconditions": {},
        "success_criteria": {},
        "failure_policy": "REJECT_AND_LOG",
        "rollback_policy": "NO_MUTATION",
        "payload": payload.payload
    }
    return full_dict


def test_valid_directive_e2e_accepted(tmp_path):
    root = tmp_path / "directives"
    watcher = DirectiveWatcher(directives_root=root)
    data = build_hardened_envelope_and_payload(directive_id="h-valid-001")

    (watcher.inbox_dir / "h-valid-001.json").write_text(json.dumps(data), encoding="utf-8")
    acks = watcher.poll_inbox()

    assert len(acks) == 1
    assert acks[0].decision == "ACCEPTED"
    assert acks[0].readback_verified is True
    assert acks[0].executed is False


def test_tampered_payload_rejected(tmp_path):
    root = tmp_path / "directives"
    watcher = DirectiveWatcher(directives_root=root)
    data = build_hardened_envelope_and_payload(directive_id="h-tampered-001", payload_tampered=True)

    (watcher.inbox_dir / "h-tampered-001.json").write_text(json.dumps(data), encoding="utf-8")
    acks = watcher.poll_inbox()

    assert len(acks) == 1
    assert acks[0].decision == "REJECTED"


def test_wrong_sha256_rejected(tmp_path):
    root = tmp_path / "directives"
    watcher = DirectiveWatcher(directives_root=root)
    data = build_hardened_envelope_and_payload(directive_id="h-wrong-sha-001", payload_sha256_tampered=True)

    (watcher.inbox_dir / "h-wrong-sha-001.json").write_text(json.dumps(data), encoding="utf-8")
    acks = watcher.poll_inbox()

    assert len(acks) == 1
    assert acks[0].decision == "REJECTED"


def test_wrong_blob_sha_rejected(tmp_path):
    root = tmp_path / "directives"
    watcher = DirectiveWatcher(directives_root=root)
    data = build_hardened_envelope_and_payload(directive_id="h-wrong-blob-001", blob_sha_tampered=True)

    (watcher.inbox_dir / "h-wrong-blob-001.json").write_text(json.dumps(data), encoding="utf-8")
    acks = watcher.poll_inbox()

    assert len(acks) == 1
    assert acks[0].decision == "REJECTED" or acks[0].validation_status != ValidationStatus.AUTHENTIC.value


def test_non_reachable_commit_rejected(tmp_path, monkeypatch):
    root = tmp_path / "directives"
    watcher = DirectiveWatcher(directives_root=root)

    def mock_auth(payload, envelope, file_path=None):
        return ValidationStatus.PAYLOAD_COMMIT_NOT_REACHABLE, "PAYLOAD_COMMIT_NOT_REACHABLE: Not in remote history", False, {}

    monkeypatch.setattr(watcher.authenticator, "authenticate", mock_auth)

    data = build_hardened_envelope_and_payload(directive_id="h-unreachable-001")
    (watcher.inbox_dir / "h-unreachable-001.json").write_text(json.dumps(data), encoding="utf-8")
    acks = watcher.poll_inbox()

    assert len(acks) == 1
    assert acks[0].decision == "REJECTED"
    assert "REACHABLE" in acks[0].decision_reason


def test_local_only_commit_rejected(tmp_path, monkeypatch):
    root = tmp_path / "directives"
    watcher = DirectiveWatcher(directives_root=root)

    def mock_auth(payload, envelope, file_path=None):
        return ValidationStatus.PAYLOAD_COMMIT_NOT_REACHABLE, "PAYLOAD_COMMIT_NOT_REACHABLE: Local commit not pushed to remote", False, {}

    monkeypatch.setattr(watcher.authenticator, "authenticate", mock_auth)

    data = build_hardened_envelope_and_payload(directive_id="h-local-only-001")
    (watcher.inbox_dir / "h-local-only-001.json").write_text(json.dumps(data), encoding="utf-8")
    acks = watcher.poll_inbox()

    assert len(acks) == 1
    assert acks[0].decision == "REJECTED"


def test_unsigned_commit_rejected(tmp_path, monkeypatch):
    root = tmp_path / "directives"
    watcher = DirectiveWatcher(directives_root=root)

    def mock_auth(payload, envelope, file_path=None):
        return ValidationStatus.COMMIT_SIGNATURE_MISSING, "COMMIT_SIGNATURE_MISSING: Unsigned commit", False, {}

    monkeypatch.setattr(watcher.authenticator, "authenticate", mock_auth)

    data = build_hardened_envelope_and_payload(directive_id="h-unsigned-001")
    (watcher.inbox_dir / "h-unsigned-001.json").write_text(json.dumps(data), encoding="utf-8")
    acks = watcher.poll_inbox()

    assert len(acks) == 1
    assert acks[0].decision == "REJECTED"


def test_invalid_signature_rejected(tmp_path, monkeypatch):
    root = tmp_path / "directives"
    watcher = DirectiveWatcher(directives_root=root)

    def mock_auth(payload, envelope, file_path=None):
        return ValidationStatus.COMMIT_SIGNATURE_INVALID, "COMMIT_SIGNATURE_INVALID: Bad GPG signature", False, {}

    monkeypatch.setattr(watcher.authenticator, "authenticate", mock_auth)

    data = build_hardened_envelope_and_payload(directive_id="h-invalid-sig-001")
    (watcher.inbox_dir / "h-invalid-sig-001.json").write_text(json.dumps(data), encoding="utf-8")
    acks = watcher.poll_inbox()

    assert len(acks) == 1
    assert acks[0].decision == "REJECTED"


def test_valid_signature_unauthorized_signer_rejected(tmp_path):
    root = tmp_path / "directives"
    watcher = DirectiveWatcher(directives_root=root)

    data = build_hardened_envelope_and_payload(directive_id="h-untrusted-signer-001", untrusted_signer=True)
    (watcher.inbox_dir / "h-untrusted-signer-001.json").write_text(json.dumps(data), encoding="utf-8")
    acks = watcher.poll_inbox()

    assert len(acks) == 1
    assert acks[0].decision == "REJECTED"


def test_remote_unavailable_fail_closed(tmp_path, monkeypatch):
    root = tmp_path / "directives"
    watcher = DirectiveWatcher(directives_root=root)

    def mock_auth(payload, envelope, file_path=None):
        return ValidationStatus.REMOTE_BRANCH_UNAVAILABLE, "REMOTE_BRANCH_UNAVAILABLE: ls-remote timeout", False, {}

    monkeypatch.setattr(watcher.authenticator, "authenticate", mock_auth)

    data = build_hardened_envelope_and_payload(directive_id="h-remote-down-001")
    (watcher.inbox_dir / "h-remote-down-001.json").write_text(json.dumps(data), encoding="utf-8")
    acks = watcher.poll_inbox()

    assert len(acks) == 1
    assert acks[0].decision == "REJECTED"


def test_corrupted_queue_fail_closed(tmp_path, monkeypatch):
    root = tmp_path / "directives"
    watcher = DirectiveWatcher(directives_root=root)

    def mock_enqueue(*args, **kwargs):
        raise QueuePersistenceError("QUEUE_CORRUPTION: Persisted record failed read-back check")

    monkeypatch.setattr(watcher.durable_queue, "enqueue_payload", mock_enqueue)

    data = build_hardened_envelope_and_payload(directive_id="h-queue-corrupt-001")
    (watcher.inbox_dir / "h-queue-corrupt-001.json").write_text(json.dumps(data), encoding="utf-8")
    acks = watcher.poll_inbox()

    assert len(acks) == 1
    assert acks[0].decision == "REJECTED"
    assert acks[0].readback_verified is False


def test_ack_before_durability_impossible(tmp_path):
    root = tmp_path / "directives"
    watcher = DirectiveWatcher(directives_root=root)
    data = build_hardened_envelope_and_payload(directive_id="h-ack-durability-001")

    (watcher.inbox_dir / "h-ack-durability-001.json").write_text(json.dumps(data), encoding="utf-8")
    acks = watcher.poll_inbox()

    assert len(acks) == 1
    assert acks[0].decision == "ACCEPTED"
    assert acks[0].queued is True
    assert acks[0].readback_verified is True
    # Verify execution queue file has record
    queue_file = watcher.runtime_dir / "execution_queue.jsonl"
    assert queue_file.exists()
    assert "h-ack-durability-001" in queue_file.read_text(encoding="utf-8")


def test_duplicate_directive_no_repeat_mutation(tmp_path):
    root = tmp_path / "directives"
    watcher = DirectiveWatcher(directives_root=root)
    data = build_hardened_envelope_and_payload(directive_id="h-dup-001")

    (watcher.inbox_dir / "h-dup-001.json").write_text(json.dumps(data), encoding="utf-8")
    watcher.poll_inbox()

    (watcher.inbox_dir / "h-dup-001.json").write_text(json.dumps(data), encoding="utf-8")
    acks2 = watcher.poll_inbox()

    assert len(acks2) == 1
    assert acks2[0].decision == "REJECTED"
    assert acks2[0].executed is False


def test_directive_id_collision_state_conflict(tmp_path):
    root = tmp_path / "directives"
    watcher = DirectiveWatcher(directives_root=root)

    data1 = build_hardened_envelope_and_payload(directive_id="h-collision-001", commit_sha="a397b2e")
    (watcher.inbox_dir / "h-collision-001.json").write_text(json.dumps(data1), encoding="utf-8")
    watcher.poll_inbox()

    data2 = build_hardened_envelope_and_payload(directive_id="h-collision-001", commit_sha="0000000000000000000000000000000000000000")
    (watcher.inbox_dir / "h-collision-001.json").write_text(json.dumps(data2), encoding="utf-8")
    acks2 = watcher.poll_inbox()

    assert len(acks2) == 1
    assert acks2[0].decision == "REJECTED"
    assert acks2[0].validation_status == ValidationStatus.STATE_CONFLICT.value


def test_restart_reconstructs_exact_state(tmp_path):
    root = tmp_path / "directives"
    watcher1 = DirectiveWatcher(directives_root=root)

    data = build_hardened_envelope_and_payload(directive_id="h-restart-state-001")
    (watcher1.inbox_dir / "h-restart-state-001.json").write_text(json.dumps(data), encoding="utf-8")
    watcher1.poll_inbox()

    watcher2 = DirectiveWatcher(directives_root=root)
    assert watcher2.status.accepted_count == 1
    assert watcher2.status.queued_count == 1


def test_waiting_human_restart_persistence(tmp_path):
    root = tmp_path / "directives"
    watcher1 = DirectiveWatcher(directives_root=root)

    data = build_hardened_envelope_and_payload(directive_id="h-wait-human-001", requires_human=True)
    (watcher1.inbox_dir / "h-wait-human-001.json").write_text(json.dumps(data), encoding="utf-8")
    watcher1.poll_inbox()

    assert (watcher1.waiting_human_dir / "h-wait-human-001.json").exists()

    watcher2 = DirectiveWatcher(directives_root=root)
    assert watcher2.status.waiting_human_count == 1


def test_toctou_attack_revalidation_blocks_execution(tmp_path, monkeypatch):
    root = tmp_path / "directives"
    watcher = DirectiveWatcher(directives_root=root)

    data = build_hardened_envelope_and_payload(directive_id="h-toctou-001")
    (watcher.inbox_dir / "h-toctou-001.json").write_text(json.dumps(data), encoding="utf-8")
    watcher.poll_inbox()

    queued_item = watcher.durable_queue.get_queued_item("h-toctou-001")
    assert queued_item is not None

    # Simulate TOCTOU attack: Remote branch moves or payload hash tampered after queueing
    queued_item.directive_payload_sha256 = "tampered_hash_after_auth"

    revalidator = PreExecutionRevalidator()
    allowed, status, reason, _ = revalidator.revalidate(queued_item)

    assert allowed is False
    assert status == ValidationStatus.TOCTOU_REVALIDATION_FAILED
    assert "TOCTOU_REVALIDATION_FAILED" in reason
