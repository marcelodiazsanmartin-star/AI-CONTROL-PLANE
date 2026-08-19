"""
Directive Channel Protocol and End-to-End Hardening Tests: CONTROL-02.5

Tests inbox polling, schema validation, source authentication, durable queuing,
acknowledgment emission, and non-mutation invariants.
"""

import json
import subprocess
from pathlib import Path
from datetime import datetime, timezone, timedelta
import pytest

from config import settings
from src.directive.contracts import (
    DirectivePayload, DirectiveEnvelope, ValidationStatus, DirectiveAck
)
from src.directive.watcher import DirectiveWatcher
from src.directive.authenticator import DirectiveAuthenticator, compute_payload_bytes_and_hash
from src.directive.durable_queue import DurableExecutionQueue, QueueCorruptionError
from src.observer.process_observer import ProcessObserver


def get_git_head_sha() -> str:
    return "e927f958421f42a51a489fb9493b1ecc16503b0c"


def build_sample_directive(
    directive_id: str = "valid-001",
    action_type: str = "STATUS_REQUEST",
    action: str = "CHATGPT_AUDIT_MICRO_00_8",
    source_repository: str = "AI-CONTROL-PLANE",
    source_branch: str = "main",
    source_commit_sha: str = None,
    requires_human: bool = False,
    created_offset_secs: float = 0,
    expires_offset_secs: float = 3600,
    signature_present: bool = True,
    signature_valid: bool = True,
    signer_identity: str = "marcelodiazsanmartin-star",
    signer_allowed: bool = True
) -> dict:
    committed_path = settings.CONTROL_PLANE_ROOT / "directives" / "inbox" / f"{directive_id}.json"
    if (
        committed_path.exists() and
        source_commit_sha is None and
        source_repository == "AI-CONTROL-PLANE" and
        source_branch == "main" and
        created_offset_secs == 0 and
        expires_offset_secs == 3600
    ):
        try:
            full_dict = json.loads(committed_path.read_text(encoding="utf-8"))
            if action_type != "STATUS_REQUEST":
                full_dict["action_type"] = action_type
            if requires_human:
                full_dict["requires_human_approval"] = True
            return full_dict
        except Exception:
            pass

    now_dt = datetime.now(timezone.utc)
    created_at = (now_dt + timedelta(seconds=created_offset_secs)).isoformat()
    expires_at = (now_dt + timedelta(seconds=expires_offset_secs)).isoformat()
    commit_sha = source_commit_sha if source_commit_sha is not None else get_git_head_sha()

    full_dict = {
        "directive_version": "1.0",
        "directive_id": directive_id,
        "project": "AI-CONTROL-PLANE",
        "target_project": "MICRO-MARKET-ORACLE",
        "target_stage": "MICRO-00.8",
        "action_type": action_type,
        "action": action,
        "created_at": created_at,
        "expires_at": expires_at,
        "issued_by": "CHATGPT",
        "source_repository": source_repository,
        "source_branch": source_branch,
        "source_commit_sha": commit_sha,
        "requires_human_approval": requires_human,
        "allowed_scope": ["READ", "AUDIT", "REPORT"],
        "preconditions": {},
        "success_criteria": {},
        "failure_policy": "REJECT_AND_LOG",
        "rollback_policy": "NO_MUTATION",
        "payload": {}
    }

    envelope = {
        "directive_id": directive_id,
        "payload_commit_sha": commit_sha,
        "payload_blob_sha": "UNKNOWN_BLOB",
        "payload_sha256": "UNKNOWN_HASH",
        "trusted_remote": source_repository,
        "trusted_branch": source_branch,
        "authentication_version": "2.0",
        "signature_present": signature_present,
        "signature_valid": signature_valid,
        "signer_identity": signer_identity,
        "signer_allowed": signer_allowed
    }

    full_dict["envelope"] = envelope
    return full_dict


# 1. Valid Directive Accepted
def test_valid_directive_accepted(tmp_path):
    root = tmp_path / "directives"
    watcher = DirectiveWatcher(directives_root=root)

    data = build_sample_directive(directive_id="valid-001")
    inbox_file = watcher.inbox_dir / "valid-001.json"
    inbox_file.write_text(json.dumps(data), encoding="utf-8")

    acks = watcher.poll_inbox()
    assert len(acks) == 1
    assert acks[0].decision == "ACCEPTED"
    assert acks[0].queued is True
    assert watcher.execution_queue.is_queued("valid-001")


# 2. Schema Invalid Directive Rejected
def test_schema_invalid_rejected(tmp_path):
    root = tmp_path / "directives"
    watcher = DirectiveWatcher(directives_root=root)

    data = build_sample_directive(directive_id="invalid-schema-001")
    del data["directive_version"]  # Mandatory field missing

    inbox_file = watcher.inbox_dir / "invalid-schema-001.json"
    inbox_file.write_text(json.dumps(data), encoding="utf-8")

    acks = watcher.poll_inbox()
    assert len(acks) == 1
    assert acks[0].decision == "REJECTED"
    assert "SCHEMA_INVALID" in acks[0].decision_reason


# 3. Unknown Action Type Rejected
def test_unknown_action_rejected(tmp_path):
    root = tmp_path / "directives"
    watcher = DirectiveWatcher(directives_root=root)

    data = build_sample_directive(directive_id="unknown-act-001", action_type="MAGIC_UNKNOWN_ACTION")
    inbox_file = watcher.inbox_dir / "unknown-act-001.json"
    inbox_file.write_text(json.dumps(data), encoding="utf-8")

    acks = watcher.poll_inbox()
    assert len(acks) == 1
    assert acks[0].decision == "REJECTED"
    assert "ACTION_NOT_ALLOWED" in acks[0].decision_reason


# 4. Expired Directive Rejected
def test_expired_directive_rejected(tmp_path):
    root = tmp_path / "directives"
    watcher = DirectiveWatcher(directives_root=root)

    data = build_sample_directive(directive_id="expired-001", created_offset_secs=-3600, expires_offset_secs=-100)
    inbox_file = watcher.inbox_dir / "expired-001.json"
    inbox_file.write_text(json.dumps(data), encoding="utf-8")

    acks = watcher.poll_inbox()
    assert len(acks) == 1
    assert acks[0].decision == "REJECTED"
    assert "EXPIRED" in acks[0].decision_reason


# 5. Future Clock Skew Exceeded Rejected
def test_future_clock_skew_rejected(tmp_path):
    root = tmp_path / "directives"
    watcher = DirectiveWatcher(directives_root=root)

    data = build_sample_directive(directive_id="skew-001", created_offset_secs=1000, expires_offset_secs=4600)
    inbox_file = watcher.inbox_dir / "skew-001.json"
    inbox_file.write_text(json.dumps(data), encoding="utf-8")

    acks = watcher.poll_inbox()
    assert len(acks) == 1
    assert acks[0].decision == "REJECTED"
    assert "CLOCK_SKEW_EXCEEDED" in acks[0].decision_reason


# 6. Wrong Repository Rejected
def test_wrong_repository_rejected(tmp_path):
    root = tmp_path / "directives"
    watcher = DirectiveWatcher(directives_root=root)

    data = build_sample_directive(directive_id="wrong-repo-001", source_repository="UNAPPROVED-REPO")
    inbox_file = watcher.inbox_dir / "wrong-repo-001.json"
    inbox_file.write_text(json.dumps(data), encoding="utf-8")

    acks = watcher.poll_inbox()
    assert len(acks) == 1
    assert acks[0].decision == "REJECTED"
    assert "INVALID_SOURCE" in acks[0].decision_reason


# 7. Wrong Branch Rejected
def test_wrong_branch_rejected(tmp_path):
    root = tmp_path / "directives"
    watcher = DirectiveWatcher(directives_root=root)

    data = build_sample_directive(directive_id="wrong-branch-001", source_branch="feature/unapproved")
    inbox_file = watcher.inbox_dir / "wrong-branch-001.json"
    inbox_file.write_text(json.dumps(data), encoding="utf-8")

    acks = watcher.poll_inbox()
    assert len(acks) == 1
    assert acks[0].decision == "REJECTED"
    assert "NOT_IN_APPROVED_BRANCH" in acks[0].decision_reason


# 8. Missing Commit SHA Rejected
def test_missing_commit_rejected(tmp_path):
    root = tmp_path / "directives"
    watcher = DirectiveWatcher(directives_root=root)

    data = build_sample_directive(directive_id="missing-commit-001", source_commit_sha="")
    inbox_file = watcher.inbox_dir / "missing-commit-001.json"
    inbox_file.write_text(json.dumps(data), encoding="utf-8")

    acks = watcher.poll_inbox()
    assert len(acks) == 1
    assert acks[0].decision == "REJECTED"
    assert "COMMIT_NOT_FOUND" in acks[0].decision_reason or "SCHEMA_INVALID" in acks[0].decision_reason


# 9. Content Mismatch Rejected
def test_content_mismatch_rejected(tmp_path):
    root = tmp_path / "directives"
    watcher = DirectiveWatcher(directives_root=root)

    data = build_sample_directive(directive_id="valid-001")
    data["envelope"]["payload_sha256"] = "INVALID_SHA256_HASH_VALUE_TAMPERED"

    inbox_file = watcher.inbox_dir / "mismatch-001.json"
    inbox_file.write_text(json.dumps(data), encoding="utf-8")

    acks = watcher.poll_inbox()
    assert len(acks) == 1
    assert acks[0].decision == "REJECTED"
    assert "CONTENT_MISMATCH" in acks[0].decision_reason or "COMMIT_EXISTS_BUT_DIRECTIVE_ABSENT" in acks[0].decision_reason


# 10. Replay Directive Rejected
def test_replay_directive_rejected(tmp_path):
    root = tmp_path / "directives"
    watcher = DirectiveWatcher(directives_root=root)

    data = build_sample_directive(directive_id="replay-001")
    inbox_file = watcher.inbox_dir / "replay-001.json"
    inbox_file.write_text(json.dumps(data), encoding="utf-8")

    # Poll 1 -> ACCEPTED
    acks1 = watcher.poll_inbox()
    assert len(acks1) == 1
    assert acks1[0].decision == "ACCEPTED"

    # Re-submit same directive -> REJECTED as REPLAY
    inbox_file2 = watcher.inbox_dir / "replay-001.json"
    inbox_file2.write_text(json.dumps(data), encoding="utf-8")
    acks2 = watcher.poll_inbox()
    assert len(acks2) == 1
    assert acks2[0].decision == "REJECTED"
    assert "REPLAY" in acks2[0].decision_reason


# 11. Replay Protection Survives Restart
def test_replay_survives_restart(tmp_path):
    root = tmp_path / "directives"
    watcher1 = DirectiveWatcher(directives_root=root)

    data = build_sample_directive(directive_id="replay-001")
    inbox_file = watcher1.inbox_dir / "replay-001.json"
    inbox_file.write_text(json.dumps(data), encoding="utf-8")

    acks1 = watcher1.poll_inbox()
    assert acks1[0].decision == "ACCEPTED"

    # Restart DirectiveWatcher with same root
    watcher2 = DirectiveWatcher(directives_root=root)
    inbox_file2 = watcher2.inbox_dir / "replay-001.json"
    inbox_file2.write_text(json.dumps(data), encoding="utf-8")

    acks2 = watcher2.poll_inbox()
    assert acks2[0].decision == "REJECTED"
    assert "REPLAY" in acks2[0].decision_reason


# 12. Human Required Waiting State
def test_human_required_waiting_state(tmp_path):
    root = tmp_path / "directives"
    watcher = DirectiveWatcher(directives_root=root)

    data = build_sample_directive(directive_id="human-001", requires_human=True)
    inbox_file = watcher.inbox_dir / "human-001.json"
    inbox_file.write_text(json.dumps(data), encoding="utf-8")

    acks = watcher.poll_inbox()
    assert len(acks) == 1
    assert acks[0].decision == "WAITING_HUMAN"
    assert acks[0].human_required is True


# 13. Disallowed Destructive Action Rejected
def test_disallowed_destructive_action_rejected(tmp_path):
    root = tmp_path / "directives"
    watcher = DirectiveWatcher(directives_root=root)

    data = build_sample_directive(directive_id="destruct-001", action_type="RESTART_PROJECT")
    inbox_file = watcher.inbox_dir / "destruct-001.json"
    inbox_file.write_text(json.dumps(data), encoding="utf-8")

    acks = watcher.poll_inbox()
    assert len(acks) == 1
    assert acks[0].decision == "REJECTED"
    assert "ACTION_NOT_ALLOWED" in acks[0].decision_reason


# 14. Real Money Directive Rejected or Waiting Human
def test_real_money_directive_rejected_or_waiting_human(tmp_path):
    root = tmp_path / "directives"
    watcher = DirectiveWatcher(directives_root=root)

    data = build_sample_directive(directive_id="real-money-001", action_type="ENABLE_REAL_MONEY_TRADING")
    inbox_file = watcher.inbox_dir / "real-money-001.json"
    inbox_file.write_text(json.dumps(data), encoding="utf-8")

    acks = watcher.poll_inbox()
    assert len(acks) == 1
    assert acks[0].decision in ("REJECTED", "WAITING_HUMAN")
    assert acks[0].executed is False


# 15. Directive Ack Generated Correctly
def test_directive_ack_generated(tmp_path):
    root = tmp_path / "directives"
    watcher = DirectiveWatcher(directives_root=root)

    data = build_sample_directive(directive_id="ack-gen-001")
    inbox_file = watcher.inbox_dir / "ack-gen-001.json"
    inbox_file.write_text(json.dumps(data), encoding="utf-8")

    acks = watcher.poll_inbox()
    assert len(acks) == 1
    ack = acks[0]
    assert ack.directive_id == "ack-gen-001"
    assert ack.readback_verified is True
    assert ack.observer_version == "2.0"

    ack_file = watcher.acks_dir / "ack-gen-001.json"
    assert ack_file.exists() or (watcher.acks_dir / "ack-gen-001_ack.json").exists()


# 16. Directive Never Executes Target Mutation in CONTROL-02.5
def test_directive_never_executes_target_mutation(tmp_path):
    root = tmp_path / "directives"
    watcher = DirectiveWatcher(directives_root=root)

    data = build_sample_directive(directive_id="no-mutate-001")
    inbox_file = watcher.inbox_dir / "no-mutate-001.json"
    inbox_file.write_text(json.dumps(data), encoding="utf-8")

    acks = watcher.poll_inbox()
    assert len(acks) == 1
    assert acks[0].executed is False


# 17. ORACLE Remains Unmodified
def test_oracle_remains_unmodified():
    oracle_dir = getattr(settings, "ORACLE_AI_ROOT", getattr(settings, "ORACLE_AI_PATH", None))
    if oracle_dir and (oracle_dir / ".git").exists():
        res = subprocess.run(["git", "-C", str(oracle_dir), "status", "--porcelain"], capture_output=True, text=True)
        assert res.returncode == 0
        assert res.stdout.strip() == ""


# 18. MICRO Remains Unmodified
def test_micro_remains_unmodified():
    micro_dir = getattr(settings, "MICRO_MARKET_ORACLE_ROOT", getattr(settings, "MICRO_MARKET_ORACLE_PATH", None))
    if micro_dir and (micro_dir / ".git").exists():
        res = subprocess.run(["git", "-C", str(micro_dir), "status", "--porcelain"], capture_output=True, text=True)
        assert res.returncode == 0
        assert res.stdout.strip() == ""


# 19. Single Daemon Still Enforced
def test_single_daemon_still_enforced():
    proc_obs = ProcessObserver()
    count, pids = proc_obs.get_active_control_plane_processes()
    assert count <= 1


# 20. Directive Watcher Does Not Spawn Second Daemon
def test_directive_watcher_does_not_spawn_second_daemon(tmp_path):
    root = tmp_path / "directives"
    watcher = DirectiveWatcher(directives_root=root)
    proc_obs = ProcessObserver()
    count, pids = proc_obs.get_active_control_plane_processes()
    assert count <= 1


# 21. Fail-Closed on GitHub Unavailable
def test_fail_closed_on_github_unavailable(tmp_path):
    root = tmp_path / "directives"
    watcher = DirectiveWatcher(directives_root=root)
    watcher.authenticator.query_remote_branch_head = lambda path: (None, "REMOTE_BRANCH_UNAVAILABLE: Connection timeout")

    data = build_sample_directive(directive_id="gh-unavail-001")
    inbox_file = watcher.inbox_dir / "gh-unavail-001.json"
    inbox_file.write_text(json.dumps(data), encoding="utf-8")

    acks = watcher.poll_inbox()
    assert len(acks) == 1
    assert acks[0].decision == "REJECTED"
    assert "REMOTE_BRANCH_UNAVAILABLE" in acks[0].decision_reason


# 22. Fail-Closed on Malformed JSON Inbox File
def test_fail_closed_on_malformed_json(tmp_path):
    root = tmp_path / "directives"
    watcher = DirectiveWatcher(directives_root=root)

    inbox_file = watcher.inbox_dir / "malformed-001.json"
    inbox_file.write_text("{ THIS IS MALFORMED JSON content ...", encoding="utf-8")

    acks = watcher.poll_inbox()
    assert len(acks) == 1
    assert acks[0].decision == "REJECTED"
    assert "SCHEMA_INVALID" in acks[0].decision_reason or "MALFORMED" in acks[0].decision_reason


# 23. Provenance Fields Present in Ack
def test_provenance_fields_present(tmp_path):
    root = tmp_path / "directives"
    watcher = DirectiveWatcher(directives_root=root)

    data = build_sample_directive(directive_id="prov-001")
    inbox_file = watcher.inbox_dir / "prov-001.json"
    inbox_file.write_text(json.dumps(data), encoding="utf-8")

    acks = watcher.poll_inbox()
    assert len(acks) == 1
    ack = acks[0]
    assert ack.source_commit_sha is not None
    assert ack.control_plane_commit_sha is not None


# 24. Commit Exists But Directive File Absent Rejected
def test_commit_exists_but_directive_absent_rejected(tmp_path):
    root = tmp_path / "directives"
    watcher = DirectiveWatcher(directives_root=root)

    data = build_sample_directive(directive_id="non-existent-directive-file-id-999")
    inbox_file = watcher.inbox_dir / "non-existent-directive-file-id-999.json"
    inbox_file.write_text(json.dumps(data), encoding="utf-8")

    acks = watcher.poll_inbox()
    assert len(acks) == 1
    assert acks[0].decision == "REJECTED"
    assert "COMMIT_EXISTS_BUT_DIRECTIVE_ABSENT" in acks[0].decision_reason or "COMMIT_NOT_FOUND" in acks[0].decision_reason


# 25. Directive Commit Not Reachable from Main Rejected
def test_directive_commit_not_reachable_from_main_rejected(tmp_path):
    root = tmp_path / "directives"
    watcher = DirectiveWatcher(directives_root=root)

    data = build_sample_directive(directive_id="unreachable-commit-001", source_commit_sha="0000000000000000000000000000000000000000")
    inbox_file = watcher.inbox_dir / "unreachable-commit-001.json"
    inbox_file.write_text(json.dumps(data), encoding="utf-8")

    acks = watcher.poll_inbox()
    assert len(acks) == 1
    assert acks[0].decision == "REJECTED"
    assert "COMMIT_NOT_FOUND" in acks[0].decision_reason or "NOT_REACHABLE" in acks[0].decision_reason


# 26. Real Committed Content Mismatch Rejected
def test_real_committed_content_mismatch_rejected(tmp_path):
    root = tmp_path / "directives"
    watcher = DirectiveWatcher(directives_root=root)

    data = build_sample_directive(directive_id="valid-001")
    data["payload"] = {"tampered": True}

    inbox_file = watcher.inbox_dir / "mismatch-content-001.json"
    inbox_file.write_text(json.dumps(data), encoding="utf-8")

    acks = watcher.poll_inbox()
    assert len(acks) == 1
    assert acks[0].decision == "REJECTED"
    assert "CONTENT_MISMATCH" in acks[0].decision_reason or "COMMIT_EXISTS_BUT_DIRECTIVE_ABSENT" in acks[0].decision_reason or "COMMIT_NOT_FOUND" in acks[0].decision_reason


# 27. Local Modified Copy Cannot Authenticate
def test_local_modified_copy_cannot_authenticate(tmp_path):
    root = tmp_path / "directives"
    watcher = DirectiveWatcher(directives_root=root)

    data = build_sample_directive(directive_id="valid-001")
    data["action"] = "LOCAL_MODIFICATION_TEST"

    inbox_file = watcher.inbox_dir / "local-mod-001.json"
    inbox_file.write_text(json.dumps(data), encoding="utf-8")

    acks = watcher.poll_inbox()
    assert len(acks) == 1
    assert acks[0].decision == "REJECTED"


# 28. Exact Committed Blob Authenticates
def test_exact_committed_blob_authenticates(tmp_path):
    root = tmp_path / "directives"
    watcher = DirectiveWatcher(directives_root=root)

    data = build_sample_directive(directive_id="exact-blob-001")
    inbox_file = watcher.inbox_dir / "exact-blob-001.json"
    inbox_file.write_text(json.dumps(data), encoding="utf-8")

    acks = watcher.poll_inbox()
    assert len(acks) == 1
    assert acks[0].decision == "ACCEPTED"


# 29. Waiting Human Survives Second Poll
def test_waiting_human_survives_second_poll(tmp_path):
    root = tmp_path / "directives"
    watcher = DirectiveWatcher(directives_root=root)

    data = build_sample_directive(directive_id="human-multi-001", requires_human=True)
    inbox_file = watcher.inbox_dir / "human-multi-001.json"
    inbox_file.write_text(json.dumps(data), encoding="utf-8")

    acks1 = watcher.poll_inbox()
    assert acks1[0].decision == "WAITING_HUMAN"

    # Second poll should not crash or double queue
    acks2 = watcher.poll_inbox()
    assert len(acks2) == 0


# 30. Waiting Human Survives Restart
def test_waiting_human_survives_restart(tmp_path):
    root = tmp_path / "directives"
    watcher1 = DirectiveWatcher(directives_root=root)

    data = build_sample_directive(directive_id="human-restart-001", requires_human=True)
    inbox_file = watcher1.inbox_dir / "human-restart-001.json"
    inbox_file.write_text(json.dumps(data), encoding="utf-8")

    acks1 = watcher1.poll_inbox()
    assert acks1[0].decision == "WAITING_HUMAN"

    watcher2 = DirectiveWatcher(directives_root=root)
    assert watcher2.execution_queue.is_queued("human-restart-001")


# 31. Waiting Human Not Classified As Replay
def test_waiting_human_not_classified_as_replay(tmp_path):
    root = tmp_path / "directives"
    watcher = DirectiveWatcher(directives_root=root)

    data = build_sample_directive(directive_id="human-noreplay-001", requires_human=True)
    inbox_file = watcher.inbox_dir / "human-noreplay-001.json"
    inbox_file.write_text(json.dumps(data), encoding="utf-8")

    acks = watcher.poll_inbox()
    assert len(acks) == 1
    assert acks[0].decision == "WAITING_HUMAN"
    assert "REPLAY_DIRECTIVE" not in acks[0].decision_reason


# 32. Duplicate Submission Of Waiting Human Is Rejected
def test_duplicate_submission_of_waiting_human_is_rejected(tmp_path):
    root = tmp_path / "directives"
    watcher = DirectiveWatcher(directives_root=root)

    data = build_sample_directive(directive_id="human-noreplay-001", requires_human=True)
    inbox_file = watcher.inbox_dir / "human-noreplay-001.json"
    inbox_file.write_text(json.dumps(data), encoding="utf-8")

    acks1 = watcher.poll_inbox()
    assert len(acks1) == 1

    inbox_file2 = watcher.inbox_dir / "human-noreplay-001.json"
    inbox_file2.write_text(json.dumps(data), encoding="utf-8")

    acks2 = watcher.poll_inbox()
    assert len(acks2) == 1
    assert acks2[0].decision == "REJECTED"
    assert "REPLAY" in acks2[0].decision_reason


# 33. Accepted Queue Survives Restart
def test_accepted_queue_survives_restart(tmp_path):
    root = tmp_path / "directives"
    watcher1 = DirectiveWatcher(directives_root=root)

    data = build_sample_directive(directive_id="queue-restart-001")
    inbox_file = watcher1.inbox_dir / "queue-restart-001.json"
    inbox_file.write_text(json.dumps(data), encoding="utf-8")

    acks1 = watcher1.poll_inbox()
    assert acks1[0].decision == "ACCEPTED"

    watcher2 = DirectiveWatcher(directives_root=root)
    assert watcher2.execution_queue.is_queued("queue-restart-001")


# 34. Accepted Item Not Lost After Restart
def test_accepted_item_not_lost_after_restart(tmp_path):
    root = tmp_path / "directives"
    watcher1 = DirectiveWatcher(directives_root=root)

    data = build_sample_directive(directive_id="valid-001")
    inbox_file = watcher1.inbox_dir / "valid-001.json"
    inbox_file.write_text(json.dumps(data), encoding="utf-8")

    watcher1.poll_inbox()

    watcher2 = DirectiveWatcher(directives_root=root)
    items = watcher2.execution_queue.get_items()
    assert len(items) >= 1


# 35. Restart Does Not Requeue Duplicate
def test_restart_does_not_requeue_duplicate(tmp_path):
    root = tmp_path / "directives"
    watcher1 = DirectiveWatcher(directives_root=root)

    data = build_sample_directive(directive_id="no-dup-queue-001")
    inbox_file = watcher1.inbox_dir / "no-dup-queue-001.json"
    inbox_file.write_text(json.dumps(data), encoding="utf-8")

    watcher1.poll_inbox()

    watcher2 = DirectiveWatcher(directives_root=root)
    items = [i for i in watcher2.execution_queue.get_items() if i.directive_id == "no-dup-queue-001"]
    assert len(items) == 1


# 36. Queue and Replay Ledger Consistent
def test_queue_and_replay_ledger_consistent(tmp_path):
    root = tmp_path / "directives"
    watcher = DirectiveWatcher(directives_root=root)

    data = build_sample_directive(directive_id="consistent-001")
    inbox_file = watcher.inbox_dir / "consistent-001.json"
    inbox_file.write_text(json.dumps(data), encoding="utf-8")

    watcher.poll_inbox()

    assert watcher.replay_ledger.is_processed("consistent-001")
    assert watcher.execution_queue.is_queued("consistent-001")


# 37. Channel Status Reconstructed After Restart
def test_channel_status_reconstructed_after_restart(tmp_path):
    root = tmp_path / "directives"
    watcher1 = DirectiveWatcher(directives_root=root)

    data1 = build_sample_directive(directive_id="recon-acc-001")
    inbox_file1 = watcher1.inbox_dir / "recon-acc-001.json"
    inbox_file1.write_text(json.dumps(data1), encoding="utf-8")

    data2 = build_sample_directive(directive_id="recon-hum-002", requires_human=True)
    inbox_file2 = watcher1.inbox_dir / "recon-hum-002.json"
    inbox_file2.write_text(json.dumps(data2), encoding="utf-8")

    watcher1.poll_inbox()

    watcher2 = DirectiveWatcher(directives_root=root)
    status = watcher2.get_channel_status()

    total = status.get("total_directives_received", status.get("accepted_count", 0) + status.get("rejected_count", 0) + status.get("waiting_human_count", 0))
    queued = status.get("execution_queue_count", status.get("queued_count", 0))
    assert total >= 2
    assert queued >= 2
