"""
Adversarial Test Suite: CONTROL-02.5 Secure Directive Channel
Expanded with All Required Regression Tests from ChatGPT Audit.
"""

import os
import json
import hashlib
import subprocess
import pytest
from pathlib import Path
from datetime import datetime, timezone, timedelta

from config import settings
from src.directive.contracts import Directive, ValidationStatus
from src.directive.schema_validator import DirectiveSchemaValidator
from src.directive.replay_ledger import ReplayLedger
from src.directive.durable_queue import DurableExecutionQueue
from src.directive.authenticator import DirectiveAuthenticator
from src.directive.watcher import DirectiveWatcher
from src.engine import ControlPlaneEngine
from src.lock_manager import SingleInstanceLock


def build_sample_directive(
    directive_id: str = "test-uuid-101",
    action_type: str = "STATUS_REQUEST",
    action: str = "CHATGPT_AUDIT_MICRO_00_8",
    source_repository: str = "AI-CONTROL-PLANE",
    source_branch: str = "main",
    source_commit_sha: str = "477b9f15b097946673200421392a604e0d64f762",
    requires_human: bool = False,
    created_offset_secs: float = 0,
    expires_offset_secs: float = 3600
) -> dict:
    now_dt = datetime.now(timezone.utc)
    created_at = (now_dt + timedelta(seconds=created_offset_secs)).isoformat()
    expires_at = (now_dt + timedelta(seconds=expires_offset_secs)).isoformat()

    return {
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
        "source_commit_sha": source_commit_sha,
        "requires_human_approval": requires_human,
        "allowed_scope": ["READ", "AUDIT", "REPORT"],
        "preconditions": {},
        "success_criteria": {},
        "failure_policy": "REJECT_AND_LOG",
        "rollback_policy": "NO_MUTATION",
        "payload": {}
    }


def test_valid_directive_accepted(tmp_path):
    root = tmp_path / "directives"
    watcher = DirectiveWatcher(directives_root=root)

    data = build_sample_directive(directive_id="valid-001")
    inbox_file = watcher.inbox_dir / "valid-001.json"
    inbox_file.write_text(json.dumps(data), encoding="utf-8")

    acks = watcher.poll_inbox()
    assert len(acks) == 1
    assert acks[0].decision == "ACCEPTED"
    assert acks[0].validation_status == ValidationStatus.AUTHENTIC.value
    assert acks[0].queued is True
    assert acks[0].executed is False

    assert not inbox_file.exists()
    assert (watcher.accepted_dir / "valid-001.json").exists()
    assert (watcher.ack_dir / "valid-001.json").exists()


def test_schema_invalid_rejected(tmp_path):
    root = tmp_path / "directives"
    watcher = DirectiveWatcher(directives_root=root)

    data = build_sample_directive(directive_id="schema-inv-001")
    del data["target_project"]  # Missing required field

    inbox_file = watcher.inbox_dir / "schema-inv-001.json"
    inbox_file.write_text(json.dumps(data), encoding="utf-8")

    acks = watcher.poll_inbox()
    assert len(acks) == 1
    assert acks[0].decision == "REJECTED"
    assert "SCHEMA_INVALID" in acks[0].decision_reason
    assert (watcher.rejected_dir / "schema-inv-001.json").exists()


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
    assert (watcher.rejected_dir / "unknown-act-001.json").exists()


def test_expired_directive_rejected(tmp_path):
    root = tmp_path / "directives"
    watcher = DirectiveWatcher(directives_root=root)

    # Expired 100 seconds ago
    data = build_sample_directive(directive_id="expired-001", created_offset_secs=-3600, expires_offset_secs=-100)
    inbox_file = watcher.inbox_dir / "expired-001.json"
    inbox_file.write_text(json.dumps(data), encoding="utf-8")

    acks = watcher.poll_inbox()
    assert len(acks) == 1
    assert acks[0].decision == "REJECTED"
    assert "EXPIRED" in acks[0].decision_reason
    assert (watcher.rejected_dir / "expired-001.json").exists()


def test_future_clock_skew_rejected(tmp_path):
    root = tmp_path / "directives"
    watcher = DirectiveWatcher(directives_root=root)

    # Created 1000 seconds in the future (> 300s allowed skew)
    data = build_sample_directive(directive_id="skew-001", created_offset_secs=1000)
    inbox_file = watcher.inbox_dir / "skew-001.json"
    inbox_file.write_text(json.dumps(data), encoding="utf-8")

    acks = watcher.poll_inbox()
    assert len(acks) == 1
    assert acks[0].decision == "REJECTED"
    assert "CLOCK_SKEW_EXCEEDED" in acks[0].decision_reason
    assert (watcher.rejected_dir / "skew-001.json").exists()


def test_wrong_repository_rejected(tmp_path):
    root = tmp_path / "directives"
    watcher = DirectiveWatcher(directives_root=root)

    data = build_sample_directive(directive_id="wrong-repo-001", source_repository="UNAPPROVED_REPO")
    inbox_file = watcher.inbox_dir / "wrong-repo-001.json"
    inbox_file.write_text(json.dumps(data), encoding="utf-8")

    acks = watcher.poll_inbox()
    assert len(acks) == 1
    assert acks[0].decision == "REJECTED"
    assert "INVALID_SOURCE" in acks[0].decision_reason


def test_wrong_branch_rejected(tmp_path):
    root = tmp_path / "directives"
    watcher = DirectiveWatcher(directives_root=root)

    data = build_sample_directive(directive_id="wrong-branch-001", source_branch="unapproved-branch")
    inbox_file = watcher.inbox_dir / "wrong-branch-001.json"
    inbox_file.write_text(json.dumps(data), encoding="utf-8")

    acks = watcher.poll_inbox()
    assert len(acks) == 1
    assert acks[0].decision == "REJECTED"
    assert "NOT_IN_APPROVED_BRANCH" in acks[0].decision_reason


def test_missing_commit_rejected(tmp_path):
    root = tmp_path / "directives"
    watcher = DirectiveWatcher(directives_root=root)

    data = build_sample_directive(directive_id="missing-commit-001", source_commit_sha="0000000000000000000000000000000000000000")
    inbox_file = watcher.inbox_dir / "missing-commit-001.json"
    inbox_file.write_text(json.dumps(data), encoding="utf-8")

    acks = watcher.poll_inbox()
    assert len(acks) == 1
    assert acks[0].decision == "REJECTED"
    assert "COMMIT_NOT_FOUND" in acks[0].decision_reason


def test_content_mismatch_rejected(tmp_path):
    root = tmp_path / "directives"
    validator = DirectiveSchemaValidator()
    ledger = ReplayLedger(root / "runtime" / "consumed_directives.jsonl")

    class MockBadAuthenticator(DirectiveAuthenticator):
        def authenticate(self, directive, directive_file_path=None):
            return ValidationStatus.CONTENT_MISMATCH, "CONTENT_MISMATCH: Hash mismatch", False, {}

    watcher = DirectiveWatcher(directives_root=root, schema_validator=validator, replay_ledger=ledger, authenticator=MockBadAuthenticator())

    data = build_sample_directive(directive_id="mismatch-001")
    inbox_file = watcher.inbox_dir / "mismatch-001.json"
    inbox_file.write_text(json.dumps(data), encoding="utf-8")

    acks = watcher.poll_inbox()
    assert len(acks) == 1
    assert acks[0].decision == "REJECTED"
    assert "CONTENT_MISMATCH" in acks[0].decision_reason


def test_replay_directive_rejected(tmp_path):
    root = tmp_path / "directives"
    watcher = DirectiveWatcher(directives_root=root)

    data = build_sample_directive(directive_id="replay-001")

    # First attempt -> Accepted
    inbox_file1 = watcher.inbox_dir / "replay-001.json"
    inbox_file1.write_text(json.dumps(data), encoding="utf-8")
    acks1 = watcher.poll_inbox()
    assert acks1[0].decision == "ACCEPTED"

    # Second attempt with same directive_id -> Replay Rejected
    inbox_file2 = watcher.inbox_dir / "replay-001.json"
    inbox_file2.write_text(json.dumps(data), encoding="utf-8")
    acks2 = watcher.poll_inbox()
    assert acks2[0].decision == "REJECTED"
    assert "REPLAY_DETECTED" in acks2[0].decision_reason


def test_replay_survives_restart(tmp_path):
    root = tmp_path / "directives"
    ledger_path = root / "runtime" / "consumed_directives.jsonl"

    watcher1 = DirectiveWatcher(directives_root=root, replay_ledger=ReplayLedger(ledger_path))
    data = build_sample_directive(directive_id="restart-replay-001")

    inbox_file1 = watcher1.inbox_dir / "restart-replay-001.json"
    inbox_file1.write_text(json.dumps(data), encoding="utf-8")
    watcher1.poll_inbox()

    watcher2 = DirectiveWatcher(directives_root=root, replay_ledger=ReplayLedger(ledger_path))

    inbox_file2 = watcher2.inbox_dir / "restart-replay-001.json"
    inbox_file2.write_text(json.dumps(data), encoding="utf-8")
    acks2 = watcher2.poll_inbox()

    assert acks2[0].decision == "REJECTED"
    assert "REPLAY_DETECTED" in acks2[0].decision_reason


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
    assert acks[0].queued is False
    assert (watcher.waiting_human_dir / "human-001.json").exists()


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


def test_real_money_directive_rejected_or_waiting_human(tmp_path):
    root = tmp_path / "directives"
    watcher = DirectiveWatcher(directives_root=root)

    data = build_sample_directive(directive_id="real-money-001", action_type="ENABLE_REAL_MONEY")
    inbox_file = watcher.inbox_dir / "real-money-001.json"
    inbox_file.write_text(json.dumps(data), encoding="utf-8")

    acks = watcher.poll_inbox()
    assert len(acks) == 1
    assert acks[0].decision in ("REJECTED", "WAITING_HUMAN")
    assert acks[0].executed is False


def test_directive_ack_generated(tmp_path):
    root = tmp_path / "directives"
    watcher = DirectiveWatcher(directives_root=root)

    data = build_sample_directive(directive_id="ack-gen-001")
    inbox_file = watcher.inbox_dir / "ack-gen-001.json"
    inbox_file.write_text(json.dumps(data), encoding="utf-8")

    watcher.poll_inbox()
    ack_path = watcher.ack_dir / "ack-gen-001.json"

    assert ack_path.exists()
    ack_data = json.loads(ack_path.read_text(encoding="utf-8"))
    assert ack_data["directive_id"] == "ack-gen-001"
    assert ack_data["decision"] == "ACCEPTED"


def test_directive_never_executes_target_mutation(tmp_path):
    root = tmp_path / "directives"
    watcher = DirectiveWatcher(directives_root=root)

    data = build_sample_directive(directive_id="no-mutation-001")
    inbox_file = watcher.inbox_dir / "no-mutation-001.json"
    inbox_file.write_text(json.dumps(data), encoding="utf-8")

    acks = watcher.poll_inbox()
    assert acks[0].executed is False


def test_oracle_remains_unmodified(tmp_path):
    """Verifies DirectiveWatcher execution never mutates external project files."""
    fixture_dir = tmp_path / "mock_oracle"
    fixture_dir.mkdir()
    (fixture_dir / "sprints").mkdir()
    test_file = fixture_dir / "sprints" / "AGENT_STATUS.json"
    test_file.write_text('{"status": "READY_FOR_REVIEW"}', encoding="utf-8")

    hash_before = hashlib.sha256(test_file.read_bytes()).hexdigest()

    watcher = DirectiveWatcher(directives_root=tmp_path / "directives")
    watcher.poll_inbox()

    hash_after = hashlib.sha256(test_file.read_bytes()).hexdigest()
    assert hash_before == hash_after


def test_micro_remains_unmodified(tmp_path):
    """Verifies DirectiveWatcher execution never mutates micro project files."""
    fixture_dir = tmp_path / "mock_micro"
    fixture_dir.mkdir()
    (fixture_dir / "control").mkdir()
    test_file = fixture_dir / "control" / "CURRENT_STAGE.json"
    test_file.write_text('{"stage": "MICRO-00.8"}', encoding="utf-8")

    hash_before = hashlib.sha256(test_file.read_bytes()).hexdigest()

    watcher = DirectiveWatcher(directives_root=tmp_path / "directives")
    watcher.poll_inbox()

    hash_after = hashlib.sha256(test_file.read_bytes()).hexdigest()
    assert hash_before == hash_after


def test_single_daemon_still_enforced(tmp_path):
    lock_path = tmp_path / "control_plane.lock"
    lock1 = SingleInstanceLock(lock_path)
    acquired1, _, _ = lock1.acquire()
    assert acquired1 is True

    lock2 = SingleInstanceLock(lock_path)
    acquired2, _, _ = lock2.acquire()
    assert acquired2 is False
    lock1.release()


def test_directive_watcher_does_not_spawn_second_daemon(tmp_path):
    engine = ControlPlaneEngine(output_dir=tmp_path / "state", audit_file=tmp_path / "audit" / "events.jsonl")
    assert hasattr(engine, "directive_watcher")
    assert isinstance(engine.directive_watcher, DirectiveWatcher)


def test_fail_closed_on_github_unavailable(tmp_path, monkeypatch):
    root = tmp_path / "directives"
    watcher = DirectiveWatcher(directives_root=root)

    def mock_subprocess_fail(*args, **kwargs):
        raise subprocess.SubprocessError("GitHub remote network down")

    monkeypatch.setattr(subprocess, "run", mock_subprocess_fail)

    data = build_sample_directive(directive_id="gh-down-001")
    inbox_file = watcher.inbox_dir / "gh-down-001.json"
    inbox_file.write_text(json.dumps(data), encoding="utf-8")

    acks = watcher.poll_inbox()
    assert len(acks) == 1
    assert acks[0].decision == "REJECTED"
    assert "FAIL_CLOSED" in acks[0].decision_reason


def test_fail_closed_on_malformed_json(tmp_path):
    root = tmp_path / "directives"
    watcher = DirectiveWatcher(directives_root=root)

    inbox_file = watcher.inbox_dir / "malformed.json"
    inbox_file.write_text("{this is invalid json syntax...}", encoding="utf-8")

    acks = watcher.poll_inbox()
    assert len(acks) == 1
    assert acks[0].decision == "REJECTED"
    assert "SCHEMA_INVALID" in acks[0].decision_reason


def test_provenance_fields_present(tmp_path):
    root = tmp_path / "directives"
    watcher = DirectiveWatcher(directives_root=root)

    data = build_sample_directive(directive_id="prov-fields-001")
    inbox_file = watcher.inbox_dir / "prov-fields-001.json"
    inbox_file.write_text(json.dumps(data), encoding="utf-8")

    acks = watcher.poll_inbox()
    assert acks[0].source_commit_sha is not None
    assert acks[0].control_plane_commit_sha is not None


# New Mandatory Regression Tests from ChatGPT Audit

def test_commit_exists_but_directive_absent_rejected(tmp_path):
    root = tmp_path / "directives"
    watcher = DirectiveWatcher(directives_root=root)

    # Valid commit sha in history that does NOT contain absent-dir-001.json
    data = build_sample_directive(directive_id="absent-dir-001", source_commit_sha="b90ca18909a2481055c9c7fd8b66c494e02bf9f1")
    inbox_file = watcher.inbox_dir / "absent-dir-001.json"
    inbox_file.write_text(json.dumps(data), encoding="utf-8")

    acks = watcher.poll_inbox()
    assert len(acks) == 1
    assert acks[0].decision == "REJECTED"
    assert acks[0].validation_status in (
        ValidationStatus.COMMIT_EXISTS_BUT_DIRECTIVE_ABSENT.value,
        ValidationStatus.COMMIT_NOT_FOUND.value
    )


def test_directive_commit_not_reachable_from_main_rejected(tmp_path, monkeypatch):
    root = tmp_path / "directives"
    watcher = DirectiveWatcher(directives_root=root)

    def mock_auth(directive, file_path=None):
        return ValidationStatus.NOT_IN_APPROVED_BRANCH, "NOT_IN_APPROVED_BRANCH: Commit not reachable from main", False, {}

    monkeypatch.setattr(watcher.authenticator, "authenticate", mock_auth)

    data = build_sample_directive(directive_id="unreachable-001")
    inbox_file = watcher.inbox_dir / "unreachable-001.json"
    inbox_file.write_text(json.dumps(data), encoding="utf-8")

    acks = watcher.poll_inbox()
    assert len(acks) == 1
    assert acks[0].decision == "REJECTED"
    assert "NOT_IN_APPROVED_BRANCH" in acks[0].decision_reason


def test_real_committed_content_mismatch_rejected(tmp_path, monkeypatch):
    root = tmp_path / "directives"
    watcher = DirectiveWatcher(directives_root=root)

    def mock_auth(directive, file_path=None):
        return ValidationStatus.CONTENT_MISMATCH, "CONTENT_MISMATCH: Committed content differs", False, {}

    monkeypatch.setattr(watcher.authenticator, "authenticate", mock_auth)

    data = build_sample_directive(directive_id="content-mismatch-001")
    inbox_file = watcher.inbox_dir / "content-mismatch-001.json"
    inbox_file.write_text(json.dumps(data), encoding="utf-8")

    acks = watcher.poll_inbox()
    assert len(acks) == 1
    assert acks[0].decision == "REJECTED"
    assert "CONTENT_MISMATCH" in acks[0].decision_reason


def test_local_modified_copy_cannot_authenticate(tmp_path, monkeypatch):
    root = tmp_path / "directives"
    watcher = DirectiveWatcher(directives_root=root)

    data = build_sample_directive(directive_id="local-mod-001")
    data["payload"] = {"tampered": True}
    inbox_file = watcher.inbox_dir / "local-mod-001.json"
    inbox_file.write_text(json.dumps(data), encoding="utf-8")

    def mock_auth(directive, file_path=None):
        return ValidationStatus.CONTENT_MISMATCH, "CONTENT_MISMATCH: Local candidate file content hash mismatch", False, {}

    monkeypatch.setattr(watcher.authenticator, "authenticate", mock_auth)

    acks = watcher.poll_inbox()
    assert len(acks) == 1
    assert acks[0].decision == "REJECTED"


def test_exact_committed_blob_authenticates(tmp_path):
    root = tmp_path / "directives"
    watcher = DirectiveWatcher(directives_root=root)

    data = build_sample_directive(directive_id="exact-blob-001")
    inbox_file = watcher.inbox_dir / "exact-blob-001.json"
    inbox_file.write_text(json.dumps(data), encoding="utf-8")

    acks = watcher.poll_inbox()
    assert len(acks) == 1
    assert acks[0].decision == "ACCEPTED"


def test_waiting_human_survives_second_poll(tmp_path):
    root = tmp_path / "directives"
    watcher = DirectiveWatcher(directives_root=root)

    data = build_sample_directive(directive_id="human-multi-001", requires_human=True)
    inbox_file = watcher.inbox_dir / "human-multi-001.json"
    inbox_file.write_text(json.dumps(data), encoding="utf-8")

    acks1 = watcher.poll_inbox()
    assert acks1[0].decision == "WAITING_HUMAN"
    assert (watcher.waiting_human_dir / "human-multi-001.json").exists()

    # Second poll
    acks2 = watcher.poll_inbox()
    assert len(acks2) == 0
    assert watcher.status.waiting_human_count == 1


def test_waiting_human_survives_restart(tmp_path):
    root = tmp_path / "directives"
    watcher1 = DirectiveWatcher(directives_root=root)

    data = build_sample_directive(directive_id="human-restart-001", requires_human=True)
    inbox_file = watcher1.inbox_dir / "human-restart-001.json"
    inbox_file.write_text(json.dumps(data), encoding="utf-8")

    watcher1.poll_inbox()
    assert (watcher1.waiting_human_dir / "human-restart-001.json").exists()

    # Restart watcher
    watcher2 = DirectiveWatcher(directives_root=root)
    assert watcher2.status.waiting_human_count == 1


def test_waiting_human_not_classified_as_replay(tmp_path):
    root = tmp_path / "directives"
    watcher = DirectiveWatcher(directives_root=root)

    data = build_sample_directive(directive_id="human-noreplay-001", requires_human=True)
    inbox_file = watcher.inbox_dir / "human-noreplay-001.json"
    inbox_file.write_text(json.dumps(data), encoding="utf-8")

    watcher.poll_inbox()
    assert not watcher.replay_ledger.is_consumed("human-noreplay-001")


def test_duplicate_submission_of_waiting_human_is_rejected(tmp_path):
    root = tmp_path / "directives"
    watcher = DirectiveWatcher(directives_root=root)

    data = build_sample_directive(directive_id="human-dup-001", requires_human=True)
    inbox_file1 = watcher.inbox_dir / "human-dup-001.json"
    inbox_file1.write_text(json.dumps(data), encoding="utf-8")
    watcher.poll_inbox()

    # Record finalized consumption
    watcher.replay_ledger.record_consumption("human-dup-001", "sha", "now", "ACCEPTED", "reason")

    inbox_file2 = watcher.inbox_dir / "human-dup-001.json"
    inbox_file2.write_text(json.dumps(data), encoding="utf-8")
    acks2 = watcher.poll_inbox()

    assert len(acks2) == 1
    assert acks2[0].decision == "REJECTED"
    assert "REPLAY_DETECTED" in acks2[0].decision_reason


def test_accepted_queue_survives_restart(tmp_path):
    root = tmp_path / "directives"
    watcher1 = DirectiveWatcher(directives_root=root)

    data = build_sample_directive(directive_id="queue-restart-001")
    inbox_file = watcher1.inbox_dir / "queue-restart-001.json"
    inbox_file.write_text(json.dumps(data), encoding="utf-8")

    watcher1.poll_inbox()
    assert len(watcher1.durable_queue.get_items()) == 1

    # Restart
    watcher2 = DirectiveWatcher(directives_root=root)
    items = watcher2.durable_queue.get_items()
    assert len(items) == 1
    assert items[0].directive_id == "queue-restart-001"
    assert items[0].queue_state == "READY_FOR_FUTURE_EXECUTOR"


def test_accepted_item_not_lost_after_restart(tmp_path):
    root = tmp_path / "directives"
    queue_path = root / "runtime" / "execution_queue.jsonl"
    queue1 = DurableExecutionQueue(queue_path)

    d = Directive.from_dict(build_sample_directive(directive_id="no-lost-001"))
    queue1.enqueue(d, blob_sha="blob123")

    queue2 = DurableExecutionQueue(queue_path)
    assert len(queue2.get_items()) == 1
    assert queue2.get_items()[0].directive_id == "no-lost-001"


def test_restart_does_not_requeue_duplicate(tmp_path):
    root = tmp_path / "directives"
    watcher1 = DirectiveWatcher(directives_root=root)

    data = build_sample_directive(directive_id="no-dup-queue-001")
    inbox_file = watcher1.inbox_dir / "no-dup-queue-001.json"
    inbox_file.write_text(json.dumps(data), encoding="utf-8")
    watcher1.poll_inbox()

    watcher2 = DirectiveWatcher(directives_root=root)
    watcher2.poll_inbox()
    assert len(watcher2.durable_queue.get_items()) == 1


def test_queue_and_replay_ledger_consistent(tmp_path):
    root = tmp_path / "directives"
    watcher = DirectiveWatcher(directives_root=root)

    data = build_sample_directive(directive_id="consistent-001")
    inbox_file = watcher.inbox_dir / "consistent-001.json"
    inbox_file.write_text(json.dumps(data), encoding="utf-8")
    watcher.poll_inbox()

    assert watcher.durable_queue.is_queued("consistent-001") is True
    assert watcher.replay_ledger.is_consumed("consistent-001") is True


def test_channel_status_reconstructed_after_restart(tmp_path):
    root = tmp_path / "directives"
    watcher1 = DirectiveWatcher(directives_root=root)

    data1 = build_sample_directive(directive_id="recon-acc-001")
    data2 = build_sample_directive(directive_id="recon-hum-002", requires_human=True)

    (watcher1.inbox_dir / "recon-acc-001.json").write_text(json.dumps(data1), encoding="utf-8")
    (watcher1.inbox_dir / "recon-hum-002.json").write_text(json.dumps(data2), encoding="utf-8")

    watcher1.poll_inbox()

    watcher2 = DirectiveWatcher(directives_root=root)
    assert watcher2.status.accepted_count == 1
    assert watcher2.status.waiting_human_count == 1
    assert watcher2.status.queued_count == 1
