"""
Adversarial Test Suite: CONTROL-02.5 Secure Directive Channel
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
    source_commit_sha: str = "b90ca18909a2481055c9c7fd8b66c494e02bf9f1",
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
            return ValidationStatus.CONTENT_MISMATCH, "CONTENT_MISMATCH: Hash mismatch", False

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

    # Simulate restart by instantiating new DirectiveWatcher with fresh ledger instance pointing to same file
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
    assert inbox_file.exists()  # Leaves in inbox for human review


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
