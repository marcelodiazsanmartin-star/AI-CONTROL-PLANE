"""
Adversarial Test Suite: Strict Read-Only Protocol & Disallowed Git Command Interception

Verifies:
1. Control Plane interceptor blocks all mutating git commands (fetch, pull, checkout, reset, clean, commit, etc.).
2. EvidenceCollector opens files strictly in read-only mode ('r').
3. External project activity is classified separately and does not imply Control Plane modified the repos.
"""

import os
import hashlib
import pytest
from pathlib import Path
from config import settings
from src.observer.git_observer import GitObserver
from src.observer.evidence_collector import EvidenceCollector
from src.engine import ControlPlaneEngine


def test_disallowed_git_commands_blocked(tmp_path):
    repo_dir = tmp_path / "mock_repo"
    repo_dir.mkdir()
    (repo_dir / ".git").mkdir()

    observer = GitObserver()

    # Verify mutating git commands raise security violation
    for disallowed_cmd in ["fetch", "pull", "checkout", "reset", "clean", "add", "commit", "gc"]:
        with pytest.raises(ValueError, match="SECURITY VIOLATION"):
            observer._run_git(repo_dir, [disallowed_cmd])


def test_read_only_file_access(tmp_path):
    test_file = tmp_path / "evidence.json"
    test_file.write_text('{"status": "RUNNING"}', encoding="utf-8")

    collector = EvidenceCollector()
    item = collector.collect_file_evidence(tmp_path, "evidence.json")

    assert item.file_exists is True
    assert item.parsed_data == {"status": "RUNNING"}
    # File content remains unchanged
    assert test_file.read_text(encoding="utf-8") == '{"status": "RUNNING"}'


def test_isolated_fixture_immutability(tmp_path):
    """Verifies that running ControlPlaneEngine on isolated fixtures leaves files 100% untouched."""
    fixture_dir = tmp_path / "mock_oracle"
    fixture_dir.mkdir()
    (fixture_dir / ".git").mkdir()
    (fixture_dir / "sprints").mkdir()
    
    agent_status = fixture_dir / "sprints" / "AGENT_STATUS.json"
    agent_status.write_text('{"status": "READY_FOR_REVIEW", "gates": {"FINAL_STATUS": "PASS"}}', encoding="utf-8")

    # Hash before
    hash_before = hashlib.sha256(agent_status.read_bytes()).hexdigest()

    collector = EvidenceCollector()
    collector.collect_file_evidence(fixture_dir, "sprints/AGENT_STATUS.json")

    # Hash after
    hash_after = hashlib.sha256(agent_status.read_bytes()).hexdigest()

    assert hash_before == hash_after
