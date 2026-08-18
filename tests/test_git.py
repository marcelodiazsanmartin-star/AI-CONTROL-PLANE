"""
Test Suite: Git Observer, GitHub Unavailability, Remote Branch Verification, Read-Only Locks Environment
"""

import pytest
from pathlib import Path
from src.observer.git_observer import GitObserver


def test_git_observer_nonexistent_repo(tmp_path):
    fake_path = tmp_path / "nonexistent_repo"
    observer = GitObserver(timeout_seconds=0.5)

    info = observer.observe_repo(fake_path)
    assert info["git_available"] is False
    assert info["branch"] is None
    assert info["local_head"] is None
    assert info["remote_head"] is None
    assert len(info["observer_errors"]) > 0


def test_remote_branch_verification_exact_ref(tmp_path, monkeypatch):
    """
    Requirement #1: Local branch A + remote default branch B does NOT compare local HEAD against B.
    Queries ls-remote --heads origin refs/heads/<branch> specifically.
    """
    repo_dir = tmp_path / "mock_git_repo"
    repo_dir.mkdir()
    (repo_dir / ".git").mkdir()

    executed_git_commands = []

    def mock_run_git(self, repo_path, args):
        executed_git_commands.append(" ".join(args))
        if "rev-parse" in args and "--abbrev-ref" in args:
            return "feature/custom-branch"
        if "rev-parse" in args and "HEAD" in args:
            return "aaaa1111222233334444"
        if "status" in args:
            return ""
        if "ls-remote" in args and "refs/heads/feature/custom-branch" in args:
            # Returns exact matching line for refs/heads/feature/custom-branch
            return "bbbb1111222233334444\trefs/heads/feature/custom-branch"
        return None

    monkeypatch.setattr(GitObserver, "_run_git", mock_run_git)

    observer = GitObserver()
    info = observer.observe_repo(repo_dir)

    assert info["git_available"] is True
    assert info["branch"] == "feature/custom-branch"
    assert info["local_head"] == "aaaa1111222233334444"
    assert info["remote_head"] == "bbbb1111222233334444"
    assert info["remote_branch_exists"] is True

    # Assert exact command was executed (refs/heads/feature/custom-branch, NOT generic HEAD)
    assert any("ls-remote --heads origin refs/heads/feature/custom-branch" in cmd for cmd in executed_git_commands)


def test_read_only_git_environment_passed(tmp_path, monkeypatch):
    """
    Requirement #4: Verifies GIT_OPTIONAL_LOCKS=0, GIT_TERMINAL_PROMPT=0, GIT_SSH_COMMAND are passed.
    """
    repo_dir = tmp_path / "mock_git_repo"
    repo_dir.mkdir()
    (repo_dir / ".git").mkdir()

    captured_envs = {}

    import subprocess
    orig_run = subprocess.run

    def mock_subprocess_run(cmd, capture_output=True, text=True, env=None, timeout=None):
        if env:
            captured_envs.update(env)
        return orig_run(["git", "--version"], capture_output=True, text=True)

    monkeypatch.setattr(subprocess, "run", mock_subprocess_run)

    observer = GitObserver()
    observer._run_git(repo_dir, ["status", "--porcelain"])

    assert captured_envs.get("GIT_OPTIONAL_LOCKS") == "0"
    assert captured_envs.get("GIT_TERMINAL_PROMPT") == "0"
    assert captured_envs.get("GIT_SSH_COMMAND") == "ssh -o BatchMode=yes"
