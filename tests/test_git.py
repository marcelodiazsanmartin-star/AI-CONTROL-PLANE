"""
Test Suite: Git Observer, GitHub Unavailability, Local Machine / Path Missing, Stale Git Head
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


def test_git_observer_github_unavailable(tmp_path, monkeypatch):
    """Simulates git ls-remote network failure or timeout without crashing."""
    repo_dir = tmp_path / "mock_git_repo"
    repo_dir.mkdir()
    (repo_dir / ".git").mkdir()

    def mock_run_git(self, repo_path, args):
        if "rev-parse" in args and "--abbrev-ref" in args:
            return "main"
        if "rev-parse" in args and "HEAD" in args:
            return "1234567890abcdef"
        if "status" in args:
            return ""
        if "ls-remote" in args:
            return None  # GitHub / network offline simulation
        return None

    monkeypatch.setattr(GitObserver, "_run_git", mock_run_git)

    observer = GitObserver()
    info = observer.observe_repo(repo_dir)

    assert info["git_available"] is True
    assert info["branch"] == "main"
    assert info["local_head"] == "1234567890abcdef"
    assert info["remote_head"] is None
    assert len(info["observer_errors"]) > 0  # Contains non-fatal GitHub offline notice
