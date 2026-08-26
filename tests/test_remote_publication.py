"""Remote publication is explicit, fail-closed, and isolated from local sweeps."""

from types import SimpleNamespace

import pytest
from src.engine import ControlPlaneEngine
from config import settings


class _NoOpDirectiveWatcher:
    def poll_inbox(self):
        return []


def test_default_sweeps_never_invoke_remote_publication(tmp_path, monkeypatch):
    output_dir = tmp_path / "state"
    audit_file = tmp_path / "audit" / "events.jsonl"

    publish_call_count = 0

    def mock_publish(self):
        nonlocal publish_call_count
        publish_call_count += 1
        return True

    monkeypatch.setattr(ControlPlaneEngine, "publish_remote_status", mock_publish)

    engine = ControlPlaneEngine(output_dir=output_dir, audit_file=audit_file, directive_watcher=_NoOpDirectiveWatcher())
    assert settings.REMOTE_PUBLICATION_ENABLED is False
    engine.run_sweep()
    engine.run_sweep()
    engine.last_states["ORACLE-AI"] = "DIFFERENT_PREVIOUS_STATE"
    engine.run_sweep()
    assert publish_call_count == 0
    assert (output_dir / "global_status.json").exists()
    assert audit_file.exists()


def test_publish_disabled_does_not_invoke_subprocess(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "CONTROL_PLANE_ROOT", tmp_path)
    (tmp_path / ".git").mkdir()
    monkeypatch.setattr("src.engine.subprocess.run", lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("git invoked")))
    engine = ControlPlaneEngine(output_dir=tmp_path / "local", audit_file=tmp_path / "audit.jsonl")
    assert engine.publish_remote_status() is False


def test_protected_branch_variants_fail_closed_without_git(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "REMOTE_PUBLICATION_ENABLED", True)
    monkeypatch.setattr(settings, "PROTECTED_REMOTE_PUBLISH_BRANCHES", frozenset({"main", "master"}))
    monkeypatch.setattr(settings, "CONTROL_PLANE_ROOT", tmp_path)
    (tmp_path / ".git").mkdir()
    monkeypatch.setattr("src.engine.subprocess.run", lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("git invoked")))
    engine = ControlPlaneEngine(output_dir=tmp_path / "local", audit_file=tmp_path / "audit.jsonl")
    for branch in ("main", "MAIN", " Main ", "refs/heads/main", "REFS/HEADS/MAIN", "master"):
        monkeypatch.setattr(settings, "REMOTE_PUBLISH_BRANCH", branch)
        assert engine.publish_remote_status() is False


def test_missing_or_invalid_publication_config_fails_closed(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "CONTROL_PLANE_ROOT", tmp_path)
    (tmp_path / ".git").mkdir()
    engine = ControlPlaneEngine(output_dir=tmp_path / "local", audit_file=tmp_path / "audit.jsonl")
    monkeypatch.delattr(settings, "REMOTE_PUBLICATION_ENABLED")
    assert engine.publish_remote_status() is False
    monkeypatch.setattr(settings, "REMOTE_PUBLICATION_ENABLED", True, raising=False)
    for invalid in (None, 7, "", "   ", "-option", "feature branch"):
        monkeypatch.setattr(settings, "REMOTE_PUBLISH_BRANCH", invalid)
        assert engine.publish_remote_status() is False


@pytest.mark.parametrize(
    "branch",
    (
        "HEAD:main",
        "feature:main",
        "+HEAD:main",
        "refs/heads/feature:refs/heads/main",
        "+feature",
        "feature*wildcard",
        "feature^parent",
        "feature~parent",
        "feature?query",
        "feature[range",
        r"feature\backslash",
        "feature..main",
        "feature@{upstream}",
        "feature\x00control",
        "feature\x1fcontrol",
        "feature\x7fcontrol",
        "/feature",
        "feature/",
        "feature//nested",
        ".feature",
        "team/.feature",
        "feature.",
        "feature.lock",
        "team/feature.LOCK",
        " feature",
        "feature ",
        "@",
    ),
)
def test_refspec_and_invalid_branch_syntax_fail_before_git(
    tmp_path, monkeypatch, branch
):
    monkeypatch.setattr(settings, "REMOTE_PUBLICATION_ENABLED", True)
    monkeypatch.setattr(settings, "REMOTE_PUBLISH_BRANCH", branch)
    monkeypatch.setattr(settings, "CONTROL_PLANE_ROOT", tmp_path)
    (tmp_path / ".git").mkdir()
    monkeypatch.setattr(
        "src.engine.subprocess.run",
        lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("git invoked")),
    )
    engine = ControlPlaneEngine(
        output_dir=tmp_path / "local", audit_file=tmp_path / "audit.jsonl"
    )
    assert engine.publish_remote_status() is False


def test_valid_branch_uses_controlled_push_refspec(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "REMOTE_PUBLICATION_ENABLED", True)
    monkeypatch.setattr(settings, "REMOTE_PUBLISH_BRANCH", "codex/local-publication")
    monkeypatch.setattr(settings, "CONTROL_PLANE_ROOT", tmp_path)
    (tmp_path / ".git").mkdir()
    calls = []

    def successful_stage(command, **kwargs):
        calls.append(command)
        stdout = " M state/example.json\n" if command[1:3] == ["status", "--porcelain"] else ""
        return SimpleNamespace(returncode=0, stdout=stdout, stderr="")

    monkeypatch.setattr("src.engine.subprocess.run", successful_stage)
    engine = ControlPlaneEngine(
        output_dir=tmp_path / "local", audit_file=tmp_path / "audit.jsonl"
    )
    assert engine.publish_remote_status() is True
    assert calls[-1] == [
        "git",
        "push",
        "origin",
        "HEAD:refs/heads/codex/local-publication",
    ]


@pytest.mark.parametrize("failure_index", range(4))
def test_subprocess_failure_never_reports_success(tmp_path, monkeypatch, failure_index):
    monkeypatch.setattr(settings, "REMOTE_PUBLICATION_ENABLED", True)
    monkeypatch.setattr(settings, "REMOTE_PUBLISH_BRANCH", "codex/local-publication")
    monkeypatch.setattr(settings, "CONTROL_PLANE_ROOT", tmp_path)
    (tmp_path / ".git").mkdir()
    calls = []

    def fail_one_stage(command, **kwargs):
        calls.append(command)
        index = len(calls) - 1
        if index == failure_index:
            return SimpleNamespace(returncode=1, stdout="", stderr="denied")
        stdout = " M state/example.json\n" if command[1:3] == ["status", "--porcelain"] else ""
        return SimpleNamespace(returncode=0, stdout=stdout, stderr="")

    monkeypatch.setattr("src.engine.subprocess.run", fail_one_stage)
    engine = ControlPlaneEngine(output_dir=tmp_path / "local", audit_file=tmp_path / "audit.jsonl")
    assert engine.publish_remote_status() is False
    assert len(calls) == failure_index + 1
