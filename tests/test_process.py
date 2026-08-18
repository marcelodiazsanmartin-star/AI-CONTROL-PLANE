"""
Test Suite: Process Alive vs Process Dead Inspection & Context-Aware Expectations
"""

import pytest
from src.observer.process_observer import ProcessObserver
from src.observer.project_observer import ProjectObserver
from src.state_machine.evaluator import StateEvaluator
from src.contracts import CanonicalState, EvidenceItem


def test_process_alive_detection():
    mock_processes = [
        {"ProcessId": 101, "CommandLine": "C:\\Python313\\python.exe download_and_unify_real_data.py"},
        {"ProcessId": 102, "CommandLine": "svchost.exe"}
    ]

    proc_observer = ProcessObserver(process_provider=lambda: mock_processes)
    running, matched, pid = proc_observer.check_process_running(["download_and_unify_real_data.py"])

    assert running is True
    assert matched == "download_and_unify_real_data.py"
    assert pid == 101


def test_process_dead_detection():
    mock_processes = [
        {"ProcessId": 201, "CommandLine": "notepad.exe"}
    ]

    proc_observer = ProcessObserver(process_provider=lambda: mock_processes)
    running, matched, pid = proc_observer.check_process_running(["live_test.py", "run_watcher.py"])

    assert running is False
    assert matched is None
    assert pid is None


def test_integration_dead_expected_process(tmp_path):
    """
    Requirement #2 Integration Test through ProjectObserver:
    configured stage-derived expected process = True + OS process disappears = STALE/BLOCKED
    """
    proj_dir = tmp_path / "mock_project"
    proj_dir.mkdir()
    (proj_dir / ".git").mkdir()

    # Process table missing expected script
    mock_proc_observer = ProcessObserver(process_provider=lambda: [])
    project_observer = ProjectObserver(process_observer=mock_proc_observer)

    proj_cfg = {
        "name": "MOCK_PROJECT",
        "root_path": proj_dir,
        "expected_process_names": ["expected_daemon.py"],
        "default_process_expected": True,  # Configured expected process = True
        "state_files": []
    }

    obs = project_observer.observe(proj_cfg)
    assert obs["process_expected"] is True
    assert obs["process_running"] is False

    evaluator = StateEvaluator()
    state = evaluator.evaluate(obs)

    assert state.process_expected is True
    assert state.process_running is False
    assert state.status in (CanonicalState.STALE, CanonicalState.BLOCKED)
    assert "Process expected to be running but OS process table shows inactive" in state.reason


def test_unexpected_process_running(tmp_path):
    """
    expected FALSE + running TRUE -> unexpected_process = True
    """
    mock_proc_observer = ProcessObserver(process_provider=lambda: [
        {"ProcessId": 505, "CommandLine": "python unexpected_worker.py"}
    ])
    project_observer = ProjectObserver(process_observer=mock_proc_observer)

    proj_cfg = {
        "name": "MOCK_PROJECT",
        "root_path": tmp_path,
        "expected_process_names": ["unexpected_worker.py"],
        "default_process_expected": False,  # Configured expected process = False
        "state_files": []
    }

    obs = project_observer.observe(proj_cfg)
    assert obs["process_expected"] is False
    assert obs["process_running"] is True
    assert obs["unexpected_process"] is True

    evaluator = StateEvaluator()
    state = evaluator.evaluate(obs)

    assert state.unexpected_process is True
    assert state.state_conflict is True
    assert "unexpected_process" in state.conflicting_sources
