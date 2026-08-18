"""
Test Suite: Process Alive vs Process Dead Inspection
"""

import pytest
from src.observer.process_observer import ProcessObserver
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


def test_fail_closed_on_dead_process():
    """If process expected is dead while file says RUNNING, evaluator flags STALE/BLOCKED."""
    evaluator = StateEvaluator()
    observed_data = {
        "project": "MOCK_PROJECT",
        "git_info": {},
        "process_expected": True,
        "process_running": False,
        "evidence_map": {
            "PROJECT_STATE.json": EvidenceItem(
                source_name="PROJECT_STATE.json",
                filepath="/tmp/PROJECT_STATE.json",
                file_exists=True,
                parsed_data={"status": "RUNNING"}
            )
        }
    }

    state = evaluator.evaluate(observed_data)
    assert state.state_conflict is True
    assert state.status in (CanonicalState.STALE, CanonicalState.BLOCKED)
    assert "process_table" in state.conflicting_sources
