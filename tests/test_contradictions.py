"""
Test Suite: Contradictory Status Files & Evidence Precedence Resolution
"""

import pytest
from src.state_machine.evaluator import StateEvaluator
from src.contracts import CanonicalState, EvidenceItem


def test_micro_contradiction_with_running_process():
    """
    Tests scenario:
    CURRENT_STAGE.json: status = READY_FOR_ANTIGRAVITY
    PROJECT_STATE.json: status = READY_FOR_AUDIT
    WATCHER_STATE.json: status = STOPPED
    Process table: ACTIVE expected process running

    Precedence 1 (Process Observation) wins over static files.
    derived status = RUNNING
    state_conflict = True
    status_source = "1_LOCAL_PROCESS_OBSERVATION"
    """
    evaluator = StateEvaluator()

    observed_data = {
        "project": "MICRO-MARKET-ORACLE",
        "git_info": {"branch": "micro00-8-antigravity-watcher"},
        "process_expected": True,
        "process_running": True,
        "matched_process_name": "run_watcher.py",
        "evidence_map": {
            "control/CURRENT_STAGE.json": EvidenceItem(
                source_name="CURRENT_STAGE.json",
                filepath="control/CURRENT_STAGE.json",
                file_exists=True,
                parsed_data={"status": "READY_FOR_ANTIGRAVITY", "stage": "MICRO-00.8"}
            ),
            "control/PROJECT_STATE.json": EvidenceItem(
                source_name="PROJECT_STATE.json",
                filepath="control/PROJECT_STATE.json",
                file_exists=True,
                parsed_data={"status": "READY_FOR_AUDIT", "stage": "MICRO-00.8"}
            ),
            "control/WATCHER_STATE.json": EvidenceItem(
                source_name="WATCHER_STATE.json",
                filepath="control/WATCHER_STATE.json",
                file_exists=True,
                parsed_data={"heartbeat": {"status": "STOPPED"}}
            )
        }
    }

    state = evaluator.evaluate(observed_data)

    assert state.status == CanonicalState.RUNNING
    assert state.state_conflict is True
    assert len(state.conflicting_sources) == 3
    assert state.status_source == "1_LOCAL_PROCESS_OBSERVATION"
    assert "Active expected process running" in state.reason


def test_stopped_watcher_when_not_expected_does_not_block():
    """
    A STOPPED watcher when no watcher is required (process_expected = False)
    must NOT automatically produce BLOCKED.
    """
    evaluator = StateEvaluator()

    observed_data = {
        "project": "MICRO-MARKET-ORACLE",
        "git_info": {},
        "process_expected": False,
        "process_running": False,
        "evidence_map": {
            "control/PROJECT_STATE.json": EvidenceItem(
                source_name="PROJECT_STATE.json",
                filepath="control/PROJECT_STATE.json",
                file_exists=True,
                parsed_data={"status": "READY_FOR_AUDIT", "stage": "MICRO-00.8", "next_action": "CHATGPT_AUDIT"}
            ),
            "control/WATCHER_STATE.json": EvidenceItem(
                source_name="WATCHER_STATE.json",
                filepath="control/WATCHER_STATE.json",
                file_exists=True,
                parsed_data={"heartbeat": {"status": "STOPPED"}}
            )
        }
    }

    state = evaluator.evaluate(observed_data)

    assert state.status == CanonicalState.IDLE_VALID
    assert state.status_source == "control/PROJECT_STATE.json"
