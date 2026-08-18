"""
Test Suite: Intentionally Idle, Completed, and Human Decision Required States
"""

import pytest
from src.state_machine.evaluator import StateEvaluator
from src.contracts import CanonicalState, EvidenceItem


def test_human_decision_required():
    evaluator = StateEvaluator()

    observed_data = {
        "project": "HUMAN_REQ_PROJ",
        "git_info": {},
        "process_expected": False,
        "process_running": False,
        "evidence_map": {
            "HUMAN_APPROVAL_REQUIRED.md": EvidenceItem(
                source_name="HUMAN_APPROVAL_REQUIRED.md",
                filepath="HUMAN_APPROVAL_REQUIRED.md",
                file_exists=True,
                parsed_data={"raw_text": "Human sign-off needed for release"}
            )
        }
    }

    state = evaluator.evaluate(observed_data)
    assert state.status == CanonicalState.HUMAN_REQUIRED
    assert state.human_required is True
    assert state.human_decision_required is True


def test_project_completed():
    evaluator = StateEvaluator()

    observed_data = {
        "project": "ORACLE-AI",
        "git_info": {},
        "process_expected": False,
        "process_running": False,
        "evidence_map": {
            "AGENT_STATUS.json": EvidenceItem(
                source_name="AGENT_STATUS.json",
                filepath="AGENT_STATUS.json",
                file_exists=True,
                parsed_data={"status": "READY_FOR_REVIEW", "gates": {"FINAL_STATUS": "PASS"}}
            )
        }
    }

    state = evaluator.evaluate(observed_data)
    assert state.status == CanonicalState.COMPLETED
    assert "completed" in state.reason.lower()


def test_project_idle_valid():
    evaluator = StateEvaluator()

    observed_data = {
        "project": "IDLE_PROJ",
        "git_info": {},
        "process_expected": False,
        "process_running": False,
        "evidence_map": {
            "PROJECT_STATE.json": EvidenceItem(
                source_name="PROJECT_STATE.json",
                filepath="PROJECT_STATE.json",
                file_exists=True,
                parsed_data={"status": "READY_FOR_AUDIT", "next_action": "AUDIT"}
            )
        }
    }

    state = evaluator.evaluate(observed_data)
    assert state.status == CanonicalState.IDLE_VALID
    assert state.next_action == "AUDIT"
