"""
Test Suite: Fail-Closed Rule Verification
Missing evidence != PASS. Must default to UNKNOWN or STALE. Never infer RUNNING.
"""

import pytest
from src.state_machine.evaluator import StateEvaluator
from src.contracts import CanonicalState, EvidenceItem


def test_missing_evidence_defaults_to_unknown():
    evaluator = StateEvaluator()

    observed_data = {
        "project": "MISSING_EVIDENCE_PROJ",
        "git_info": {},
        "process_expected": False,
        "process_running": False,
        "evidence_map": {}
    }

    state = evaluator.evaluate(observed_data)
    assert state.status == CanonicalState.UNKNOWN
    assert state.confidence == 0.0
    assert "No evidence files found" in state.reason


def test_stale_declaration_never_infers_running():
    """Even if an old file says RUNNING, if process is dead and heartbeat is missing/stale, status is not RUNNING."""
    evaluator = StateEvaluator()

    observed_data = {
        "project": "STALE_RUNNING_PROJ",
        "git_info": {},
        "process_expected": True,
        "process_running": False,  # Process is dead
        "evidence_map": {
            "old_state.json": EvidenceItem(
                source_name="old_state.json",
                filepath="old_state.json",
                file_exists=True,
                parsed_data={"status": "RUNNING"}
            )
        }
    }

    state = evaluator.evaluate(observed_data)
    assert state.status != CanonicalState.RUNNING
    assert state.status in (CanonicalState.STALE, CanonicalState.BLOCKED)
    assert state.state_conflict is True
