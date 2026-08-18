"""
Test Suite: Malformed State Files & Clock Skew Resilience
"""

import pytest
from datetime import datetime, timezone, timedelta
from src.state_machine.evaluator import StateEvaluator
from src.contracts import CanonicalState, EvidenceItem


def test_malformed_json_evidence():
    evaluator = StateEvaluator()

    observed_data = {
        "project": "MALFORMED_PROJ",
        "git_info": {},
        "process_expected": False,
        "process_running": False,
        "evidence_map": {
            "corrupt.json": EvidenceItem(
                source_name="corrupt.json",
                filepath="corrupt.json",
                file_exists=True,
                parse_error="JSON decode error: Expecting value at line 1 column 1",
                parsed_data=None
            )
        }
    }

    # Evaluator should gracefully handle corrupted JSON without crashing
    state = evaluator.evaluate(observed_data)
    assert state.status in (CanonicalState.UNKNOWN, CanonicalState.IDLE_VALID)
    assert state.project == "MALFORMED_PROJ"


def test_future_clock_skew():
    """If heartbeat timestamp is in the future relative to system clock, clamp age to 0.0s."""
    now_dt = datetime.now(timezone.utc)
    future_ts = (now_dt + timedelta(seconds=120)).isoformat()

    evaluator = StateEvaluator(reference_time=now_dt)

    observed_data = {
        "project": "FUTURE_SKEW_PROJ",
        "git_info": {},
        "process_expected": False,
        "process_running": False,
        "evidence_map": {
            "PROJECT_STATE.json": EvidenceItem(
                source_name="PROJECT_STATE.json",
                filepath="PROJECT_STATE.json",
                file_exists=True,
                parsed_data={"status": "READY_FOR_AUDIT", "heartbeat": {"last_update": future_ts}}
            )
        }
    }

    state = evaluator.evaluate(observed_data)
    assert state.heartbeat_age_seconds == 0.0
    assert state.status == CanonicalState.IDLE_VALID
