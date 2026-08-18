"""
Test Suite: Heartbeat Freshness, Staleness, and Missing Heartbeats
"""

import pytest
from datetime import datetime, timezone, timedelta
from src.state_machine.evaluator import StateEvaluator
from src.contracts import CanonicalState, EvidenceItem


def test_fresh_heartbeat():
    now_dt = datetime.now(timezone.utc)
    fresh_ts = (now_dt - timedelta(seconds=60)).isoformat()
    evaluator = StateEvaluator(heartbeat_stale_threshold_seconds=300.0, reference_time=now_dt)

    observed_data = {
        "project": "TEST_PROJ",
        "git_info": {"branch": "main", "local_head": "abc"},
        "process_expected": True,
        "process_running": True,
        "matched_process_name": "test_runner.py",
        "evidence_map": {
            "state.json": EvidenceItem(
                source_name="state.json",
                filepath="/tmp/state.json",
                file_exists=True,
                parsed_data={"status": "RUNNING", "heartbeat": {"last_update": fresh_ts}}
            )
        }
    }

    state = evaluator.evaluate(observed_data)
    assert state.status == CanonicalState.RUNNING
    assert state.heartbeat_age_seconds is not None
    assert state.heartbeat_age_seconds <= 300.0
    assert not state.state_conflict


def test_stale_heartbeat():
    now_dt = datetime.now(timezone.utc)
    stale_ts = (now_dt - timedelta(seconds=600)).isoformat()
    evaluator = StateEvaluator(heartbeat_stale_threshold_seconds=300.0, reference_time=now_dt)

    observed_data = {
        "project": "TEST_PROJ",
        "git_info": {"branch": "main", "local_head": "abc"},
        "process_expected": False,
        "process_running": False,
        "evidence_map": {
            "sprints/AGENT_STATUS.json": EvidenceItem(
                source_name="AGENT_STATUS.json",
                filepath="/tmp/AGENT_STATUS.json",
                file_exists=True,
                parsed_data={"status": "IDLE", "timestamp": stale_ts}
            )
        }
    }

    state = evaluator.evaluate(observed_data)
    assert state.status == CanonicalState.STALE
    assert state.heartbeat_age_seconds > 300.0
    assert "exceeds project threshold" in state.reason


def test_missing_heartbeat():
    now_dt = datetime.now(timezone.utc)
    evaluator = StateEvaluator(heartbeat_stale_threshold_seconds=300.0, reference_time=now_dt)

    observed_data = {
        "project": "TEST_PROJ",
        "git_info": {"branch": "main", "local_head": "abc"},
        "process_expected": True,
        "process_running": False,
        "evidence_map": {
            "state.json": EvidenceItem(
                source_name="state.json",
                filepath="/tmp/state.json",
                file_exists=False
            )
        }
    }

    state = evaluator.evaluate(observed_data)
    assert state.status in (CanonicalState.UNKNOWN, CanonicalState.STALE)
    assert state.last_heartbeat is None
    assert state.heartbeat_age_seconds is None
