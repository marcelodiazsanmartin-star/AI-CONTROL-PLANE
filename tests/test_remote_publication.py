"""
Test Suite: Remote Publication Debouncing & Commit Storm Prevention
"""

import pytest
from pathlib import Path
from src.engine import ControlPlaneEngine
from config import settings


def test_commit_storm_prevention(tmp_path, monkeypatch):
    output_dir = tmp_path / "state"
    audit_file = tmp_path / "audit" / "events.jsonl"

    publish_call_count = 0

    def mock_publish(self):
        nonlocal publish_call_count
        publish_call_count += 1
        return True

    monkeypatch.setattr(ControlPlaneEngine, "publish_remote_status", mock_publish)

    engine = ControlPlaneEngine(output_dir=output_dir, audit_file=audit_file)

    # Sweep 1: Initial sweep (publishes initial state)
    engine.run_sweep()
    assert publish_call_count == 1

    # Sweep 2: State unchanged, checkpoint interval not elapsed -> NO remote publication!
    engine.run_sweep()
    assert publish_call_count == 1

    # Sweep 3: State unchanged -> NO remote publication!
    engine.run_sweep()
    assert publish_call_count == 1

    # Sweep 4: Simulate state transition on project
    engine.last_states["ORACLE-AI"] = "DIFFERENT_PREVIOUS_STATE"
    engine.run_sweep()
    assert publish_call_count == 2
