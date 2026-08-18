"""
Test Suite: Control Plane Restart & Audit Event Trail Persistence
"""

import json
import pytest
from pathlib import Path
from src.engine import ControlPlaneEngine


def test_control_plane_restart_and_audit(tmp_path):
    output_dir = tmp_path / "state"
    audit_file = tmp_path / "audit" / "events.jsonl"

    # Run 1
    engine1 = ControlPlaneEngine(output_dir=output_dir, audit_file=audit_file)
    engine1.run_sweep()

    assert (output_dir / "oracle.json").exists()
    assert (output_dir / "micro.json").exists()
    assert (output_dir / "global_status.json").exists()
    assert audit_file.exists()

    with open(audit_file, "r", encoding="utf-8") as f:
        lines_run1 = [json.loads(line) for line in f.readlines()]
    assert len(lines_run1) == 2

    # Simulate restart & Run 2
    engine2 = ControlPlaneEngine(output_dir=output_dir, audit_file=audit_file)
    engine2.run_sweep()

    with open(audit_file, "r", encoding="utf-8") as f:
        lines_run2 = [json.loads(line) for line in f.readlines()]
    assert len(lines_run2) == 4
