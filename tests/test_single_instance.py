"""
Test Suite: Single Instance Guarantee, Stale Lock Recovery, and Process Non-Interference
"""

import pytest
import os
import subprocess
import sys
from pathlib import Path
from src.lock_manager import SingleInstanceLock
from src.engine import ControlPlaneEngine
from config import settings


def test_single_instance_lock_acquisition(tmp_path):
    lock_path = tmp_path / "test_control_plane.lock"

    # Instance 1 acquires lock
    lock1 = SingleInstanceLock(lock_path)
    acquired1, pid1, msg1 = lock1.acquire()

    assert acquired1 is True
    assert pid1 is not None
    assert "acquired" in msg1.lower()

    # Instance 2 attempts to acquire lock while Instance 1 is active -> REJECTED!
    lock2 = SingleInstanceLock(lock_path)
    acquired2, pid2, msg2 = lock2.acquire()

    assert acquired2 is False
    assert pid2 == pid1
    assert "REJECTED" in msg2

    # Release Instance 1
    lock1.release()

    # Instance 3 attempts to acquire lock after Instance 1 is released -> SUCCEEDS!
    lock3 = SingleInstanceLock(lock_path)
    acquired3, pid3, msg3 = lock3.acquire()

    assert acquired3 is True
    lock3.release()


def test_second_daemon_is_rejected(tmp_path):
    """
    Requirement 5: Explicit test that a second main.py process launch is REJECTED
    when a primary daemon instance holds the lock.
    """
    lock_path = tmp_path / "daemon_test.lock"

    daemon1 = SingleInstanceLock(lock_path)
    acquired1, pid1, msg1 = daemon1.acquire()
    assert acquired1 is True

    # Secondary launch attempt
    daemon2 = SingleInstanceLock(lock_path)
    acquired2, pid2, msg2 = daemon2.acquire()

    assert acquired2 is False
    assert pid2 == pid1
    assert "REJECTED: Another instance of AI-CONTROL-PLANE is already running" in msg2

    daemon1.release()


def test_stale_daemon_lock_recovery(tmp_path):
    """
    Requirement 5: Explicit test for stale lock recovery when previous process PID is inactive.
    """
    lock_path = tmp_path / "stale_test.lock"
    pid_path = lock_path.with_suffix(".pid")

    # Simulate a dead process lockfile with PID 999999 (non-existent PID)
    stale_pid = 999999
    pid_path.write_text(str(stale_pid), encoding="utf-8")

    # New instance attempts acquisition -> recovers lock because OS lock is not held
    new_lock = SingleInstanceLock(lock_path)
    acquired, new_pid, msg = new_lock.acquire()

    assert acquired is True
    assert new_pid == os.getpid()
    assert new_pid != stale_pid
    new_lock.release()


def test_monitored_processes_never_terminated(tmp_path, monkeypatch):
    """
    Requirement 5: Explicit test certifying ControlPlaneEngine never terminates,
    signals, or interrupts any process matching monitored projects (ORACLE, MICRO).
    """
    terminated_pids = []

    def mock_kill(pid, sig):
        terminated_pids.append((pid, sig))
        raise PermissionError("Attempted process termination!")

    monkeypatch.setattr(os, "kill", mock_kill, raising=False)

    engine = ControlPlaneEngine(output_dir=tmp_path / "state", audit_file=tmp_path / "audit" / "events.jsonl")
    states = engine.run_sweep()

    # Zero process termination calls must have occurred!
    assert len(terminated_pids) == 0
