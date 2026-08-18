"""
Test Suite: Single Instance Guarantee & OS File Lock Verification
"""

import pytest
from pathlib import Path
from src.lock_manager import SingleInstanceLock


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
