"""
Single Instance Process Lock Manager

Guarantees strictly ONE active instance of AI-CONTROL-PLANE can execute at any time.
Uses OS-level non-blocking file locking (msvcrt on Windows, fcntl on POSIX).
"""

import os
import sys
import json
from pathlib import Path
from typing import Tuple, Optional

if os.name == 'nt':
    import msvcrt
else:
    import fcntl


class SingleInstanceLock:
    def __init__(self, lock_file_path: Path):
        self.lock_file_path = lock_file_path
        self.pid_file_path = lock_file_path.with_suffix(".pid")
        self.lock_file_path.parent.mkdir(parents=True, exist_ok=True)
        self.file_handle = None

    def acquire(self) -> Tuple[bool, Optional[int], str]:
        """
        Attempts to acquire atomic single-instance OS file lock.
        Returns (acquired: bool, existing_pid: Optional[int], message: str)
        """
        existing_pid = None
        try:
            self.file_handle = open(self.lock_file_path, "a+", encoding="utf-8")

            # Non-blocking OS lock
            if os.name == 'nt':
                self.file_handle.seek(0)
                msvcrt.locking(self.file_handle.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                fcntl.flock(self.file_handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)

            # Write current PID into lock file and pid file
            current_pid = os.getpid()
            self.file_handle.seek(0)
            self.file_handle.truncate()
            self.file_handle.write(str(current_pid))
            self.file_handle.flush()

            try:
                self.pid_file_path.write_text(str(current_pid), encoding="utf-8")
            except Exception:
                pass

            return True, current_pid, f"Lock acquired successfully by PID {current_pid}"

        except (IOError, OSError):
            # Lock is held by another running process
            if self.file_handle:
                try:
                    self.file_handle.close()
                except Exception:
                    pass
                self.file_handle = None

            # Read existing PID from pid_file_path safely
            active_pid = None
            if self.pid_file_path.exists():
                try:
                    content = self.pid_file_path.read_text(encoding="utf-8").strip()
                    if content:
                        active_pid = int(content)
                except Exception:
                    pass

            return False, active_pid, f"REJECTED: Another instance of AI-CONTROL-PLANE is already running (PID {active_pid or 'UNKNOWN'})."

    def release(self):
        if self.file_handle:
            try:
                if os.name == 'nt':
                    self.file_handle.seek(0)
                    msvcrt.locking(self.file_handle.fileno(), msvcrt.LK_UNLCK, 1)
                else:
                    fcntl.flock(self.file_handle.fileno(), fcntl.LOCK_UN)
                self.file_handle.close()
            except Exception:
                pass
            self.file_handle = None

        if self.pid_file_path.exists():
            try:
                self.pid_file_path.unlink(missing_ok=True)
            except Exception:
                pass
