"""
Process Observer Module (Read-Only)

Inspects system processes to detect if expected project scripts/watchers are running.
Does not start, stop, kill, or modify any process.
Provides empirical OS process table counting for AI-CONTROL-PLANE persistent daemons.
"""

import json
import os
import subprocess
from typing import Dict, List, Optional, Any, Tuple


class ProcessObserver:
    def __init__(self, process_provider: Optional[Any] = None):
        """
        :param process_provider: Optional callable that returns a list of dicts:
                                  [{"ProcessId": 123, "CommandLine": "python live_test.py"}]
                                  Used for dependency injection in unit tests.
        """
        self.process_provider = process_provider

    def get_running_processes(self) -> List[Dict[str, Any]]:
        if self.process_provider is not None:
            return self.process_provider()

        processes = []
        try:
            if os.name == 'nt':
                res = subprocess.run(
                    ['powershell', '-Command',
                     'Get-CimInstance Win32_Process | Select-Object ProcessId, CommandLine | ConvertTo-Json -Depth 2'],
                    capture_output=True,
                    text=True,
                    timeout=10.0
                )
                if res.returncode == 0 and res.stdout.strip():
                    raw = json.loads(res.stdout.strip())
                    if isinstance(raw, list):
                        processes = raw
                    elif isinstance(raw, dict):
                        processes = [raw]
            else:
                res = subprocess.run(
                    ['ps', '-eo', 'pid,command'],
                    capture_output=True,
                    text=True,
                    timeout=5.0
                )
                if res.returncode == 0:
                    for line in res.stdout.splitlines()[1:]:
                        parts = line.strip().split(maxsplit=1)
                        if len(parts) == 2:
                            processes.append({"ProcessId": int(parts[0]), "CommandLine": parts[1]})
        except Exception:
            pass

        return processes

    def check_process_running(self, expected_names: List[str]) -> Tuple[bool, Optional[str], Optional[int]]:
        """
        Checks if any process matching expected_names is currently running.
        Returns (is_running, matched_name, process_id)
        """
        if not expected_names:
            return False, None, None

        procs = self.get_running_processes()
        for proc in procs:
            cmdline = proc.get("CommandLine") or ""
            pid = proc.get("ProcessId")
            for expected in expected_names:
                if expected.lower() in cmdline.lower():
                    return True, expected, pid

        return False, None, None

    def get_active_control_plane_processes(self) -> Tuple[int, List[int]]:
        """
        Requirement 2: Empirically inspects OS process table for active persistent AI-CONTROL-PLANE main.py processes.
        Excludes:
        - temporary pytest child processes
        - --once certification sweeps
        - unrelated Python processes
        - ORACLE processes
        - MICRO processes
        Returns (count: int, pids: List[int])
        """
        procs = self.get_running_processes()
        active_pids = []

        for proc in procs:
            cmdline = proc.get("CommandLine") or ""
            pid = proc.get("ProcessId")
            cmd_lower = cmdline.lower()

            if "main.py" in cmd_lower and "ai-control-plane" in cmd_lower:
                if "--once" not in cmd_lower and "pytest" not in cmd_lower:
                    if pid and pid not in active_pids:
                        active_pids.append(int(pid))

        return len(active_pids), active_pids
