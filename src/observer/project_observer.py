"""
Project Observer Engine (Read-Only)

Combines Git, Process, and File Evidence collection into raw observed project snapshots.
Separates PROCESS_EXPECTATION from PROCESS_OBSERVATION.
"""

from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Any
from src.observer.git_observer import GitObserver
from src.observer.process_observer import ProcessObserver
from src.observer.evidence_collector import EvidenceCollector


class ProjectObserver:
    def __init__(
        self,
        git_observer: Optional[GitObserver] = None,
        process_observer: Optional[ProcessObserver] = None,
        evidence_collector: Optional[EvidenceCollector] = None
    ):
        self.git_observer = git_observer or GitObserver()
        self.process_observer = process_observer or ProcessObserver()
        self.evidence_collector = evidence_collector or EvidenceCollector()

    def observe(self, project_config: Dict[str, Any]) -> Dict[str, Any]:
        project_name = project_config["name"]
        root_path = Path(project_config["root_path"])
        expected_processes = project_config.get("expected_process_names", [])
        state_files = project_config.get("state_files", [])
        
        # Requirement #2: PROCESS_EXPECTATION derived independently of process execution state
        proc_expected = project_config.get("default_process_expected", False)

        observer_errors = []

        # 1. Git metadata (queries exact refs/heads/<branch>)
        git_info = self.git_observer.observe_repo(root_path)
        if git_info.get("observer_errors"):
            observer_errors.extend(git_info["observer_errors"])

        # 2. Process metadata (derived ONLY from OS process observation)
        proc_running, proc_matched, proc_pid = self.process_observer.check_process_running(expected_processes)
        
        # Detect unexpected process execution (expected FALSE + running TRUE)
        unexpected_proc = (not proc_expected) and proc_running

        # 3. Evidence files
        evidence_map = self.evidence_collector.collect_project_evidence(root_path, state_files)

        # 4. External project activity detection
        external_activity = proc_running or any(
            item.file_exists and item.age_seconds is not None and item.age_seconds < 60.0
            for item in evidence_map.values()
        )

        return {
            "project": project_name,
            "root_path": str(root_path),
            "git_info": git_info,
            "process_expected": proc_expected,
            "process_running": proc_running,
            "unexpected_process": unexpected_proc,
            "matched_process_name": proc_matched,
            "process_pid": proc_pid,
            "evidence_map": evidence_map,
            "observer_errors": observer_errors,
            "external_project_activity_detected": external_activity
        }
