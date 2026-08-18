"""
Project Observer Engine (Read-Only)

Combines Git, Process, and File Evidence collection into raw observed project snapshots.
Classifies live external activity and respects context-aware process expectation policies.
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
        default_proc_expected = project_config.get("default_process_expected", False)

        observer_errors = []

        # 1. Git metadata
        git_info = self.git_observer.observe_repo(root_path)
        if git_info.get("observer_errors"):
            observer_errors.extend(git_info["observer_errors"])

        # 2. Process metadata
        proc_running, proc_matched, proc_pid = self.process_observer.check_process_running(expected_processes)
        
        # Context-aware process expectation derivation:
        # If default is configured False (e.g. audit phase or soak complete), process_expected is False
        # unless process is actively running or explicitly flagged.
        proc_expected = default_proc_expected or proc_running

        # 3. Evidence files
        evidence_map = self.evidence_collector.collect_project_evidence(root_path, state_files)

        # 4. External project activity detection:
        # If any evidence file was modified recently (e.g. within 60s) or process is running,
        # external activity is detected from the project's own processes.
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
            "matched_process_name": proc_matched,
            "process_pid": proc_pid,
            "evidence_map": evidence_map,
            "observer_errors": observer_errors,
            "external_project_activity_detected": external_activity
        }
