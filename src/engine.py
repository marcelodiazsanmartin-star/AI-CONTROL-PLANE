"""
Control Plane Engine

Orchestrates observations across registered projects, evaluates state machines using
5-Tier Evidence Precedence and Remote Verification Triples, manages Control Plane self-health,
polls directive channel inbox (CONTROL-02.5), writes output state JSONs, and handles
low-frequency event-driven remote status publication.
"""

import json
import os
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, Optional

from config import settings
from src.contracts import NormalizedProjectState
from src.observer.project_observer import ProjectObserver
from src.state_machine.evaluator import StateEvaluator
from src.audit.audit_logger import AuditLogger
from src.directive.watcher import DirectiveWatcher


class ControlPlaneEngine:
    def __init__(
        self,
        output_dir: Optional[Path] = None,
        audit_file: Optional[Path] = None,
        project_observer: Optional[ProjectObserver] = None,
        evaluator: Optional[StateEvaluator] = None,
        directive_watcher: Optional[DirectiveWatcher] = None
    ):
        self.output_dir = output_dir or (settings.CONTROL_PLANE_ROOT / "state")
        self.audit_file = audit_file or (settings.CONTROL_PLANE_ROOT / "audit" / "events.jsonl")
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.audit_file.parent.mkdir(parents=True, exist_ok=True)

        self.project_observer = project_observer or ProjectObserver()
        self.evaluator = evaluator or StateEvaluator()
        self.audit_logger = AuditLogger(self.audit_file)
        self.directive_watcher = directive_watcher or DirectiveWatcher()

        self.started_at = datetime.now(timezone.utc).isoformat()
        self.sweep_count = 0
        self.last_states: Dict[str, str] = {}
        self.last_error: Optional[str] = None
        self.last_remote_publish_timestamp: Optional[datetime] = None

    def update_self_health(self, status_str: str = "RUNNING"):
        health_data = {
            "status": status_str,
            "pid": os.getpid(),
            "started_at": self.started_at,
            "last_heartbeat": datetime.now(timezone.utc).isoformat(),
            "last_successful_sweep": datetime.now(timezone.utc).isoformat(),
            "last_error": self.last_error,
            "sweep_count": self.sweep_count,
            "observer_version": "1.0.0"
        }

        health_file = self.output_dir / "control_plane_status.json"
        with open(health_file, "w", encoding="utf-8") as f:
            json.dump(health_data, f, indent=2)

    def run_sweep(self) -> Dict[str, NormalizedProjectState]:
        self.sweep_count += 1
        now_dt = datetime.now(timezone.utc)
        states: Dict[str, NormalizedProjectState] = {}
        project_results_dict: Dict[str, Any] = {}
        state_transition_occurred = False

        # 0. CONTROL-02.5 Directive Channel Inbox Poll
        try:
            self.directive_watcher.poll_inbox()
        except Exception as e:
            self.last_error = f"Directive watcher inbox poll error: {str(e)}"

        for proj_key, proj_cfg in settings.REGISTERED_PROJECTS.items():
            # 1. Gather raw observation data
            raw_obs = self.project_observer.observe(proj_cfg)

            # 2. Evaluate canonical state & detect contradictions using project-specific thresholds
            stale_thresh = proj_cfg.get("heartbeat_stale_threshold", settings.DEFAULT_HEARTBEAT_STALE_THRESHOLD_SECONDS)
            proj_evaluator = StateEvaluator(heartbeat_stale_threshold_seconds=stale_thresh)
            norm_state = proj_evaluator.evaluate(raw_obs)

            # Detect state transition (state change into any canonical state)
            current_status = norm_state.status.value if hasattr(norm_state.status, "value") else str(norm_state.status)
            prev_status = self.last_states.get(proj_key)
            if prev_status is not None and prev_status != current_status:
                state_transition_occurred = True

            self.last_states[proj_key] = current_status

            states[proj_key] = norm_state
            proj_dict = norm_state.to_dict()
            project_results_dict[proj_key] = proj_dict

            # 3. Write individual local state file (state/oracle.json, state/micro.json)
            file_id = proj_cfg.get("id", proj_key.lower())
            proj_state_path = self.output_dir / f"{file_id}.json"
            with open(proj_state_path, "w", encoding="utf-8") as f:
                json.dump(proj_dict, f, indent=2)

            # 4. Record audit event
            self.audit_logger.log_observation_event(norm_state, previous_status=prev_status)

        # 5. Determine overall health status
        has_blocked = any(s.status == "BLOCKED" for s in states.values())
        has_stale = any(s.status == "STALE" for s in states.values())

        if has_blocked:
            overall_health = "BLOCKED"
        elif has_stale:
            overall_health = "DEGRADED_STALE"
        else:
            overall_health = "STABLE"

        # 6. Build & Write global_status.json
        global_status_data = {
            "control_plane": {
                "version": "1.0.0",
                "permissions": {
                    "CONTROL_PLANE_WRITE_PROJECTS": settings.CONTROL_PLANE_WRITE_PROJECTS,
                    "CONTROL_PLANE_RESTART_PROJECTS": settings.CONTROL_PLANE_RESTART_PROJECTS,
                    "CONTROL_PLANE_CHANGE_STRATEGY": settings.CONTROL_PLANE_CHANGE_STRATEGY,
                    "CONTROL_PLANE_ENABLE_REAL_MONEY": settings.CONTROL_PLANE_ENABLE_REAL_MONEY,
                    "CONTROL_PLANE_EXECUTE_PROJECT_CODE": settings.CONTROL_PLANE_EXECUTE_PROJECT_CODE,
                    "CONTROL_PLANE_ACCEPT_DIRECTIVES": settings.CONTROL_PLANE_ACCEPT_DIRECTIVES,
                    "CONTROL_PLANE_VALIDATE_DIRECTIVES": settings.CONTROL_PLANE_VALIDATE_DIRECTIVES,
                    "CONTROL_PLANE_QUEUE_DIRECTIVES": settings.CONTROL_PLANE_QUEUE_DIRECTIVES,
                    "CONTROL_PLANE_EXECUTE_MUTATING_DIRECTIVES": settings.CONTROL_PLANE_EXECUTE_MUTATING_DIRECTIVES
                },
                "allowed_git_commands": settings.ALLOWED_GIT_COMMANDS,
                "disallowed_git_commands": settings.DISALLOWED_GIT_COMMANDS,
                "observed_at": now_dt.isoformat(),
                "total_projects_monitored": len(states),
                "overall_health": overall_health
            },
            "projects": project_results_dict
        }

        global_status_path = self.output_dir / "global_status.json"
        with open(global_status_path, "w", encoding="utf-8") as f:
            json.dump(global_status_data, f, indent=2)

        # 7. Update Control Plane Self Health
        self.update_self_health(status_str="RUNNING")

        # 8. Event-driven Remote Publication Debouncing
        checkpoint_due = (
            self.last_remote_publish_timestamp is None or
            (now_dt - self.last_remote_publish_timestamp).total_seconds() >= settings.REMOTE_CHECKPOINT_SECONDS
        )

        if state_transition_occurred or checkpoint_due:
            if self.publish_remote_status():
                self.last_remote_publish_timestamp = now_dt

        return states

    def publish_remote_status(self) -> bool:
        """
        Publishes updated Control Plane state to AI-CONTROL-PLANE repository ONLY.
        Monitored repositories remain strictly untouched.
        """
        cp_root = settings.CONTROL_PLANE_ROOT
        if not (cp_root / ".git").exists():
            return False

        try:
            # Stage only control plane state, directives, audit, and reports
            subprocess.run(
                ["git", "add", "state/", "directives/", "audit/", "reports/"],
                cwd=str(cp_root),
                capture_output=True,
                text=True,
                check=False
            )

            status_res = subprocess.run(
                ["git", "status", "--porcelain"],
                cwd=str(cp_root),
                capture_output=True,
                text=True,
                check=False
            )

            if status_res.stdout.strip():
                msg = f"chore(control-plane): state publication sweep #{self.sweep_count}"
                subprocess.run(
                    ["git", "commit", "-m", msg],
                    cwd=str(cp_root),
                    capture_output=True,
                    text=True,
                    check=False
                )

                push_res = subprocess.run(
                    ["git", "push", "origin", settings.REMOTE_PUBLISH_BRANCH],
                    cwd=str(cp_root),
                    capture_output=True,
                    text=True,
                    timeout=10.0,
                    check=False
                )
                return push_res.returncode == 0
            return True
        except Exception as e:
            self.last_error = f"Remote publication failed: {str(e)}"
            return False
