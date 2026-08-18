"""
AI-CONTROL-PLANE Configuration & Safety Enforcement Module

CRITICAL CONSTRAINT:
Monitored projects are strictly OBSERVED ONLY.
"""

from pathlib import Path
from typing import Dict, Any, List

# Mandatory Hardcoded Safety Permissions
CONTROL_PLANE_WRITE_PROJECTS: bool = False
CONTROL_PLANE_RESTART_PROJECTS: bool = False
CONTROL_PLANE_CHANGE_STRATEGY: bool = False
CONTROL_PLANE_ENABLE_REAL_MONEY: bool = False
CONTROL_PLANE_EXECUTE_PROJECT_CODE: bool = False

# Read-Only Git Command Allowlist for Monitored Repos
ALLOWED_GIT_COMMANDS: List[str] = ["rev-parse", "branch", "status", "ls-remote"]
DISALLOWED_GIT_COMMANDS: List[str] = [
    "fetch", "pull", "checkout", "reset", "clean",
    "add", "commit", "gc", "maintenance"
]

# Continuous Observer & Remote Publication Settings
LOCAL_POLL_SECONDS: float = 5.0
REMOTE_CHECKPOINT_SECONDS: float = 300.0  # Time-based remote health checkpoint interval (5 mins)
REMOTE_PUBLISH_REPO_URL: str = "https://github.com/marcelodiazsanmartin-star/AI-CONTROL-PLANE.git"
REMOTE_PUBLISH_BRANCH: str = "main"

# Heartbeat & Freshness Thresholds (in seconds)
DEFAULT_HEARTBEAT_STALE_THRESHOLD_SECONDS: float = 300.0
GIT_TIMEOUT_SECONDS: float = 2.0

# Base Workspace Paths
WORKSPACE_ROOT = Path("c:/Users/VD/Desktop/Antigravity")
CONTROL_PLANE_ROOT = WORKSPACE_ROOT / "AI-CONTROL-PLANE"

# Monitored Project Registry & Lifecycle Expectations
REGISTERED_PROJECTS: Dict[str, Dict[str, Any]] = {
    "ORACLE-AI": {
        "id": "oracle",
        "name": "ORACLE-AI",
        "root_path": WORKSPACE_ROOT / "Oracle",
        "expected_process_names": [
            "download_and_unify_real_data.py",
            "live_test.py",
            "server.py"
        ],
        "default_process_expected": False,  # Soak complete (READY_FOR_REVIEW)
        "heartbeat_stale_threshold": 3600.0,
        "state_files": [
            "sprints/AGENT_STATUS.json",
            "sprints/ACTIVE_SPRINT.md",
            "environment_validation_report.md"
        ]
    },
    "MICRO-MARKET-ORACLE": {
        "id": "micro",
        "name": "MICRO-MARKET-ORACLE",
        "root_path": WORKSPACE_ROOT / "MICRO-MARKET-ORACLE",
        "expected_process_names": [
            "antigravity_watcher",
            "watcher",
            "run_watcher.py"
        ],
        "default_process_expected": True,  # Watcher actively expected during stage observation
        "heartbeat_stale_threshold": 300.0,
        "state_files": [
            "control/CURRENT_STAGE.json",
            "control/PROJECT_STATE.json",
            "control/WATCHER_STATE.json"
        ]
    }
}
