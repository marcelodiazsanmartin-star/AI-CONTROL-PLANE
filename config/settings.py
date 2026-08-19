"""
AI-CONTROL-PLANE Configuration & Safety Enforcement Module

CRITICAL CONSTRAINT:
Monitored projects are strictly OBSERVED ONLY.
"""

from pathlib import Path
from typing import Dict, Any, List, Set

# Mandatory Hardcoded Safety Permissions
CONTROL_PLANE_WRITE_PROJECTS: bool = False
CONTROL_PLANE_RESTART_PROJECTS: bool = False
CONTROL_PLANE_CHANGE_STRATEGY: bool = False
CONTROL_PLANE_ENABLE_REAL_MONEY: bool = False
CONTROL_PLANE_EXECUTE_PROJECT_CODE: bool = False

# CONTROL-02.5 Security Invariants
CONTROL_PLANE_ACCEPT_DIRECTIVES: bool = True
CONTROL_PLANE_VALIDATE_DIRECTIVES: bool = True
CONTROL_PLANE_QUEUE_DIRECTIVES: bool = True
CONTROL_PLANE_EXECUTE_MUTATING_DIRECTIVES: bool = False

# Read-Only Git Command Allowlist for Monitored Repos
ALLOWED_GIT_COMMANDS: List[str] = ["rev-parse", "branch", "status", "ls-remote", "show", "cat-file", "verify-commit", "merge-base"]
DISALLOWED_GIT_COMMANDS: List[str] = [
    "fetch", "pull", "checkout", "reset", "clean",
    "add", "commit", "gc", "maintenance"
]

# Continuous Observer & Remote Publication Settings
LOCAL_POLL_SECONDS: float = 5.0
DIRECTIVE_POLL_SECONDS: float = 5.0
REMOTE_CHECKPOINT_SECONDS: float = 300.0  # Time-based remote health checkpoint interval (5 mins)
REMOTE_PUBLISH_REPO_URL: str = "https://github.com/marcelodiazsanmartin-star/AI-CONTROL-PLANE.git"
REMOTE_PUBLISH_BRANCH: str = "main"

# Heartbeat & Freshness Thresholds (in seconds)
DEFAULT_HEARTBEAT_STALE_THRESHOLD_SECONDS: float = 300.0
GIT_TIMEOUT_SECONDS: float = 10.0
MAX_CLOCK_SKEW_SECONDS: float = 300.0

# Base Workspace Paths
WORKSPACE_ROOT = Path("c:/Users/VD/Desktop/Antigravity")
CONTROL_PLANE_ROOT = WORKSPACE_ROOT / "AI-CONTROL-PLANE"

# Directive Channel Source & Action Rules
APPROVED_SOURCE_REPOSITORY: str = "AI-CONTROL-PLANE"
APPROVED_SOURCE_BRANCH: str = "main"

# Cryptographic Commit Signer Allowlist (Production Invariant: ONLY Valid Verified Key Fingerprints / Hashes)
PRODUCTION_TRUSTED_SIGNER_ALLOWLIST: Set[str] = {
    "SHA256:zYZi3+VxKz9ve+PJgTS2o8q+dvXSmzCwPZ2G3NYh41A"
}

# Runtime allowlist (Initialized from production allowlist; test fixtures inject ephemeral test keys via isolated config)
TRUSTED_SIGNER_ALLOWLIST: Set[str] = set(PRODUCTION_TRUSTED_SIGNER_ALLOWLIST)
REQUIRE_COMMIT_SIGNATURE_VERIFICATION: bool = True

ALLOWED_ACTION_CLASSES: Set[str] = {
    "STATUS_REQUEST",
    "AUDIT_REQUEST",
    "READ_ONLY_ANALYSIS",
    "GENERATE_REPORT",
    "RUN_CONTROL_PLANE_TESTS",
    "RUN_READ_ONLY_OBSERVATION",
    "PREPARE_NEXT_STAGE",
    "NO_OP"
}

PROHIBITED_MUTATING_ACTIONS: Set[str] = {
    "RESTART_PROJECT",
    "STOP_PROJECT",
    "KILL_PROCESS",
    "MODIFY_STRATEGY",
    "CHANGE_PARAMETERS",
    "WRITE_TO_ORACLE",
    "WRITE_TO_MICRO",
    "DELETE_DATA",
    "RESET_GIT",
    "CHECKOUT_PROJECT_BRANCH",
    "ENABLE_REAL_MONEY",
    "SEND_ORDER",
    "EXECUTE_TRADE",
    "MODIFY_CREDENTIALS"
}

ACTIONS_REQUIRING_HUMAN_APPROVAL: Set[str] = {
    "REAL_MONEY_ENABLE",
    "CREDENTIAL_CHANGE",
    "DESTRUCTIVE_OPERATION",
    "STRATEGY_CHANGE",
    "HIGH_RISK_ARCHITECTURE_CHANGE"
}

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
