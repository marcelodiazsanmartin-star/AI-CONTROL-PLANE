"""
Git Observer Module (Strict Read-Only)

Observes branch, local HEAD, status, and remote HEAD without modifying repository state.
Guarantees zero mutation of .git metadata or local worktree.
Strictly disallows fetch, pull, checkout, reset, clean, add, commit, gc, maintenance.
"""

import os
import subprocess
from pathlib import Path
from typing import Dict, Optional, Tuple, Any, List
from config import settings


class GitObserver:
    def __init__(self, timeout_seconds: float = 2.0):
        self.timeout_seconds = timeout_seconds

    def observe_repo(self, repo_path: Path) -> Dict[str, Any]:
        result = {
            "git_available": False,
            "branch": None,
            "local_head": None,
            "remote_head": None,
            "worktree_clean": True,
            "observer_errors": []
        }

        if not repo_path.exists() or not (repo_path / ".git").exists():
            result["observer_errors"].append("Directory or .git repository does not exist")
            return result

        try:
            # 1. Local Branch (rev-parse --abbrev-ref HEAD)
            branch = self._run_git(repo_path, ["rev-parse", "--abbrev-ref", "HEAD"])
            if branch:
                result["branch"] = branch.strip()

            # 2. Local HEAD commit hash (rev-parse HEAD)
            local_head = self._run_git(repo_path, ["rev-parse", "HEAD"])
            if local_head:
                result["local_head"] = local_head.strip()

            # 3. Worktree Cleanliness (status --porcelain) - purely read-only
            status = self._run_git(repo_path, ["status", "--porcelain"])
            if status is not None:
                result["worktree_clean"] = len(status.strip()) == 0

            # 4. Remote HEAD hash (ls-remote origin HEAD) - purely read-only remote query
            remote_head = self._run_git(repo_path, ["ls-remote", "origin", "HEAD"])
            if remote_head:
                parts = remote_head.strip().split()
                if parts:
                    result["remote_head"] = parts[0]
            else:
                result["observer_errors"].append("GitHub remote unreachable or ls-remote timed out (non-fatal)")

            result["git_available"] = True

        except Exception as e:
            result["observer_errors"].append(str(e))

        return result

    def _run_git(self, repo_path: Path, args: list) -> Optional[str]:
        # Enforce Read-Only Allowlist Guard
        subcmd = args[0] if args else ""
        if subcmd in settings.DISALLOWED_GIT_COMMANDS or subcmd not in settings.ALLOWED_GIT_COMMANDS:
            raise ValueError(f"SECURITY VIOLATION: Disallowed git command attempted: git {' '.join(args)}")

        try:
            env = os.environ.copy()
            env["GIT_TERMINAL_PROMPT"] = "0"
            env["GIT_SSH_COMMAND"] = "ssh -o BatchMode=yes"
            res = subprocess.run(
                ["git", "-C", str(repo_path)] + args,
                capture_output=True,
                text=True,
                env=env,
                timeout=self.timeout_seconds
            )
            if res.returncode == 0:
                return res.stdout.strip()
            return None
        except (subprocess.TimeoutExpired, FileNotFoundError, Exception):
            return None
