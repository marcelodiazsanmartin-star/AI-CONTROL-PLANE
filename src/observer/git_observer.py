"""
Git Observer Module (Strict Read-Only)

Observes branch, local HEAD, status, and remote branch HEAD without modifying repository state.
Guarantees zero mutation of .git metadata or local worktree by enforcing GIT_OPTIONAL_LOCKS=0.
Disallows fetch, pull, checkout, reset, clean, add, commit, gc, maintenance.
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
            "remote_branch_exists": False,
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
                branch_clean = branch.strip()
                result["branch"] = branch_clean

                # 2. Local HEAD commit hash (rev-parse HEAD)
                local_head = self._run_git(repo_path, ["rev-parse", "HEAD"])
                if local_head:
                    result["local_head"] = local_head.strip()

                # 3. Worktree Cleanliness (status --porcelain)
                status = self._run_git(repo_path, ["status", "--porcelain"])
                if status is not None:
                    result["worktree_clean"] = len(status.strip()) == 0

                # 4. Exact Remote Branch HEAD query (ls-remote --heads origin refs/heads/<branch>)
                # Requirement: Do NOT use ls-remote origin HEAD (default branch HEAD).
                ref_spec = f"refs/heads/{branch_clean}"
                remote_out = self._run_git(repo_path, ["ls-remote", "--heads", "origin", ref_spec])
                if remote_out:
                    # Output line format: "<hash>\trefs/heads/<branch>"
                    lines = remote_out.strip().splitlines()
                    for line in lines:
                        parts = line.split()
                        if len(parts) >= 2 and parts[1] == ref_spec:
                            result["remote_head"] = parts[0]
                            result["remote_branch_exists"] = True
                            break

                if not result["remote_branch_exists"]:
                    result["observer_errors"].append(
                        f"Remote branch {ref_spec} not found or origin unreachable (non-fatal)"
                    )

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
            # Requirement #4: Harden True Read-Only Git environment
            env["GIT_OPTIONAL_LOCKS"] = "0"
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
