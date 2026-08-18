"""
Git Observer Module (Strict Read-Only)

Observes branch, local HEAD, status, and exact remote branch HEAD without modifying repository state.
Guarantees zero mutation of .git metadata or local worktree by enforcing GIT_OPTIONAL_LOCKS=0 and GIT_TERMINAL_PROMPT=0.
Returns structured diagnostics for remote branch verification.
"""

import os
import subprocess
from pathlib import Path
from typing import Dict, Optional, Tuple, Any, List
from config import settings


class GitObserver:
    def __init__(self, timeout_seconds: float = 10.0):
        self.timeout_seconds = timeout_seconds

    def observe_repo(self, repo_path: Path) -> Dict[str, Any]:
        result = {
            "git_available": False,
            "branch": None,
            "local_head": None,
            "remote_head": None,
            "remote_branch_exists": False,
            "worktree_clean": True,
            "remote_query_command": None,
            "remote_query_ref": None,
            "remote_query_returncode": None,
            "remote_query_timeout": False,
            "remote_query_stderr_category": "UNKNOWN",
            "observer_errors": []
        }

        if not repo_path.exists() or not (repo_path / ".git").exists():
            result["observer_errors"].append("Directory or .git repository does not exist")
            return result

        try:
            # 1. Local Branch (rev-parse --abbrev-ref HEAD)
            branch = self._run_git(repo_path, ["rev-parse", "--abbrev-ref", "HEAD"])

            if branch and branch.get("stdout"):
                branch_clean = branch["stdout"].strip()
                result["branch"] = branch_clean

                # 2. Local HEAD commit hash (rev-parse HEAD)
                local_head = self._run_git(repo_path, ["rev-parse", "HEAD"])
                if local_head and local_head.get("stdout"):
                    result["local_head"] = local_head["stdout"].strip()

                # 3. Worktree Cleanliness (status --porcelain)
                status = self._run_git(repo_path, ["status", "--porcelain"])
                if status and status.get("stdout") is not None:
                    result["worktree_clean"] = len(status["stdout"].strip()) == 0

                # 4. Exact Remote Branch HEAD query (ls-remote --heads origin refs/heads/<branch>)
                ref_spec = f"refs/heads/{branch_clean}"
                cmd_args = ["ls-remote", "--heads", "origin", ref_spec]
                result["remote_query_command"] = f"git -C {repo_path} {' '.join(cmd_args)}"
                result["remote_query_ref"] = ref_spec

                remote_res = self._run_git(repo_path, cmd_args, timeout=self.timeout_seconds)
                result["remote_query_returncode"] = remote_res.get("returncode")
                result["remote_query_timeout"] = remote_res.get("timeout", False)

                stdout_text = remote_res.get("stdout", "") or ""
                stderr_text = remote_res.get("stderr", "") or ""

                if remote_res.get("timeout"):
                    result["remote_query_stderr_category"] = "TIMEOUT"
                    result["observer_errors"].append(f"Remote query for {ref_spec} timed out ({self.timeout_seconds}s)")

                elif remote_res.get("returncode") != 0:
                    if "Authentication failed" in stderr_text or "Permission denied" in stderr_text:
                        result["remote_query_stderr_category"] = "AUTH_FAILURE"
                    elif "Could not resolve host" in stderr_text or "Failed to connect" in stderr_text:
                        result["remote_query_stderr_category"] = "NETWORK_FAILURE"
                    else:
                        result["remote_query_stderr_category"] = "GIT_FAILURE"
                    result["observer_errors"].append(f"Remote query failed: {stderr_text.strip()}")

                else:
                    # Returncode 0
                    if stdout_text.strip():
                        lines = stdout_text.strip().splitlines()
                        for line in lines:
                            parts = line.split()
                            if len(parts) >= 2 and parts[1] == ref_spec:
                                result["remote_head"] = parts[0]
                                result["remote_branch_exists"] = True
                                result["remote_query_stderr_category"] = "VERIFIED"
                                break

                    if not result["remote_branch_exists"]:
                        result["remote_query_stderr_category"] = "BRANCH_NOT_FOUND"
                        result["observer_errors"].append(f"Remote branch {ref_spec} not found on origin")

            result["git_available"] = True

        except Exception as e:
            result["observer_errors"].append(str(e))
            result["remote_query_stderr_category"] = "GIT_FAILURE"

        return result

    def _run_git(self, repo_path: Path, args: list, timeout: Optional[float] = None) -> Dict[str, Any]:
        subcmd = args[0] if args else ""
        if subcmd in settings.DISALLOWED_GIT_COMMANDS or subcmd not in settings.ALLOWED_GIT_COMMANDS:
            raise ValueError(f"SECURITY VIOLATION: Disallowed git command attempted: git {' '.join(args)}")

        to_use = timeout or self.timeout_seconds
        try:
            env = os.environ.copy()
            # Requirement #1 & #4: Strict read-only environment variables
            env["GIT_OPTIONAL_LOCKS"] = "0"
            env["GIT_TERMINAL_PROMPT"] = "0"
            env["GIT_SSH_COMMAND"] = "ssh -o BatchMode=yes"
            res = subprocess.run(
                ["git", "-C", str(repo_path)] + args,
                capture_output=True,
                text=True,
                env=env,
                timeout=to_use
            )
            return {
                "returncode": res.returncode,
                "stdout": res.stdout,
                "stderr": res.stderr,
                "timeout": False
            }
        except subprocess.TimeoutExpired as te:
            return {
                "returncode": -1,
                "stdout": te.stdout or "",
                "stderr": "Subprocess timeout expired",
                "timeout": True
            }
        except Exception as e:
            return {
                "returncode": -1,
                "stdout": "",
                "stderr": str(e),
                "timeout": False
            }
