"""
Directive Source Authenticator, Expiration Checker, and Human Gate Evaluator

Verifies source repository, approved branch, remote commit existence, action permissions,
clock skew, and human approval gates.
"""

import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Tuple, Optional, Any, Dict
from config import settings
from src.directive.contracts import Directive, ValidationStatus


def parse_iso(ts_str: str) -> Optional[datetime]:
    if not ts_str:
        return None
    try:
        clean = ts_str.replace("Z", "+00:00")
        dt = datetime.fromisoformat(clean)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except Exception:
        return None


class DirectiveAuthenticator:
    def __init__(
        self,
        repo_root: Optional[Path] = None,
        max_clock_skew_seconds: float = settings.MAX_CLOCK_SKEW_SECONDS,
        reference_time: Optional[datetime] = None
    ):
        self.repo_root = repo_root or settings.CONTROL_PLANE_ROOT
        self.max_clock_skew_seconds = max_clock_skew_seconds
        self.reference_time = reference_time

    def get_current_time(self) -> datetime:
        return self.reference_time or datetime.now(timezone.utc)

    def authenticate(self, directive: Directive, directive_file_path: Optional[Path] = None) -> Tuple[ValidationStatus, str, bool]:
        """
        Authenticates directive and evaluates validity.
        Returns (status: ValidationStatus, reason: str, requires_human_wait: bool)
        """
        now_dt = self.get_current_time()

        # 1. Source Repository Verification
        if directive.source_repository != settings.APPROVED_SOURCE_REPOSITORY:
            return ValidationStatus.INVALID_SOURCE, f"INVALID_SOURCE: Repository '{directive.source_repository}' is not approved", False

        # 2. Approved Branch Verification
        if directive.source_branch != settings.APPROVED_SOURCE_BRANCH:
            return ValidationStatus.NOT_IN_APPROVED_BRANCH, f"NOT_IN_APPROVED_BRANCH: Branch '{directive.source_branch}' is not approved", False

        # 3. Source Commit SHA existence in Git history
        commit_sha = directive.source_commit_sha
        if not commit_sha or commit_sha == "UNKNOWN_SHA":
            return ValidationStatus.COMMIT_NOT_FOUND, "COMMIT_NOT_FOUND: source_commit_sha is missing or invalid", False

        # Check commit existence in git repo
        if (self.repo_root / ".git").exists():
            try:
                res = subprocess.run(
                    ["git", "-C", str(self.repo_root), "cat-file", "-e", f"{commit_sha}^{{commit}}"],
                    capture_output=True,
                    text=True,
                    timeout=5.0
                )
                if res.returncode != 0:
                    return ValidationStatus.COMMIT_NOT_FOUND, f"COMMIT_NOT_FOUND: Commit {commit_sha[:7]} does not exist in repository", False
            except Exception as e:
                return ValidationStatus.FAIL_CLOSED_GITHUB_UNAVAILABLE, f"FAIL_CLOSED: Git repository check failed: {str(e)}", False

        # 4. Clock Skew & Expiration Checks
        created_dt = parse_iso(directive.created_at)
        expires_dt = parse_iso(directive.expires_at)

        if not created_dt or not expires_dt:
            return ValidationStatus.SCHEMA_INVALID, "SCHEMA_INVALID: Invalid created_at or expires_at ISO timestamp", False

        # Future Clock Skew
        future_skew = (created_dt - now_dt).total_seconds()
        if future_skew > self.max_clock_skew_seconds:
            return ValidationStatus.CLOCK_SKEW_EXCEEDED, f"CLOCK_SKEW_EXCEEDED: Directive created_at is {future_skew:.1f}s in future (max allowed {self.max_clock_skew_seconds}s)", False

        # Expiration Check
        if now_dt > expires_dt:
            return ValidationStatus.EXPIRED, f"EXPIRED: Directive expired at {directive.expires_at}", False

        # 5. Allowed Action & Mutating Action Verification
        action_type = directive.action_type.upper()
        if action_type in settings.PROHIBITED_MUTATING_ACTIONS:
            return ValidationStatus.ACTION_NOT_ALLOWED, f"ACTION_NOT_ALLOWED: Prohibited mutating action '{action_type}' rejected in CONTROL-02.5", False

        if action_type not in settings.ALLOWED_ACTION_CLASSES and action_type not in settings.ACTIONS_REQUIRING_HUMAN_APPROVAL:
            return ValidationStatus.ACTION_NOT_ALLOWED, f"ACTION_NOT_ALLOWED: Unknown or unauthorized action_type '{action_type}'", False

        # 6. Human Approval Gate Evaluation
        requires_human = (
            directive.requires_human_approval or
            action_type in settings.ACTIONS_REQUIRING_HUMAN_APPROVAL
        )

        if requires_human:
            return ValidationStatus.AUTHENTIC, f"WAITING_HUMAN: Directive requires human approval for action '{action_type}'", True

        return ValidationStatus.AUTHENTIC, "AUTHENTIC: Directive source authenticated and validated successfully", False
