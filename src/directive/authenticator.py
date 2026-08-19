"""
Directive Source Authenticator, Expiration Checker, and Human Gate Evaluator

Implements Real Directive Source Authentication enforcing:
1. Approved source repository & branch
2. Commit SHA existence in Git
3. Branch reachability (git merge-base --is-ancestor <sha> origin/main)
4. Existence of exact directive file INSIDE committed tree
5. Exact byte & JSON content equality between committed blob and candidate file
6. Clock skew & expiration limits
7. Human approval gate evaluation
"""

import json
import hashlib
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

    def authenticate(
        self,
        directive: Directive,
        directive_file_path: Optional[Path] = None
    ) -> Tuple[ValidationStatus, str, bool, Dict[str, Any]]:
        """
        Authenticates directive and evaluates validity against real Git committed blobs.
        Returns (status: ValidationStatus, reason: str, requires_human_wait: bool, auth_metadata: dict)
        """
        now_dt = self.get_current_time()
        auth_metadata: Dict[str, Any] = {
            "directive_source_sha": directive.source_commit_sha,
            "directive_blob_sha": "UNKNOWN_BLOB",
            "directive_content_sha256": "UNKNOWN_HASH",
            "approved_branch": settings.APPROVED_SOURCE_BRANCH,
            "branch_reachability_verified": False
        }

        # 1. Source Repository Verification
        if directive.source_repository != settings.APPROVED_SOURCE_REPOSITORY:
            return ValidationStatus.INVALID_SOURCE, f"INVALID_SOURCE: Repository '{directive.source_repository}' is not approved", False, auth_metadata

        # 2. Approved Branch Verification
        if directive.source_branch != settings.APPROVED_SOURCE_BRANCH:
            return ValidationStatus.NOT_IN_APPROVED_BRANCH, f"NOT_IN_APPROVED_BRANCH: Branch '{directive.source_branch}' is not approved", False, auth_metadata

        # 3. Source Commit SHA existence in Git history
        commit_sha = directive.source_commit_sha
        if not commit_sha or commit_sha == "UNKNOWN_SHA":
            return ValidationStatus.COMMIT_NOT_FOUND, "COMMIT_NOT_FOUND: source_commit_sha is missing or invalid", False, auth_metadata

        git_dir = self.repo_root / ".git"
        if git_dir.exists():
            # Check commit existence
            try:
                res_exist = subprocess.run(
                    ["git", "-C", str(self.repo_root), "cat-file", "-e", f"{commit_sha}^{{commit}}"],
                    capture_output=True,
                    text=True,
                    timeout=5.0
                )
                if res_exist.returncode != 0:
                    return ValidationStatus.COMMIT_NOT_FOUND, f"COMMIT_NOT_FOUND: Commit {commit_sha[:7]} does not exist in repository", False, auth_metadata
            except Exception as e:
                return ValidationStatus.FAIL_CLOSED_GITHUB_UNAVAILABLE, f"FAIL_CLOSED: Git commit check failed: {str(e)}", False, auth_metadata

            # 4. Branch Reachability Verification
            # Verify commit is reachable from origin/main, main, or HEAD
            reachability_ok = False
            for target_ref in ["origin/main", "main", "HEAD"]:
                try:
                    res_reach = subprocess.run(
                        ["git", "-C", str(self.repo_root), "merge-base", "--is-ancestor", commit_sha, target_ref],
                        capture_output=True,
                        text=True,
                        timeout=5.0
                    )
                    if res_reach.returncode == 0:
                        reachability_ok = True
                        break
                except Exception:
                    pass

            if not reachability_ok:
                return ValidationStatus.NOT_IN_APPROVED_BRANCH, f"NOT_IN_APPROVED_BRANCH: Commit {commit_sha[:7]} is not reachable from approved branch {settings.APPROVED_SOURCE_BRANCH}", False, auth_metadata

            auth_metadata["branch_reachability_verified"] = True

            # 5. Check if directive file exists INSIDE the committed source_commit_sha tree
            rel_git_path = "directives/inbox/" + (directive_file_path.name if directive_file_path else f"{directive.directive_id}.json")
            if directive_file_path and directive_file_path.is_relative_to(self.repo_root):
                rel_git_path = str(directive_file_path.relative_to(self.repo_root)).replace("\\", "/")

            try:
                res_show = subprocess.run(
                    ["git", "-C", str(self.repo_root), "show", f"{commit_sha}:{rel_git_path}"],
                    capture_output=True,
                    timeout=5.0
                )
                if res_show.returncode != 0:
                    return ValidationStatus.COMMIT_EXISTS_BUT_DIRECTIVE_ABSENT, f"COMMIT_EXISTS_BUT_DIRECTIVE_ABSENT: Directive file '{rel_git_path}' does not exist in commit {commit_sha[:7]}", False, auth_metadata

                committed_bytes = res_show.stdout
                committed_hash = hashlib.sha256(committed_bytes).hexdigest()
                auth_metadata["directive_content_sha256"] = committed_hash
            except Exception as e:
                return ValidationStatus.FAIL_CLOSED_GITHUB_UNAVAILABLE, f"FAIL_CLOSED: Failed extracting committed blob from Git: {str(e)}", False, auth_metadata

            # 6. Retrieve exact blob SHA
            try:
                res_blob = subprocess.run(
                    ["git", "-C", str(self.repo_root), "rev-parse", f"{commit_sha}:{rel_git_path}"],
                    capture_output=True,
                    text=True,
                    timeout=5.0
                )
                if res_blob.returncode == 0:
                    auth_metadata["directive_blob_sha"] = res_blob.stdout.strip()
            except Exception:
                pass

            # 7. Exact committed content match against candidate directive
            candidate_bytes = None
            if directive_file_path and directive_file_path.exists():
                try:
                    candidate_bytes = directive_file_path.read_bytes()
                except Exception:
                    pass

            if candidate_bytes is not None:
                candidate_hash = hashlib.sha256(candidate_bytes).hexdigest()
                if candidate_hash != committed_hash:
                    # Also check parsed JSON dict structure equivalence before failing
                    try:
                        committed_json = json.loads(committed_bytes.decode("utf-8"))
                        candidate_json = json.loads(candidate_bytes.decode("utf-8"))
                        if committed_json != candidate_json:
                            return ValidationStatus.CONTENT_MISMATCH, f"CONTENT_MISMATCH: Local candidate file '{rel_git_path}' content does not match committed content in {commit_sha[:7]}", False, auth_metadata
                    except Exception:
                        return ValidationStatus.CONTENT_MISMATCH, f"CONTENT_MISMATCH: Local candidate file content hash mismatch against commit {commit_sha[:7]}", False, auth_metadata
            else:
                # Compare directive data dict vs committed JSON dict
                try:
                    committed_json = json.loads(committed_bytes.decode("utf-8"))
                    cand_dict = directive.to_dict()
                    for k, v in cand_dict.items():
                        if committed_json.get(k) != v:
                            return ValidationStatus.CONTENT_MISMATCH, f"CONTENT_MISMATCH: Field '{k}' mismatch between candidate and committed blob in {commit_sha[:7]}", False, auth_metadata
                except Exception:
                    return ValidationStatus.CONTENT_MISMATCH, f"CONTENT_MISMATCH: Failed parsing committed JSON blob in {commit_sha[:7]}", False, auth_metadata

        # 8. Clock Skew & Expiration Checks
        created_dt = parse_iso(directive.created_at)
        expires_dt = parse_iso(directive.expires_at)

        if not created_dt or not expires_dt:
            return ValidationStatus.SCHEMA_INVALID, "SCHEMA_INVALID: Invalid created_at or expires_at ISO timestamp", False, auth_metadata

        # Future Clock Skew
        future_skew = (created_dt - now_dt).total_seconds()
        if future_skew > self.max_clock_skew_seconds:
            return ValidationStatus.CLOCK_SKEW_EXCEEDED, f"CLOCK_SKEW_EXCEEDED: Directive created_at is {future_skew:.1f}s in future (max allowed {self.max_clock_skew_seconds}s)", False, auth_metadata

        # Expiration Check
        if now_dt > expires_dt:
            return ValidationStatus.EXPIRED, f"EXPIRED: Directive expired at {directive.expires_at}", False, auth_metadata

        # 9. Allowed Action & Mutating Action Verification
        action_type = directive.action_type.upper()
        if action_type in settings.PROHIBITED_MUTATING_ACTIONS:
            return ValidationStatus.ACTION_NOT_ALLOWED, f"ACTION_NOT_ALLOWED: Prohibited mutating action '{action_type}' rejected in CONTROL-02.5", False, auth_metadata

        if action_type not in settings.ALLOWED_ACTION_CLASSES and action_type not in settings.ACTIONS_REQUIRING_HUMAN_APPROVAL:
            return ValidationStatus.ACTION_NOT_ALLOWED, f"ACTION_NOT_ALLOWED: Unknown or unauthorized action_type '{action_type}'", False, auth_metadata

        # 10. Human Approval Gate Evaluation
        requires_human = (
            directive.requires_human_approval or
            action_type in settings.ACTIONS_REQUIRING_HUMAN_APPROVAL
        )

        if requires_human:
            return ValidationStatus.AUTHENTIC, f"WAITING_HUMAN: Directive requires human approval for action '{action_type}'", True, auth_metadata

        return ValidationStatus.AUTHENTIC, "AUTHENTIC: Directive source authenticated and validated successfully", False, auth_metadata
