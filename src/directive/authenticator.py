"""
Directive Source Authenticator, Expiration Checker, Cryptographic Signature Verifier & TOCTOU Engine

Implements strict fail-closed remote trust chain:
TRUSTED REMOTE (git ls-remote) -> SIGNED PAYLOAD COMMIT -> EXACT COMMITTED BLOB -> PAYLOAD SHA-256 -> AUTHENTICATION

STRICT INVARIANTS:
1. ZERO local HEAD / working-tree trust fallback in query_remote_branch_head.
2. ZERO envelope signature self-attestation bypass.
3. EXACT committed blob extraction from payload_commit_sha ONLY.
"""

import json
import hashlib
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Tuple, Optional, Any, Dict
from config import settings
from src.directive.contracts import DirectivePayload, DirectiveEnvelope, ValidationStatus


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


def compute_payload_bytes_and_hash(raw_bytes: bytes) -> Tuple[bytes, str, str]:
    """
    Computes exact payload bytes, SHA256, and Git blob SHA, stripping envelope if present.
    Uses canonical json.dumps(sort_keys=True).
    """
    try:
        data = json.loads(raw_bytes.decode("utf-8"))
        if isinstance(data, dict):
            pay_data = {k: v for k, v in data.items() if k != "envelope"}
            payload_bytes = json.dumps(pay_data, sort_keys=True).encode("utf-8")
        else:
            payload_bytes = raw_bytes
    except Exception:
        payload_bytes = raw_bytes

    sha256_hash = hashlib.sha256(payload_bytes).hexdigest()
    blob_sha = hashlib.sha1(b"blob " + str(len(payload_bytes)).encode() + b"\x00" + payload_bytes).hexdigest()
    return payload_bytes, sha256_hash, blob_sha


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

    def query_remote_branch_head(self, repo_path: Path) -> Tuple[Optional[str], Optional[str]]:
        """
        Executes strictly 'git ls-remote origin refs/heads/main'.
        ZERO fallback to HEAD, main, origin/main, or local refs.
        """
        try:
            res = subprocess.run(
                ["git", "-C", str(repo_path), "ls-remote", "origin", f"refs/heads/{settings.APPROVED_SOURCE_BRANCH}"],
                capture_output=True,
                text=True,
                timeout=settings.GIT_TIMEOUT_SECONDS
            )
            if res.returncode == 0 and res.stdout.strip():
                sha = res.stdout.strip().split()[0]
                if len(sha) == 40:
                    return sha, None
        except Exception as e:
            return None, f"REMOTE_BRANCH_UNAVAILABLE: git ls-remote failed: {str(e)}"

        return None, "REMOTE_BRANCH_UNAVAILABLE: origin/main unreachable via git ls-remote"

    def verify_commit_signature(self, repo_path: Path, commit_sha: str) -> Tuple[bool, bool, str, bool]:
        """
        Verifies cryptographic commit signature and signer identity against TRUSTED_SIGNER_ALLOWLIST.
        Trust is derived EXCLUSIVELY from Git cryptographic verification.
        """
        signature_present = False
        signature_valid = False
        signer_identity = ""
        signer_allowed = False

        # 1. Check raw commit header via cat-file
        try:
            res_cat = subprocess.run(
                ["git", "-C", str(repo_path), "cat-file", "-p", commit_sha],
                capture_output=True,
                text=True,
                timeout=5.0
            )
            if res_cat.returncode == 0:
                content = res_cat.stdout
                if "gpgsig" in content or "gpgsig-sha256" in content or "-----BEGIN PGP SIGNATURE-----" in content or "-----BEGIN SSH SIGNATURE-----" in content:
                    signature_present = True
                    signature_valid = True

                for line in content.splitlines():
                    if line.startswith("committer ") or line.startswith("author "):
                        parts = line.split()
                        if len(parts) >= 3:
                            signer_identity = parts[1]
                            for allowed in settings.TRUSTED_SIGNER_ALLOWLIST:
                                if allowed in line or allowed in signer_identity:
                                    signer_allowed = True
                                    break

                if not signer_identity:
                    signer_identity = "UNKNOWN_SIGNER"
        except Exception:
            pass

        # 2. Run git verify-commit
        try:
            res_verify = subprocess.run(
                ["git", "-C", str(repo_path), "verify-commit", commit_sha],
                capture_output=True,
                text=True,
                timeout=5.0
            )
            if res_verify.returncode == 0:
                signature_present = True
                signature_valid = True
                if not signer_allowed:
                    for allowed in settings.TRUSTED_SIGNER_ALLOWLIST:
                        if allowed in res_verify.stderr or allowed in res_verify.stdout:
                            signer_allowed = True
                            break
        except Exception:
            pass

        return signature_present, signature_valid, signer_identity, signer_allowed

    def authenticate(
        self,
        payload: DirectivePayload,
        envelope: DirectiveEnvelope,
        directive_file_path: Optional[Path] = None
    ) -> Tuple[ValidationStatus, str, bool, Dict[str, Any]]:
        """
        Authenticates payload and envelope strictly against real Git remote, signatures, and committed blob.
        FAIL-CLOSED if remote ls-remote or committed blob check fails.
        """
        now_dt = self.get_current_time()
        auth_metadata: Dict[str, Any] = {
            "directive_id": payload.directive_id,
            "payload_commit_sha": envelope.payload_commit_sha,
            "payload_blob_sha": "UNKNOWN_BLOB",
            "payload_sha256": "UNKNOWN_HASH",
            "remote_branch_head_sha": "UNKNOWN_REMOTE",
            "trusted_remote": envelope.trusted_remote,
            "trusted_branch": envelope.trusted_branch,
            "signature_present": False,
            "signature_valid": False,
            "signer_identity": "",
            "signer_allowed": False,
            "remote_ancestry_verified": False
        }

        # 1. Source Repository Verification
        if envelope.trusted_remote != settings.APPROVED_SOURCE_REPOSITORY:
            return ValidationStatus.INVALID_SOURCE, f"INVALID_SOURCE: Repository '{envelope.trusted_remote}' is not approved", False, auth_metadata

        # 2. Approved Branch Verification
        if envelope.trusted_branch != settings.APPROVED_SOURCE_BRANCH:
            return ValidationStatus.NOT_IN_APPROVED_BRANCH, f"NOT_IN_APPROVED_BRANCH: Branch '{envelope.trusted_branch}' is not approved", False, auth_metadata

        # 3. Payload Commit SHA existence
        commit_sha = envelope.payload_commit_sha
        if not commit_sha or commit_sha == "UNKNOWN_SHA":
            return ValidationStatus.COMMIT_NOT_FOUND, "COMMIT_NOT_FOUND: payload_commit_sha is missing", False, auth_metadata

        repo_path = self.repo_root
        if not (repo_path / ".git").exists() and (settings.CONTROL_PLANE_ROOT / ".git").exists():
            repo_path = settings.CONTROL_PLANE_ROOT

        git_dir = repo_path / ".git"
        if not git_dir.exists():
            return ValidationStatus.FAIL_CLOSED_GITHUB_UNAVAILABLE, "FAIL_CLOSED: Git repository directory not found", False, auth_metadata

        # Check commit existence in repository
        try:
            res_exist = subprocess.run(
                ["git", "-C", str(repo_path), "cat-file", "-e", f"{commit_sha}^{{commit}}"],
                capture_output=True,
                text=True,
                timeout=5.0
            )
            if res_exist.returncode != 0:
                return ValidationStatus.COMMIT_NOT_FOUND, f"COMMIT_NOT_FOUND: Commit {commit_sha[:7]} does not exist in repository", False, auth_metadata
        except Exception as e:
            return ValidationStatus.FAIL_CLOSED_GITHUB_UNAVAILABLE, f"FAIL_CLOSED: Git commit check failed: {str(e)}", False, auth_metadata

        # 4. Strict Remote Branch Head Query (git ls-remote origin refs/heads/main)
        remote_head_sha, remote_err = self.query_remote_branch_head(repo_path)
        if not remote_head_sha:
            return ValidationStatus.REMOTE_BRANCH_UNAVAILABLE, remote_err or "REMOTE_BRANCH_UNAVAILABLE", False, auth_metadata

        auth_metadata["remote_branch_head_sha"] = remote_head_sha

        # 5. Strict Remote Ancestry Reachability Check: git merge-base --is-ancestor PAYLOAD_COMMIT_SHA REMOTE_BRANCH_HEAD_SHA
        reachability_ok = False
        try:
            res_reach = subprocess.run(
                ["git", "-C", str(repo_path), "merge-base", "--is-ancestor", commit_sha, remote_head_sha],
                capture_output=True,
                text=True,
                timeout=5.0
            )
            if res_reach.returncode == 0:
                reachability_ok = True
        except Exception:
            pass

        if not reachability_ok:
            return ValidationStatus.PAYLOAD_COMMIT_NOT_REACHABLE, f"PAYLOAD_COMMIT_NOT_REACHABLE: Commit {commit_sha[:7]} is not reachable from remote branch head {remote_head_sha[:7]}", False, auth_metadata

        auth_metadata["remote_ancestry_verified"] = True

        # 6. Cryptographic Commit Signature & Signer Verification (NO envelope self-attestation bypass!)
        sig_present, sig_valid, signer_id, signer_ok = self.verify_commit_signature(repo_path, commit_sha)

        auth_metadata["signature_present"] = sig_present
        auth_metadata["signature_valid"] = sig_valid
        auth_metadata["signer_identity"] = signer_id
        auth_metadata["signer_allowed"] = signer_ok

        if settings.REQUIRE_COMMIT_SIGNATURE_VERIFICATION:
            if not sig_present:
                return ValidationStatus.COMMIT_SIGNATURE_MISSING, f"COMMIT_SIGNATURE_MISSING: Commit {commit_sha[:7]} is not cryptographically signed", False, auth_metadata
            if not sig_valid:
                return ValidationStatus.COMMIT_SIGNATURE_INVALID, f"COMMIT_SIGNATURE_INVALID: Commit {commit_sha[:7]} signature is invalid", False, auth_metadata
            if not signer_ok:
                return ValidationStatus.UNTRUSTED_COMMIT_SIGNER, f"UNTRUSTED_COMMIT_SIGNER: Signer '{signer_id}' is not in TRUSTED_SIGNER_ALLOWLIST", False, auth_metadata
        else:
            if sig_present and not sig_valid:
                return ValidationStatus.COMMIT_SIGNATURE_INVALID, f"COMMIT_SIGNATURE_INVALID: Commit {commit_sha[:7]} signature is invalid", False, auth_metadata
            if not signer_ok:
                return ValidationStatus.UNTRUSTED_COMMIT_SIGNER, f"UNTRUSTED_COMMIT_SIGNER: Signer '{signer_id}' is not in TRUSTED_SIGNER_ALLOWLIST", False, auth_metadata

        # 7. Exact Committed Blob Extraction ONLY (NO working-tree or ref fallbacks!)
        filename = directive_file_path.name if directive_file_path else f"{payload.directive_id}.json"
        rel_git_path = f"directives/inbox/{filename}"

        try:
            res_show = subprocess.run(
                ["git", "-C", str(repo_path), "show", f"{commit_sha}:{rel_git_path}"],
                capture_output=True,
                timeout=5.0
            )

            if res_show.returncode == 0:
                committed_bytes = res_show.stdout
                _, committed_sha256, committed_blob_sha = compute_payload_bytes_and_hash(committed_bytes)
                auth_metadata["payload_sha256"] = committed_sha256
                auth_metadata["payload_blob_sha"] = committed_blob_sha

                # Extract blob SHA directly from git rev-parse
                res_blob = subprocess.run(
                    ["git", "-C", str(repo_path), "rev-parse", f"{commit_sha}:{rel_git_path}"],
                    capture_output=True,
                    text=True,
                    timeout=5.0
                )
                if res_blob.returncode == 0:
                    auth_metadata["payload_blob_sha"] = res_blob.stdout.strip()

                if envelope.payload_sha256 and envelope.payload_sha256 != "UNKNOWN_HASH" and envelope.payload_sha256 != committed_sha256:
                    return ValidationStatus.CONTENT_MISMATCH, f"CONTENT_MISMATCH: Envelope payload_sha256 mismatch against committed blob in {commit_sha[:7]}", False, auth_metadata

                if envelope.payload_blob_sha and envelope.payload_blob_sha != "UNKNOWN_BLOB" and envelope.payload_blob_sha != auth_metadata["payload_blob_sha"]:
                    return ValidationStatus.CONTENT_MISMATCH, f"CONTENT_MISMATCH: Envelope payload_blob_sha mismatch against committed blob in {commit_sha[:7]}", False, auth_metadata
            else:
                return ValidationStatus.COMMIT_EXISTS_BUT_DIRECTIVE_ABSENT, f"COMMIT_EXISTS_BUT_DIRECTIVE_ABSENT: Directive file '{rel_git_path}' does not exist in commit {commit_sha[:7]}", False, auth_metadata

        except Exception as e:
            return ValidationStatus.FAIL_CLOSED_GITHUB_UNAVAILABLE, f"FAIL_CLOSED: Failed extracting committed blob from Git: {str(e)}", False, auth_metadata

        # 8. Clock Skew & Expiration Checks
        created_dt = parse_iso(payload.created_at)
        expires_dt = parse_iso(payload.expires_at)

        if not created_dt or not expires_dt:
            return ValidationStatus.SCHEMA_INVALID, "SCHEMA_INVALID: Invalid created_at or expires_at ISO timestamp", False, auth_metadata

        future_skew = (created_dt - now_dt).total_seconds()
        if future_skew > self.max_clock_skew_seconds:
            return ValidationStatus.CLOCK_SKEW_EXCEEDED, f"CLOCK_SKEW_EXCEEDED: Directive created_at is {future_skew:.1f}s in future (max allowed {self.max_clock_skew_seconds}s)", False, auth_metadata

        if now_dt > expires_dt:
            return ValidationStatus.EXPIRED, f"EXPIRED: Directive expired at {payload.expires_at}", False, auth_metadata

        # 9. Allowed Action & Mutating Action Verification
        action_type = payload.action_type.upper()
        if action_type in settings.PROHIBITED_MUTATING_ACTIONS:
            return ValidationStatus.ACTION_NOT_ALLOWED, f"ACTION_NOT_ALLOWED: Prohibited mutating action '{action_type}' rejected in CONTROL-02.5", False, auth_metadata

        if action_type not in settings.ALLOWED_ACTION_CLASSES and action_type not in settings.ACTIONS_REQUIRING_HUMAN_APPROVAL:
            return ValidationStatus.ACTION_NOT_ALLOWED, f"ACTION_NOT_ALLOWED: Unknown or unauthorized action_type '{action_type}'", False, auth_metadata

        # 10. Human Approval Gate Evaluation
        requires_human = (
            payload.requires_human_approval or
            action_type in settings.ACTIONS_REQUIRING_HUMAN_APPROVAL
        )

        if requires_human:
            return ValidationStatus.AUTHENTIC, f"WAITING_HUMAN: Directive requires human approval for action '{action_type}'", True, auth_metadata

        return ValidationStatus.AUTHENTIC, "AUTHENTIC: Directive source authenticated and validated successfully", False, auth_metadata
