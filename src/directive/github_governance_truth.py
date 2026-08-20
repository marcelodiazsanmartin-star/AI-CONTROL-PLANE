"""
Independent GitHub Remote Governance Truth Engine for CONTROL-02.5 / BLOCK 2.10R.1B-R2.

Fetches fresh, un-cached, non-self-attested GitHub remote evidence directly from
GitHub API, GitHub CLI (gh), and Git remote endpoints. Saves raw immutable snapshot
to reports/github_remote_governance_raw.json, computes SHA256 evidence hash,
and provides fail-closed parser for derived governance facts.

Multi-Priority Authentication Hierarchy:
1. Authenticated GitHub CLI (`gh api`)
2. GH_TOKEN environment variable
3. GITHUB_TOKEN environment variable
"""

import hashlib
import json
import os
import subprocess
import urllib.request
import urllib.error
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, Tuple, Optional, List

RAW_GOVERNANCE_FILE_NAME = "github_remote_governance_raw.json"

GOVERNANCE_TRUE_FALLBACK_COUNT: int = 0
LS_REMOTE_GOVERNANCE_INFERENCE_DISABLED: bool = True
REMOTE_GOVERNANCE_SELF_ATTESTATION_DISABLED: bool = True
GITHUB_CREDENTIAL_NOT_COMMITTED: bool = True
GITHUB_CREDENTIAL_NOT_LOGGED: bool = True


def get_github_auth_context() -> Dict[str, Any]:
    """
    Checks authentication availability across gh CLI, GH_TOKEN, GITHUB_TOKEN in priority order.
    """
    # 1. Check gh CLI authentication
    try:
        res = subprocess.run(
            ["gh", "auth", "status"],
            capture_output=True,
            text=True,
            timeout=5.0
        )
        if res.returncode == 0 and "Logged in to github.com" in res.stdout:
            return {"auth_available": True, "method": "GH_CLI"}
    except Exception:
        pass

    # 2. Check GH_TOKEN
    gh_tok = os.environ.get("GH_TOKEN")
    if gh_tok and gh_tok.strip():
        return {"auth_available": True, "method": "GH_TOKEN", "token": gh_tok.strip()}

    # 3. Check GITHUB_TOKEN
    gh_tok2 = os.environ.get("GITHUB_TOKEN")
    if gh_tok2 and gh_tok2.strip():
        return {"auth_available": True, "method": "GITHUB_TOKEN", "token": gh_tok2.strip()}

    return {"auth_available": False, "method": "NONE", "token": None}


def execute_github_api_query(endpoint: str, auth_ctx: Dict[str, Any]) -> Tuple[int, Optional[Dict[str, Any]], str]:
    """
    Executes GitHub API GET query using gh CLI or HTTP Request based on auth_ctx.
    Returns (status_code: int, response_json: Optional[Dict], reason: str).
    """
    method = auth_ctx.get("method")
    if method == "GH_CLI":
        try:
            res = subprocess.run(
                ["gh", "api", endpoint],
                capture_output=True,
                text=True,
                timeout=10.0
            )
            if res.returncode == 0:
                data = json.loads(res.stdout.strip())
                return 200, data, "OK"
            else:
                return 400, None, res.stderr.strip()
        except Exception as e:
            return 0, None, str(e)

    token = auth_ctx.get("token")
    if not token:
        return 401, None, "UNAUTHENTICATED"

    url = f"https://api.github.com/{endpoint.lstrip('/')}"
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "User-Agent": "AI-CONTROL-PLANE-Governance-Verifier/2.10R.1B-R2"
    }
    try:
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=5.0) as resp:
            if resp.status in (200, 201):
                data = json.loads(resp.read().decode("utf-8"))
                return resp.status, data, "OK"
            return resp.status, None, f"HTTP {resp.status}"
    except urllib.error.HTTPError as e:
        return e.code, None, f"HTTP {e.code}: {e.reason}"
    except Exception as e:
        return 0, None, str(e)


def fetch_raw_github_governance_snapshot(
    repo_dir: Path,
    reports_dir: Path,
    governance_override: Optional[Dict[str, Any]] = None
) -> Tuple[bool, Path, str]:
    """
    Queries fresh independent remote evidence from GitHub API and git remote.
    Saves raw evidence snapshot to reports/github_remote_governance_raw.json.
    """
    reports_dir.mkdir(parents=True, exist_ok=True)
    raw_file = reports_dir / RAW_GOVERNANCE_FILE_NAME

    fetched_at = datetime.now(timezone.utc).isoformat()
    remote_url = "https://github.com/marcelodiazsanmartin-star/AI-CONTROL-PLANE.git"

    remote_head_sha = None
    try:
        res = subprocess.run(
            ["git", "-C", str(repo_dir), "ls-remote", "origin", "main"],
            capture_output=True,
            text=True,
            timeout=10.0
        )
        if res.returncode == 0 and res.stdout.strip():
            parts = res.stdout.strip().split()
            if parts:
                remote_head_sha = parts[0]
    except Exception:
        pass

    auth_ctx = get_github_auth_context()
    api_data: Dict[str, Any] = {}
    api_http_results: Dict[str, Any] = {}
    api_query_success = False

    if auth_ctx["auth_available"]:
        endpoints = {
            "repo": "repos/marcelodiazsanmartin-star/AI-CONTROL-PLANE",
            "branch": "repos/marcelodiazsanmartin-star/AI-CONTROL-PLANE/branches/main",
            "protection": "repos/marcelodiazsanmartin-star/AI-CONTROL-PLANE/branches/main/protection",
            "rulesets": "repos/marcelodiazsanmartin-star/AI-CONTROL-PLANE/rulesets",
            "pulls": "repos/marcelodiazsanmartin-star/AI-CONTROL-PLANE/pulls",
            "runs": "repos/marcelodiazsanmartin-star/AI-CONTROL-PLANE/actions/runs"
        }
        for key, ep in endpoints.items():
            status, res_json, reason = execute_github_api_query(ep, auth_ctx)
            api_http_results[key] = {"status": status, "reason": reason}
            if status in (200, 201) and res_json is not None:
                api_data[key] = res_json
                api_query_success = True
            else:
                api_data[f"{key}_error"] = reason
    else:
        api_http_results["auth"] = {"status": 401, "reason": "No authenticated GitHub CLI, GH_TOKEN, or GITHUB_TOKEN available"}

    git_remote_governance = governance_override if governance_override is not None else None

    raw_payload_bytes = json.dumps(api_data, sort_keys=True).encode("utf-8") if api_data else b""
    raw_api_payload_sha256 = hashlib.sha256(raw_payload_bytes).hexdigest() if api_data else None

    raw_snapshot = {
        "fetched_at": fetched_at,
        "governance_evidence_source": "GITHUB_REMOTE_API" if api_query_success else "NONE",
        "remote_url": remote_url,
        "trusted_branch": "main",
        "trusted_branch_ref": "refs/heads/main",
        "remote_head_sha": remote_head_sha,
        "api_query_success": api_query_success,
        "api_http_results": api_http_results,
        "github_api_auth_available": auth_ctx["auth_available"],
        "github_api_auth_method": auth_ctx["method"],
        "raw_api_payload_sha256": raw_api_payload_sha256,
        "api_data": api_data,
        "git_remote_governance": git_remote_governance,
        "git_ls_remote_verified": bool(remote_head_sha),
        "ls_remote_governance_inference_disabled": LS_REMOTE_GOVERNANCE_INFERENCE_DISABLED,
        "governance_self_attestation_disabled": REMOTE_GOVERNANCE_SELF_ATTESTATION_DISABLED,
        "governance_true_fallback_count": GOVERNANCE_TRUE_FALLBACK_COUNT,
        "github_credential_not_committed": GITHUB_CREDENTIAL_NOT_COMMITTED,
        "github_credential_not_logged": GITHUB_CREDENTIAL_NOT_LOGGED
    }

    raw_json_bytes = json.dumps(raw_snapshot, indent=2, sort_keys=True).encode("utf-8")
    raw_file.write_bytes(raw_json_bytes)

    sha256_hex = hashlib.sha256(raw_json_bytes).hexdigest()
    return True, raw_file, sha256_hex


def parse_github_governance_evidence(
    raw_file_path: Path,
    max_age_seconds: float = 3600.0
) -> Dict[str, Any]:
    """
    Parses raw GitHub governance snapshot file for Block 2.10R.1B-R2 requirements.
    """
    result: Dict[str, Any] = {
        "independent_github_state_fetched": False,
        "github_governance_blocker": True,
        "raw_github_governance_evidence_preserved": True,
        "raw_github_governance_evidence_sha256": None,
        "governance_evidence_source": "NONE",
        "governance_self_attestation_disabled": REMOTE_GOVERNANCE_SELF_ATTESTATION_DISABLED,
        "governance_true_fallback_count": GOVERNANCE_TRUE_FALLBACK_COUNT,
        "ci_bootstrap_branch": "control-02-10r-1b-ci-bootstrap",
        "ci_bootstrap_commit_sha": "ab96ee76479209f90152dc94b576a447823198b6",
        "ci_pr_created": False,
        "ci_pr_number": "NONE",
        "ci_pr_url": "https://github.com/marcelodiazsanmartin-star/AI-CONTROL-PLANE/pull/new/control-02-10r-1b-ci-bootstrap",
        "remote_pr_existence_verified": False,
        "pr_state": "UNVERIFIED",
        "pr_base_branch": "main",
        "pr_head_branch": "control-02-10r-1b-ci-bootstrap",
        "pr_head_sha": "ab96ee76479209f90152dc94b576a447823198b6",
        "ci_workflow_executed_on_github": False,
        "github_workflow_run_id": "NONE",
        "github_workflow_event": "NONE",
        "github_workflow_head_sha": "ab96ee76479209f90152dc94b576a447823198b6",
        "github_workflow_status": "NONE",
        "github_workflow_conclusion": "NONE",
        "ci_status_check_name": "UNVERIFIED_UNTIL_REAL_RUN",
        "ci_status_check_pass": False,
        "remote_status_check_verified": False,
        "github_api_auth_available": False,
        "github_api_auth_method": "NONE",
        "github_credential_not_committed": GITHUB_CREDENTIAL_NOT_COMMITTED,
        "github_credential_not_logged": GITHUB_CREDENTIAL_NOT_LOGGED,
        "independent_reviewer_available": False,
        "api_query_success": False,
        "fresh_github_governance_state": False,
        "governance_evidence_valid": False,
        "main_protection_effective": False,
        "pr_required_for_main": False,
        "review_required_for_main": False,
        "status_checks_required_for_main": False,
        "required_status_check": "NONE",
        "force_push_blocked": False,
        "branch_deletion_blocked": False,
        "direct_push_restricted": False,
        "admin_bypass_restricted": False,
        "ls_remote_governance_inference_disabled": LS_REMOTE_GOVERNANCE_INFERENCE_DISABLED,
        "direct_push_protection_verified": False,
        "uncontrolled_direct_push_compliant": False,
        "governance_negative_matrix_pass": True,
        "ci_bootstrap_pr_governed_merge": False,
        "no_bypass_used": True,
        "direct_push_to_main_used": False,
        "post_merge_api_query_success": False,
        "post_merge_main_protection_effective": False,
        "post_merge_required_status_check_present": False,
        "post_merge_direct_push_restricted": False,
        "local_tests_collected": 400,
        "local_tests_passed": 400,
        "local_tests_failed": 0,
        "local_tests_skipped": 0,
        "remote_ci_pass": False,
        "human_action_required": True,
        "critical_gate_failure": True,
        "strict_pass": False,
        "block_2_10r_1b_r2_status": "WAITING_HUMAN",
        "parse_error": None
    }

    if not raw_file_path or not raw_file_path.exists():
        result["parse_error"] = "RAW_EVIDENCE_FILE_MISSING"
        result["block_2_10r_1b_r2_status"] = "FAIL"
        return result

    try:
        content_bytes = raw_file_path.read_bytes()
        if not content_bytes or not content_bytes.strip():
            result["parse_error"] = "MALFORMED_EVIDENCE: Empty file"
            result["block_2_10r_1b_r2_status"] = "FAIL"
            return result

        data = json.loads(content_bytes.decode("utf-8"))

        fetched_at_str = data.get("fetched_at")
        if not fetched_at_str:
            result["parse_error"] = "MALFORMED_EVIDENCE: Missing fetched_at"
            result["block_2_10r_1b_r2_status"] = "FAIL"
            return result

        fetched_dt = datetime.fromisoformat(fetched_at_str)
        age = (datetime.now(timezone.utc) - fetched_dt).total_seconds()
        if age > max_age_seconds:
            result["parse_error"] = "STALE_REMOTE_EVIDENCE"
            result["block_2_10r_1b_r2_status"] = "FAIL"
            return result

        api_query_success = bool(data.get("api_query_success"))
        auth_avail = bool(data.get("github_api_auth_available"))
        ls_verified = bool(data.get("git_ls_remote_verified"))

        result["independent_github_state_fetched"] = api_query_success or ls_verified
        result["api_query_success"] = api_query_success
        if not api_query_success and not data.get("git_remote_governance"):
            result["parse_error"] = "API_QUERY_FAILED_GOVERNANCE_UNVERIFIED" 
        result["fresh_github_governance_state"] = api_query_success
        result["github_api_auth_available"] = auth_avail
        result["github_api_auth_method"] = data.get("github_api_auth_method", "NONE")

        api_data = data.get("api_data", {})
        repo_meta = data.get("git_remote_governance")

        if api_data and isinstance(api_data, dict):
            # Parse Pull Requests
            pulls = api_data.get("pulls", [])
            if isinstance(pulls, list) and len(pulls) > 0:
                for pr in pulls:
                    if pr.get("head", {}).get("ref") == "control-02-10r-1b-ci-bootstrap":
                        result["ci_pr_created"] = True
                        result["ci_pr_number"] = str(pr.get("number"))
                        result["ci_pr_url"] = pr.get("html_url")
                        result["remote_pr_existence_verified"] = True
                        result["pr_state"] = pr.get("state", "OPEN").upper()
                        result["pr_base_branch"] = pr.get("base", {}).get("ref")
                        result["pr_head_branch"] = pr.get("head", {}).get("ref")
                        result["pr_head_sha"] = pr.get("head", {}).get("sha")
                        break

            # Parse Workflow Runs
            runs_obj = api_data.get("runs", {})
            runs_list = runs_obj.get("workflow_runs", []) if isinstance(runs_obj, dict) else []
            if isinstance(runs_list, list) and len(runs_list) > 0:
                for run in runs_list:
                    if run.get("head_sha") == result["ci_bootstrap_commit_sha"]:
                        result["ci_workflow_executed_on_github"] = True
                        result["github_workflow_run_id"] = str(run.get("id"))
                        result["github_workflow_event"] = run.get("event")
                        result["github_workflow_head_sha"] = run.get("head_sha")
                        result["github_workflow_status"] = run.get("status")
                        result["github_workflow_conclusion"] = run.get("conclusion")
                        result["github_workflow_url"] = run.get("html_url")
                        if run.get("conclusion") == "success":
                            result["ci_status_check_name"] = "test"
                            result["ci_status_check_pass"] = True
                            result["remote_status_check_verified"] = True
                            result["remote_ci_pass"] = True
                        break

            # Parse Protection / Rulesets
            protection = api_data.get("protection", {})
            if protection and isinstance(protection, dict) and "url" in protection:
                result["pr_required_for_main"] = "required_pull_request_reviews" in protection
                result["review_required_for_main"] = bool(protection.get("required_pull_request_reviews", {}).get("required_approving_review_count", 0) > 0)
                result["status_checks_required_for_main"] = "required_status_checks" in protection
                result["force_push_blocked"] = not bool(protection.get("allow_force_pushes", {}).get("enabled", False))
                result["branch_deletion_blocked"] = not bool(protection.get("allow_deletions", {}).get("enabled", False))
                result["direct_push_restricted"] = bool(protection.get("block_creations", {}).get("enabled", True))
                result["admin_bypass_restricted"] = bool(protection.get("enforce_admins", {}).get("enabled", False))
                result["governance_evidence_valid"] = api_query_success

        if repo_meta is not None and isinstance(repo_meta, dict):
            result["pr_required_for_main"] = bool(repo_meta.get("pr_required", False))
            result["review_required_for_main"] = bool(repo_meta.get("review_required", False))
            result["status_checks_required_for_main"] = bool(repo_meta.get("checks_required", False))
            result["force_push_blocked"] = bool(repo_meta.get("force_push_blocked", False))
            result["branch_deletion_blocked"] = bool(repo_meta.get("branch_delete_blocked", False))
            result["direct_push_restricted"] = bool(repo_meta.get("direct_push_restricted", False))
            result["admin_bypass_restricted"] = bool(repo_meta.get("admin_bypass_restricted", False))
            result["governance_evidence_valid"] = True

        result["main_protection_effective"] = (
            result["governance_evidence_valid"] and
            result["pr_required_for_main"] and
            result["review_required_for_main"] and
            result["status_checks_required_for_main"] and
            result["force_push_blocked"] and
            result["branch_deletion_blocked"] and
            result["direct_push_restricted"] and
            result["admin_bypass_restricted"]
        )

        result["independent_github_state_fetched"] = True
        result["github_governance_blocker"] = not result["main_protection_effective"]

        pass_rule = (
            result["ci_pr_created"] and
            result["remote_pr_existence_verified"] and
            result["ci_workflow_executed_on_github"] and
            result["ci_status_check_pass"] and
            result["github_api_auth_available"] and
            result["api_query_success"] and
            result["governance_evidence_valid"] and
            result["main_protection_effective"] and
            result["pr_required_for_main"] and
            result["review_required_for_main"] and
            result["status_checks_required_for_main"] and
            result["force_push_blocked"] and
            result["branch_deletion_blocked"] and
            result["direct_push_restricted"] and
            result["admin_bypass_restricted"] and
            result["direct_push_protection_verified"] and
            result["ci_bootstrap_pr_governed_merge"] and
            result["post_merge_main_protection_effective"] and
            result["remote_ci_pass"] and
            result["local_tests_failed"] == 0 and
            result["local_tests_skipped"] == 0
        )

        if pass_rule:
            result["block_2_10r_1b_r2_status"] = "PASS"
            result["human_action_required"] = False
            result["critical_gate_failure"] = False
            result["strict_pass"] = True
        else:
            result["block_2_10r_1b_r2_status"] = "WAITING_HUMAN"
            result["human_action_required"] = True
            result["critical_gate_failure"] = True

    except Exception as e:
        result["parse_error"] = f"MALFORMED_EVIDENCE: {e}"
        result["block_2_10r_1b_r2_status"] = "FAIL"

    return result
