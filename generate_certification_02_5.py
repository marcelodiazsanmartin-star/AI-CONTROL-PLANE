"""
Certification Evidence Generator for CONTROL-02.5 (Round 3 Hardened)

Derived evidence calculation, AST self-auditing scanner, fresh crypto run ID verification,
independent generator crypto re-verification, production signer manifest validation,
execution ledger reconciliation, direct monitored repo cleanliness observation,
4-commit provenance model, and two-phase certification state.
"""

import sys
import json
import os
import uuid
import ast
import argparse
import subprocess
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path
from typing import Set, Dict, Any, List, Optional

ROOT_DIR = Path(__file__).resolve().parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from config import settings
from src.directive.scanner import scan_authentication_bypasses
from src.directive.signer_validator import validate_production_signers
from src.directive.reconciler import reconcile_execution_evidence
from src.observer.process_observer import ProcessObserver


CRITICAL_CERTIFICATION_FIELDS = {
    "hardcoded_signature_bypass_count",
    "production_placeholder_signer_count",
    "test_keys_isolated_from_production",
    "real_crypto_test_backend",
    "real_crypto_backend_verified",
    "real_signature_verification_tested",
    "mutating_directives_executed",
    "queue_fsync_verified",
    "queue_restart_integrity_verified",
    "queue_corruption_fail_closed",
    "queue_record_readback_verified",
    "remote_fail_closed",
    "strict_remote_ancestry",
    "worktree_fallback",
    "toctou_revalidation_verified",
    "execution_evidence_available",
    "execution_evidence_complete",
    "execution_ledger_consistent",
    "critical_gate_failure"
}

SUPPORTED_CRYPTO_BACKENDS = {"SSH"}


def validate_crypto_backend(backend: Optional[str]) -> bool:
    if not backend or not isinstance(backend, str):
        return False
    return backend in SUPPORTED_CRYPTO_BACKENDS


def derive_security_gates(passed_test_names: Set[str], crypto_metrics: Dict[str, Any]) -> Dict[str, Any]:
    queue_fsync_verified = "test_queue_fsync_persistence_verified" in passed_test_names
    queue_restart_integrity_verified = (
        "test_accepted_queue_survives_restart" in passed_test_names and
        "test_accepted_item_not_lost_after_restart" in passed_test_names
    )
    queue_corruption_fail_closed = "test_queue_corrupted_after_restart_fail_closed" in passed_test_names
    queue_record_readback_verified = (
        "test_queue_fsync_persistence_verified" in passed_test_names and
        "test_queue_integrity_after_restart" in passed_test_names
    )

    remote_fail_closed = "test_fail_closed_on_github_unavailable" in passed_test_names
    strict_remote_ancestry = "test_directive_commit_not_reachable_from_main_rejected" in passed_test_names

    worktree_fallback_disabled = (
        "test_local_modified_copy_cannot_authenticate" in passed_test_names and
        "test_commit_exists_but_directive_absent_rejected" in passed_test_names
    )
    worktree_fallback = not worktree_fallback_disabled

    toctou_revalidation_verified = "test_toctou_revalidation_executes_auth_meta_branch" in passed_test_names

    real_signature_verification_tested = all([
        crypto_metrics.get("real_unsigned_commit_rejected") is True,
        crypto_metrics.get("real_invalid_signature_rejected") is True,
        crypto_metrics.get("real_trusted_signer_accepted") is True,
        crypto_metrics.get("real_untrusted_signer_rejected") is True,
        crypto_metrics.get("author_metadata_authorization_disabled") is True,
        crypto_metrics.get("envelope_self_attestation_disabled") is True,
        crypto_metrics.get("real_git_verify_commit_success_count", 0) >= 2,
        crypto_metrics.get("real_git_verify_commit_failure_count", 0) >= 2
    ])

    return {
        "queue_fsync_verified": queue_fsync_verified,
        "queue_restart_integrity_verified": queue_restart_integrity_verified,
        "queue_corruption_fail_closed": queue_corruption_fail_closed,
        "queue_record_readback_verified": queue_record_readback_verified,
        "remote_fail_closed": remote_fail_closed,
        "strict_remote_ancestry": strict_remote_ancestry,
        "worktree_fallback": worktree_fallback,
        "toctou_revalidation_verified": toctou_revalidation_verified,
        "real_signature_verification_tested": real_signature_verification_tested
    }


def audit_certification_generator_ast(gen_file: Path = None) -> bool:
    """
    AST Self-Auditing Scanner: Inspects generate_certification_02_5.py source code AST
    to verify no critical security variables are assigned literal constant values without computation,
    no critical dict entries in cert_data use hardcoded primitive literals, and no dict.get()
    calls introduce unsafe default primitive literals for critical fields.
    Returns True if NO critical certification fields are hardcoded.
    """
    if gen_file is None:
        gen_file = ROOT_DIR / "generate_certification_02_5.py"
    if not gen_file.exists():
        return False

    try:
        tree = ast.parse(gen_file.read_text(encoding="utf-8"))

        for node in ast.walk(tree):
            # A. Variable assignments
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name) and target.id in CRITICAL_CERTIFICATION_FIELDS:
                        if isinstance(node.value, (ast.Constant, ast.NameConstant)):
                            val = getattr(node.value, "value", None)
                            if val is not None and val != "UNKNOWN":
                                return False

            # B. Dictionary literal keys in cert_data
            if isinstance(node, ast.Dict):
                for key_node, val_node in zip(node.keys, node.values):
                    key_name = None
                    if isinstance(key_node, ast.Constant) and isinstance(key_node.value, str):
                        key_name = key_node.value
                    elif isinstance(key_node, ast.Str):
                        key_name = key_node.s

                    if key_name and key_name in CRITICAL_CERTIFICATION_FIELDS:
                        if isinstance(val_node, (ast.Constant, ast.NameConstant)):
                            return False

            # C. dict.get(key, DEFAULT) calls with unsafe defaults for critical crypto/backend fields
            if isinstance(node, ast.Call):
                if isinstance(node.func, ast.Attribute) and node.func.attr == "get":
                    if len(node.args) >= 2:
                        first_arg = node.args[0]
                        second_arg = node.args[1]
                        key_str = None
                        if isinstance(first_arg, ast.Constant) and isinstance(first_arg.value, str):
                            key_str = first_arg.value
                        elif isinstance(first_arg, ast.Str):
                            key_str = first_arg.s

                        if key_str and key_str in ("backend", "real_crypto_test_backend"):
                            if isinstance(second_arg, (ast.Constant, ast.NameConstant)):
                                val = getattr(second_arg, "value", None)
                                if val is not None:
                                    return False
                        elif key_str and key_str in CRITICAL_CERTIFICATION_FIELDS:
                            if isinstance(second_arg, (ast.Constant, ast.NameConstant)):
                                val = getattr(second_arg, "value", None)
                                if val is True or val in ("PASS", "SSH", "AUTHENTIC"):
                                    return False

        return True
    except Exception:
        return False


def get_git_head_sha(repo_path: Path = None) -> str:
    if repo_path is None:
        repo_path = ROOT_DIR
    try:
        res = subprocess.run(
            ["git", "-C", str(repo_path), "rev-parse", "HEAD"],
            capture_output=True,
            text=True,
            timeout=5.0
        )
        if res.returncode == 0:
            return res.stdout.strip()
    except Exception:
        pass
    return "UNKNOWN_SHA"


def check_git_worktree_clean(repo_path: Path) -> bool:
    if not repo_path.exists():
        return False
    try:
        res = subprocess.run(
            ["git", "-C", str(repo_path), "status", "--porcelain"],
            capture_output=True,
            text=True,
            timeout=5.0
        )
        if res.returncode == 0:
            return res.stdout.strip() == ""
    except Exception:
        pass
    return False


def verify_git_ancestor(ancestor_sha: str, descendant_sha: str, repo_path: Path = None) -> bool:
    if repo_path is None:
        repo_path = ROOT_DIR
    if not ancestor_sha or not descendant_sha or "PENDING" in ancestor_sha or "PENDING" in descendant_sha or "UNKNOWN" in ancestor_sha or "UNKNOWN" in descendant_sha:
        return False
    try:
        res = subprocess.run(
            ["git", "-C", str(repo_path), "merge-base", "--is-ancestor", ancestor_sha, descendant_sha],
            capture_output=True,
            text=True,
            timeout=5.0
        )
        return res.returncode == 0
    except Exception:
        return False





def generate_certification(
    implementation_sha: str = None,
    evidence_sha: str = None,
    certification_sha: str = None
) -> dict:
    reports_dir = ROOT_DIR / "reports"
    reports_dir.mkdir(parents=True, exist_ok=True)
    xml_report = reports_dir / "results_02_5.xml"
    basetemp = ROOT_DIR / "tmp_pytest"

    # Step 1: Export Fresh Certification Run ID and Started At timestamp
    certification_run_id = f"RUN_{uuid.uuid4().hex[:12].upper()}"
    certification_started_at = datetime.now(timezone.utc).isoformat()

    os.environ["CERTIFICATION_RUN_ID"] = certification_run_id
    os.environ["CERTIFICATION_STARTED_AT"] = certification_started_at

    # Delete stale crypto evidence file prior to test execution
    stale_crypto_evidence = reports_dir / "crypto_test_evidence.json"
    if stale_crypto_evidence.exists():
        stale_crypto_evidence.unlink()

    # Step 2: Execute Pytest Suite with Run ID exported
    pytest_res = subprocess.run(
        [
            sys.executable, "-m", "pytest", "tests/",
            f"--basetemp={basetemp}",
            f"--junitxml={xml_report}",
            "-q"
        ],
        cwd=str(ROOT_DIR),
        capture_output=True,
        text=True
    )

    tests_collected = 0
    tests_passed = 0
    tests_failed = 0
    tests_skipped = 0
    passed_test_names = set()

    if xml_report.exists():
        try:
            tree = ET.parse(xml_report)
            root = tree.getroot()

            for ts in root.iter("testsuite"):
                tests_collected += int(ts.attrib.get("tests", 0))
                tests_failed += int(ts.attrib.get("failures", 0)) + int(ts.attrib.get("errors", 0))
                tests_skipped += int(ts.attrib.get("skipped", 0))

            for tc in root.iter("testcase"):
                name = tc.attrib.get("name", "")
                has_failure = len(list(tc.iter("failure"))) > 0 or len(list(tc.iter("error"))) > 0
                if not has_failure:
                    tests_passed += 1
                    passed_test_names.add(name)
        except Exception as e:
            print(f"XML parse error: {e}")

    # Step 3: Derived Scanner Evidence
    scanner_res = scan_authentication_bypasses(root_dir=ROOT_DIR)
    hardcoded_signature_bypass_count = scanner_res.get("count", 999) if scanner_res.get("available") else 999
    no_critical_field_hardcoded = audit_certification_generator_ast()

    # Step 4: Derived Production Signer Manifest Validation
    signer_val = validate_production_signers(root_dir=ROOT_DIR)
    production_signer_count = signer_val.get("production_signer_count", 0)
    production_signers_validated = signer_val.get("production_signers_validated", 0)
    production_invalid_signer_count = signer_val.get("production_invalid_signer_count", 999)
    production_placeholder_signer_count = signer_val.get("production_placeholder_signer_count", 999)
    production_signer_manifest_valid = signer_val.get("production_signer_manifest_valid", False)
    production_signer_public_key_verified = signer_val.get("production_signer_public_key_verified", False)

    # Step 5: Fresh Crypto Test Evidence & Independent Generator Re-verification
    crypto_evidence_file = reports_dir / "crypto_test_evidence.json"
    crypto_evidence_fresh = False
    crypto_evidence_run_id_match = False
    real_crypto_test_backend = None
    real_git_verify_commit_success_count = 0
    real_git_verify_commit_failure_count = 0
    test_fingerprints = set()

    real_unsigned_commit_rejected = "test_real_unsigned_commit_rejected" in passed_test_names
    real_invalid_signature_rejected = "test_real_invalid_signature_rejected" in passed_test_names
    real_trusted_signer_accepted = "test_real_valid_trusted_signed_commit_accepted" in passed_test_names
    real_untrusted_signer_rejected = "test_real_valid_untrusted_signed_commit_rejected" in passed_test_names
    author_metadata_authorization_disabled = "test_author_spoof_cannot_authorize" in passed_test_names
    envelope_self_attestation_disabled = "test_envelope_self_attestation_cannot_authorize" in passed_test_names

    real_test_signed_sha = "UNKNOWN_SHA"
    real_test_unsigned_sha = "UNKNOWN_SHA"
    real_test_trusted_fp = "UNKNOWN_FP"
    real_test_untrusted_fp = "UNKNOWN_FP"

    if crypto_evidence_file.exists():
        try:
            evidence_data = json.loads(crypto_evidence_file.read_text(encoding="utf-8"))
            ev_run_id = evidence_data.get("certification_run_id")
            ev_gen_at = evidence_data.get("generated_at")
            real_crypto_test_backend = evidence_data.get("backend")

            if ev_run_id == certification_run_id:
                crypto_evidence_run_id_match = True
            if ev_gen_at and ev_gen_at >= certification_started_at:
                crypto_evidence_fresh = True

            cases = evidence_data.get("cases", {})
            for cname, cdata in cases.items():
                repo_p = Path(cdata.get("repo_path", ""))
                csha = cdata.get("commit_sha", "")
                fp = cdata.get("fingerprint")
                if fp:
                    test_fingerprints.add(fp)

                if cname == "trusted_signed":
                    real_test_signed_sha = csha
                    real_test_trusted_fp = fp or "UNKNOWN_FP"
                elif cname == "untrusted_signed":
                    real_test_untrusted_fp = fp or "UNKNOWN_FP"
                elif cname == "unsigned":
                    real_test_unsigned_sha = csha

                # Independent Generator git verify-commit re-verification!
                if repo_p.exists() and csha:
                    res_ver = subprocess.run(
                        ["git", "-C", str(repo_p), "verify-commit", csha],
                        capture_output=True,
                        text=True,
                        timeout=5.0
                    )
                    if res_ver.returncode == 0:
                        real_git_verify_commit_success_count += 1
                    else:
                        real_git_verify_commit_failure_count += 1
        except Exception as e:
            print(f"Error re-verifying crypto evidence: {e}")

    # Step 6: Test Key Isolation Computation
    prod_allowlist = getattr(settings, "PRODUCTION_TRUSTED_SIGNER_ALLOWLIST", set())
    test_key_count = len(test_fingerprints)
    production_key_count = len(prod_allowlist)
    test_production_intersection = test_fingerprints.intersection(prod_allowlist)
    test_production_key_intersection_count = len(test_production_intersection)
    test_keys_isolated_from_production = (test_production_key_intersection_count == 0)

    # Step 7: Execution Evidence Reconciliation
    exec_rec = reconcile_execution_evidence(root_dir=ROOT_DIR)
    execution_evidence_available = exec_rec["available"]
    execution_evidence_complete = exec_rec["complete"]
    execution_ledger_consistent = exec_rec["consistent"]
    execution_evidence_source_count = exec_rec["source_count"]
    executed_directive_count = exec_rec["executed_directive_count"]
    executed_directive_ids = exec_rec["executed_directive_ids"]
    mutating_directives_executed = exec_rec["mutating_directives_executed"]

    # Step 8: Direct Monitored Repository Cleanliness Observation
    oracle_root = settings.REGISTERED_PROJECTS.get("ORACLE-AI", {}).get("root_path", settings.WORKSPACE_ROOT / "Oracle")
    micro_root = settings.REGISTERED_PROJECTS.get("MICRO-MARKET-ORACLE", {}).get("root_path", settings.WORKSPACE_ROOT / "MICRO-MARKET-ORACLE")

    oracle_worktree_clean = check_git_worktree_clean(oracle_root)
    micro_worktree_clean = check_git_worktree_clean(micro_root)

    # Step 9: Process Observation
    proc_observer = ProcessObserver()
    live_process_instance_count, active_pids = proc_observer.get_active_control_plane_processes()

    declared_process_status = "UNKNOWN"
    cp_status_file = ROOT_DIR / "state" / "control_plane_status.json"
    if cp_status_file.exists():
        try:
            cp_data = json.loads(cp_status_file.read_text(encoding="utf-8"))
            declared_process_status = cp_data.get("status", "UNKNOWN")
        except Exception:
            pass

    # Step 10: Critical Security Gates Verification
    cg_provenance_integrity = "test_provenance_fields_present" in passed_test_names
    cg_remote_ancestry = "test_fail_closed_on_github_unavailable" in passed_test_names or "test_directive_commit_not_reachable_from_main_rejected" in passed_test_names
    cg_commit_signature = real_unsigned_commit_rejected and real_invalid_signature_rejected and envelope_self_attestation_disabled
    cg_trusted_signer = real_trusted_signer_accepted and real_untrusted_signer_rejected and author_metadata_authorization_disabled
    cg_payload_integrity = "test_commit_exists_but_directive_absent_rejected" in passed_test_names or "test_exact_committed_blob_authenticates" in passed_test_names
    cg_queue_durability = "test_accepted_queue_survives_restart" in passed_test_names and "test_queue_and_replay_ledger_consistent" in passed_test_names
    cg_ledger_integrity = "test_directive_ack_generated" in passed_test_names
    cg_state_consistency = "test_duplicate_submission_of_waiting_human_is_rejected" in passed_test_names
    cg_idempotency = "test_replay_directive_rejected" in passed_test_names and "test_replay_survives_restart" in passed_test_names
    cg_restart_recovery = "test_waiting_human_survives_restart" in passed_test_names and "test_accepted_item_not_lost_after_restart" in passed_test_names
    cg_waiting_human = "test_human_required_waiting_state" in passed_test_names and "test_waiting_human_survives_second_poll" in passed_test_names
    cg_toctou_revalidation = "test_toctou_revalidation_executes_auth_meta_branch" in passed_test_names
    cg_no_unauthorized_execution = "test_directive_never_executes_target_mutation" in passed_test_names

    crypto_metrics = {
        "real_unsigned_commit_rejected": real_unsigned_commit_rejected,
        "real_invalid_signature_rejected": real_invalid_signature_rejected,
        "real_trusted_signer_accepted": real_trusted_signer_accepted,
        "real_untrusted_signer_rejected": real_untrusted_signer_rejected,
        "author_metadata_authorization_disabled": author_metadata_authorization_disabled,
        "envelope_self_attestation_disabled": envelope_self_attestation_disabled,
        "real_git_verify_commit_success_count": real_git_verify_commit_success_count,
        "real_git_verify_commit_failure_count": real_git_verify_commit_failure_count
    }

    sec_gates = derive_security_gates(passed_test_names, crypto_metrics)

    queue_fsync_verified = sec_gates["queue_fsync_verified"]
    queue_restart_integrity_verified = sec_gates["queue_restart_integrity_verified"]
    queue_corruption_fail_closed = sec_gates["queue_corruption_fail_closed"]
    queue_record_readback_verified = sec_gates["queue_record_readback_verified"]
    toctou_revalidation_verified = sec_gates["toctou_revalidation_verified"]
    remote_fail_closed = sec_gates["remote_fail_closed"]
    strict_remote_ancestry = sec_gates["strict_remote_ancestry"]
    worktree_fallback = sec_gates["worktree_fallback"]
    real_crypto_backend_verified = validate_crypto_backend(real_crypto_test_backend)

    critical_gate_failure = not (
        cg_provenance_integrity and
        cg_remote_ancestry and
        cg_commit_signature and
        cg_trusted_signer and
        cg_payload_integrity and
        cg_queue_durability and
        cg_ledger_integrity and
        cg_state_consistency and
        cg_idempotency and
        cg_restart_recovery and
        cg_waiting_human and
        cg_toctou_revalidation and
        cg_no_unauthorized_execution and
        no_critical_field_hardcoded and
        production_signer_manifest_valid and
        production_signer_public_key_verified and
        crypto_evidence_fresh and
        crypto_evidence_run_id_match and
        test_keys_isolated_from_production and
        queue_fsync_verified and
        queue_restart_integrity_verified and
        queue_corruption_fail_closed and
        queue_record_readback_verified and
        remote_fail_closed and
        strict_remote_ancestry and
        not worktree_fallback and
        toctou_revalidation_verified and
        real_signature_verification_tested and
        real_crypto_backend_verified
    )

    # 4-Commit Provenance & Ancestry Resolution
    imp_sha = implementation_sha or get_git_head_sha()
    ev_sha = evidence_sha or "PENDING_COMMIT"
    cert_sha = certification_sha or "PENDING_COMMIT"
    remote_head_sha = get_git_head_sha()

    imp_ancestry_verified = verify_git_ancestor(imp_sha, ev_sha) if ev_sha != "PENDING_COMMIT" else True
    ev_ancestry_verified = verify_git_ancestor(ev_sha, cert_sha) if cert_sha != "PENDING_COMMIT" else True
    cert_ancestry_verified = verify_git_ancestor(cert_sha, remote_head_sha) if cert_sha != "PENDING_COMMIT" else True

    # Two-Phase Certification State Determination
    evidence_pending = (ev_sha == "PENDING_COMMIT" or cert_sha == "PENDING_COMMIT")

    strict_pass = (
        tests_collected >= 99 and
        tests_passed == tests_collected and
        tests_failed == 0 and
        hardcoded_signature_bypass_count == 0 and
        no_critical_field_hardcoded is True and
        production_signer_count >= 1 and
        production_signers_validated == production_signer_count and
        production_invalid_signer_count == 0 and
        production_placeholder_signer_count == 0 and
        production_signer_manifest_valid is True and
        production_signer_public_key_verified is True and
        crypto_evidence_fresh is True and
        crypto_evidence_run_id_match is True and
        real_crypto_backend_verified is True and
        real_git_verify_commit_success_count >= 2 and
        real_git_verify_commit_failure_count >= 2 and
        execution_evidence_available is True and
        execution_evidence_complete is True and
        execution_ledger_consistent is True and
        execution_evidence_source_count >= 3 and
        mutating_directives_executed == 0 and
        oracle_worktree_clean is True and
        micro_worktree_clean is True and
        live_process_instance_count <= 1 and
        critical_gate_failure is False and
        not evidence_pending
    )

    if evidence_pending and not critical_gate_failure and tests_failed == 0 and tests_passed >= 99:
        overall_result = "PENDING_EVIDENCE_COMMIT"
        control_status = "PENDING_EVIDENCE_COMMIT"
        control_03_authorized = False
    elif strict_pass:
        overall_result = "PASS"
        control_status = "PASS"
        control_03_authorized = True
    else:
        overall_result = "FAIL"
        control_status = "CORRECTION_REQUIRED"
        control_03_authorized = False

    review_1_functional = "PASS" if not critical_gate_failure and tests_failed == 0 else "CORRECTION_REQUIRED"
    review_2_adversarial = "PASS" if hardcoded_signature_bypass_count == 0 and test_keys_isolated_from_production and no_critical_field_hardcoded else "CORRECTION_REQUIRED"

    cert_data = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "stage": "CONTROL-02.5",
        "overall_result": overall_result,
        "certification_run_id": certification_run_id,
        "certification_started_at": certification_started_at,
        "implementation_commit_sha": imp_sha,
        "evidence_bundle_commit_sha": ev_sha,
        "certification_commit_sha": cert_sha,
        "remote_head_sha": remote_head_sha,
        "implementation_ancestry_verified": imp_ancestry_verified,
        "evidence_ancestry_verified": ev_ancestry_verified,
        "certification_ancestry_verified": cert_ancestry_verified,
        "tests_collected": tests_collected,
        "tests_passed": tests_passed,
        "tests_failed": tests_failed,
        "tests_skipped": tests_skipped,
        "live_process_instance_count": live_process_instance_count,
        "active_control_plane_pids": active_pids,
        "declared_process_status": declared_process_status,
        "require_commit_signature_verification": settings.REQUIRE_COMMIT_SIGNATURE_VERIFICATION,
        "hardcoded_signature_bypass_count": hardcoded_signature_bypass_count,
        "no_critical_certification_field_hardcoded": no_critical_field_hardcoded,
        "production_signer_count": production_signer_count,
        "production_signers_validated": production_signers_validated,
        "production_invalid_signer_count": production_invalid_signer_count,
        "production_placeholder_signer_count": production_placeholder_signer_count,
        "production_signer_manifest_valid": production_signer_manifest_valid,
        "production_signer_public_key_verified": production_signer_public_key_verified,
        "crypto_evidence_fresh": crypto_evidence_fresh,
        "crypto_evidence_run_id_match": crypto_evidence_run_id_match,
        "real_crypto_test_backend": real_crypto_test_backend,
        "real_crypto_backend_verified": real_crypto_backend_verified,
        "real_git_verify_commit_success_count": real_git_verify_commit_success_count,
        "real_git_verify_commit_failure_count": real_git_verify_commit_failure_count,
        "real_signature_verification_tested": real_signature_verification_tested,
        "real_unsigned_commit_rejected": real_unsigned_commit_rejected,
        "real_invalid_signature_rejected": real_invalid_signature_rejected,
        "real_trusted_signer_accepted": real_trusted_signer_accepted,
        "real_untrusted_signer_rejected": real_untrusted_signer_rejected,
        "real_test_signed_commit_sha": real_test_signed_sha,
        "real_test_unsigned_commit_sha": real_test_unsigned_sha,
        "real_test_trusted_key_fingerprint": real_test_trusted_fp,
        "real_test_untrusted_key_fingerprint": real_test_untrusted_fp,
        "test_key_count": test_key_count,
        "production_key_count": production_key_count,
        "test_production_key_intersection_count": test_production_key_intersection_count,
        "test_keys_isolated_from_production": test_keys_isolated_from_production,
        "author_metadata_authorization_disabled": author_metadata_authorization_disabled,
        "envelope_self_attestation_disabled": envelope_self_attestation_disabled,
        "remote_fail_closed": remote_fail_closed,
        "strict_remote_ancestry": strict_remote_ancestry,
        "worktree_fallback": worktree_fallback,
        "queue_fsync_verified": queue_fsync_verified,
        "queue_restart_integrity_verified": queue_restart_integrity_verified,
        "queue_corruption_fail_closed": queue_corruption_fail_closed,
        "queue_record_readback_verified": queue_record_readback_verified,
        "toctou_revalidation_verified": toctou_revalidation_verified,
        "execution_evidence_available": execution_evidence_available,
        "execution_evidence_complete": execution_evidence_complete,
        "execution_ledger_consistent": execution_ledger_consistent,
        "execution_evidence_source_count": execution_evidence_source_count,
        "executed_directive_count": executed_directive_count,
        "executed_directive_ids": executed_directive_ids,
        "mutating_directives_executed": mutating_directives_executed,
        "oracle_worktree_clean": oracle_worktree_clean,
        "micro_worktree_clean": micro_worktree_clean,
        "critical_gate_failure": critical_gate_failure,
        "review_1_functional": review_1_functional,
        "review_2_adversarial": review_2_adversarial,
        "control_02_5_status": control_status,
        "control_03_authorized": control_03_authorized
    }

    cert_file = reports_dir / "CONTROL_02_5_CERTIFICATION.json"
    with open(cert_file, "w", encoding="utf-8") as f:
        json.dump(cert_data, f, indent=2)

    print(f"CONTROL-02.5 Certification generated at {cert_file}")
    print(f"Overall Result: {overall_result} ({tests_passed}/{tests_collected} passed)")
    print(f"Certification Run ID: {certification_run_id}")
    print(f"Live Process Instance Count: {live_process_instance_count} (PIDs: {active_pids})")
    print(f"Declared Process Status: {declared_process_status}")
    return cert_data


def main():
    parser = argparse.ArgumentParser(description="Generate CONTROL-02.5 Certification Evidence")
    parser.add_argument("--implementation-sha", type=str, default=None, help="Exact Git commit SHA of implementation (C0)")
    parser.add_argument("--evidence-sha", type=str, default=None, help="Exact Git commit SHA of evidence bundle (E1)")
    parser.add_argument("--certification-sha", type=str, default=None, help="Exact Git commit SHA of certification artifact (C2)")
    args = parser.parse_args()

    generate_certification(
        implementation_sha=args.implementation_sha,
        evidence_sha=args.evidence_sha,
        certification_sha=args.certification_sha
    )


if __name__ == "__main__":
    main()
