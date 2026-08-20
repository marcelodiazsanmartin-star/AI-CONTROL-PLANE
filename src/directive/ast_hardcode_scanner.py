"""
AST Static Hardcode Scanner Engine for CONTROL-02.5 / BLOCK 2.10R.

Scans Python source files across the codebase to detect prohibited unconditional
True assignments to critical security, governance, and certification variables/fields.
"""

import ast
from pathlib import Path
from typing import Dict, Any, List, Set, Optional

CRITICAL_SECURITY_VARIABLES: Set[str] = {
    "trusted_head_signature_valid",
    "implementation_reachable_from_trusted_head",
    "backend_init_failure_rejected",
    "invalid_key_rejected",
    "unauthorized_key_rejected",
    "crypto_failure_rejected",
    "indeterminate_result_rejected",
    "valid_signature_exact_target_accepted",
    "modified_target_rejected",
    "wrong_commit_rejected",
    "wrong_key_rejected",
    "force_push_detected_and_rejected",
    "history_rewrite_rejected",
    "authenticated_commit_unreachable_rejected",
    "payload_changed_after_auth_rejected",
    "blob_changed_after_auth_rejected",
    "commit_substitution_rejected",
    "key_revoked_before_execution_rejected",
    "stale_authorization_rejected",
    "remote_fetch_failure_rejected",
    "remote_head_unresolved_rejected",
    "ancestry_indeterminate_rejected",
    "signature_revalidation_failure_rejected",
    "payload_revalidation_failure_rejected",
    "indeterminate_pre_exec_state_rejected",
    "strict_pass",
    "control_02_5_certified_pass",
    "control_02_5_status",
    "control_03_authorized",
    "remote_fail_closed",
    "strict_remote_ancestry",
    "no_critical_certification_field_hardcoded",
    "queue_fsync_verified",
    "queue_restart_integrity_verified",
    "queue_corruption_fail_closed",
    "queue_record_readback_verified",
    "real_signature_verification_tested",
    "real_crypto_test_backend"
}

PASS_VARIABLES: Set[str] = {
    "control_02_5_certified_pass",
    "control_02_5_status",
    "control_03_authorized"
}

STRICT_PASS_VARIABLES: Set[str] = {
    "strict_pass"
}


def scan_ast_for_critical_hardcodes(
    file_paths: List[Path]
) -> Dict[str, Any]:
    total_hardcoded_true = 0
    direct_pass_count = 0
    direct_strict_pass_count = 0
    direct_gate_override_count = 0
    detected_violations: List[Dict[str, Any]] = []

    for fpath in file_paths:
        if not fpath.exists():
            continue
        try:
            tree = ast.parse(fpath.read_text(encoding="utf-8"), filename=str(fpath))
            for node in ast.walk(tree):
                if isinstance(node, ast.Assign):
                    for target in node.targets:
                        var_name = None
                        if isinstance(target, ast.Name):
                            var_name = target.id
                        elif isinstance(target, ast.Attribute):
                            var_name = target.attr

                        if var_name in CRITICAL_SECURITY_VARIABLES:
                            val_is_prohibited = False
                            if isinstance(node.value, ast.Constant):
                                if node.value.value is True or node.value.value == "SSH":
                                    val_is_prohibited = True
                            elif isinstance(node.value, ast.Call):
                                for default_arg in node.value.args[1:] + [kw.value for kw in node.value.keywords if kw.arg == "default"]:
                                    if isinstance(default_arg, ast.Constant) and default_arg.value == "SSH":
                                        val_is_prohibited = True

                            if val_is_prohibited:
                                total_hardcoded_true += 1
                                if var_name in PASS_VARIABLES:
                                    direct_pass_count += 1
                                if var_name in STRICT_PASS_VARIABLES:
                                    direct_strict_pass_count += 1
                                direct_gate_override_count += 1
                                detected_violations.append({
                                    "file": str(fpath),
                                    "line": node.lineno,
                                    "variable": var_name,
                                    "type": "PROHIBITED_HARDCODE"
                                })

                if isinstance(node, ast.Dict):
                    for key, val in zip(node.keys, node.values):
                        key_str = None
                        if isinstance(key, ast.Constant) and isinstance(key.value, str):
                            key_str = key.value
                        if key_str and key_str in CRITICAL_SECURITY_VARIABLES:
                            val_is_prohibited = False
                            if isinstance(val, ast.Constant) and val.value is True:
                                val_is_prohibited = True
                            if val_is_prohibited:
                                total_hardcoded_true += 1
                                if key_str in PASS_VARIABLES:
                                    direct_pass_count += 1
                                if key_str in STRICT_PASS_VARIABLES:
                                    direct_strict_pass_count += 1
                                direct_gate_override_count += 1
                                detected_violations.append({
                                    "file": str(fpath),
                                    "line": node.lineno,
                                    "key": key_str,
                                    "type": "DICT_LITERAL_PROHIBITED"
                                })

        except Exception as e:
            detected_violations.append({
                "file": str(fpath),
                "error": str(e),
                "type": "AST_PARSE_ERROR"
            })

    return {
        "critical_boolean_hardcode_scan_complete": True,
        "critical_hardcoded_true_count": total_hardcoded_true,
        "direct_pass_assignment_count": direct_pass_count,
        "direct_strict_pass_assignment_count": direct_strict_pass_count,
        "direct_gate_override_count": direct_gate_override_count,
        "no_hardcoded_critical_pass": (total_hardcoded_true == 0),
        "violations": detected_violations
    }
