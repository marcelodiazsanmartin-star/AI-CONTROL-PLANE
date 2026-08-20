"""
Execution Authorization, Capability Boundary & Command Policy Engine for CONTROL-02.5 / BLOCK 2.7.

Enforces:
1. Explicit Closed Capability Allowlist (Deny-by-default, No wildcards)
2. Strict Authentication != Authorization Separation
3. Structured Operation Dispatch & Shell Injection Protection
4. Strict Parameter Schema & Target Scope Boundary Enforcement
5. Filesystem Canonical Path Verification
6. Least Privilege & Risk Classification (Read-Only side-effect analysis)
7. Human Approval Boundary for Critical Capabilities
8. Short-lived Immutable Execution Authorization Tokens & Tamper-Evident Audit Trail
"""

import hashlib
import json
import os
import re
import time
from enum import Enum
from pathlib import Path
from typing import Dict, Any, Tuple, Optional, Set, List

from src.directive.approval_engine import revalidate_approval_for_execution


class RiskClass(str, Enum):
    READ_ONLY = "READ_ONLY"
    LOW_RISK_WRITE = "LOW_RISK_WRITE"
    CONTROLLED_WRITE = "CONTROLLED_WRITE"
    CRITICAL = "CRITICAL"


# Closed Allowlist of certified Capabilities
CAPABILITY_ALLOWLIST: Dict[str, Dict[str, Any]] = {
    "CAP-GIT-STATUS": {
        "directive_type": "READ_ONLY_STATUS",
        "operation": "git_status",
        "allowed_targets": {"AI-CONTROL-PLANE", "Oracle", "Micro"},
        "risk_class": RiskClass.READ_ONLY,
        "human_approval_required": False,
        "parameters_schema": {}
    },
    "CAP-GIT-FETCH": {
        "directive_type": "READ_ONLY_FETCH",
        "operation": "git_fetch",
        "allowed_targets": {"AI-CONTROL-PLANE"},
        "risk_class": RiskClass.READ_ONLY,
        "human_approval_required": False,
        "parameters_schema": {"remote": str}
    },
    "CAP-QUEUE-RECONCILE": {
        "directive_type": "LOW_RISK_RECONCILE",
        "operation": "queue_reconcile",
        "allowed_targets": {"AI-CONTROL-PLANE"},
        "risk_class": RiskClass.LOW_RISK_WRITE,
        "human_approval_required": False,
        "parameters_schema": {"queue_file": str}
    },
    "CAP-RISK-LIMIT-UPDATE": {
        "directive_type": "CRITICAL_CONFIG_UPDATE",
        "operation": "update_risk_limit",
        "allowed_targets": {"AI-CONTROL-PLANE"},
        "risk_class": RiskClass.CRITICAL,
        "human_approval_required": True,
        "parameters_schema": {"max_limit": int, "reason": str}
    }
}


FORBIDDEN_WILDCARDS = {"*", "ANY", "ALL", "shell", "arbitrary_command", "exec", "eval"}
SHELL_METACHARS_PATTERN = re.compile(r"[;&|`$><()\\]")
FORBIDDEN_PRIVILEGE_KEYWORDS = {
    "sudo", "admin", "root", "chmod", "chown", "password", "secret",
    "disable_security", "override_governance", "bypass_policy"
}


def sanitize_and_resolve_path(raw_path: str, authorized_root: Path) -> Tuple[bool, Optional[Path], Optional[str]]:
    """
    Validates and resolves canonical filesystem paths, rejecting path traversal and out-of-scope paths.
    """
    if not raw_path or not isinstance(raw_path, str):
        return False, None, "INVALID_PATH_TYPE"

    if ".." in raw_path or SHELL_METACHARS_PATTERN.search(raw_path):
        return False, None, "PATH_TRAVERSAL_REJECTED"

    try:
        auth_root_resolved = authorized_root.resolve()
        requested_path = (authorized_root / raw_path).resolve()

        if not str(requested_path).startswith(str(auth_root_resolved)):
            return False, None, "ABSOLUTE_OUT_OF_SCOPE_PATH_REJECTED"

        return True, requested_path, None
    except Exception as e:
        return False, None, f"PATH_RESOLUTION_ERROR: {str(e)}"


def derive_risk_class(capability_id: str, self_declared_risk: Optional[str] = None) -> Tuple[RiskClass, bool]:
    """
    Derives risk classification deterministically from capability policy.
    Rejects self-declared risk downgrades.
    """
    cap_info = CAPABILITY_ALLOWLIST.get(capability_id)
    if not cap_info:
        return RiskClass.CRITICAL, False

    policy_risk = cap_info["risk_class"]
    bypass_attempted = False

    if self_declared_risk:
        if self_declared_risk != policy_risk.value:
            bypass_attempted = True

    return policy_risk, not bypass_attempted


class ExecutionAuthorizationToken:
    """
    Short-lived, immutable execution authorization token bound to directive, parameters, and risk.
    """
    def __init__(
        self,
        directive_id: str,
        capability_id: str,
        parameter_hash: str,
        target: str,
        risk_class: RiskClass,
        approval_id: Optional[str] = None
    ):
        self.directive_id = directive_id
        self.capability_id = capability_id
        self.parameter_hash = parameter_hash
        self.target = target
        self.risk_class = risk_class.value
        self.approval_id = approval_id
        self.created_at = time.time()
        self.token_hash = self._compute_token_hash()

    def _compute_token_hash(self) -> str:
        raw = f"{self.directive_id}:{self.capability_id}:{self.parameter_hash}:{self.target}:{self.risk_class}:{self.approval_id}:{self.created_at}"
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()

    def is_valid(self, directive_id: str, params_hash: str, max_age_seconds: float = 300.0) -> bool:
        if self.directive_id != directive_id or self.parameter_hash != params_hash:
            return False
        if (time.time() - self.created_at) > max_age_seconds:
            return False
        return True


class AuthorizationAuditTrail:
    """
    Append-only tamper-evident audit logger for capability execution authorization decisions.
    """
    def __init__(self, audit_file: Path):
        self.audit_file = audit_file
        self.audit_file.parent.mkdir(parents=True, exist_ok=True)

    def append_decision(
        self,
        directive_id: str,
        capability_id: str,
        requested_target: str,
        parameter_hash: str,
        derived_risk_class: str,
        human_approval_required: bool,
        approval_id: Optional[str],
        authorized: bool,
        rejection_reason: Optional[str]
    ) -> Dict[str, Any]:
        prev_hash = "0000000000000000000000000000000000000000000000000000000000000000"
        if self.audit_file.exists():
            try:
                lines = self.audit_file.read_text(encoding="utf-8").strip().splitlines()
                if lines:
                    prev_hash = json.loads(lines[-1]).get("event_hash", prev_hash)
            except Exception:
                pass

        ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        body = f"{directive_id}:{capability_id}:{requested_target}:{parameter_hash}:{derived_risk_class}:{human_approval_required}:{approval_id}:{authorized}:{rejection_reason}:{ts}:{prev_hash}"
        event_hash = hashlib.sha256(body.encode("utf-8")).hexdigest()

        rec = {
            "directive_id": directive_id,
            "capability_id": capability_id,
            "requested_target": requested_target,
            "parameter_hash": parameter_hash,
            "derived_risk_class": derived_risk_class,
            "human_approval_required": human_approval_required,
            "approval_id": approval_id,
            "authorized": authorized,
            "rejection_reason": rejection_reason,
            "timestamp": ts,
            "previous_event_hash": prev_hash,
            "event_hash": event_hash
        }

        with open(self.audit_file, "a", encoding="utf-8") as f:
            f.write(json.dumps(rec) + "\n")
            f.flush()
            os.fsync(f.fileno())

        return rec

    def verify_integrity(self) -> Tuple[bool, Optional[str]]:
        if not self.audit_file.exists():
            return True, None
        try:
            lines = self.audit_file.read_text(encoding="utf-8").strip().splitlines()
            expected_prev = "0000000000000000000000000000000000000000000000000000000000000000"
            for line in lines:
                if not line.strip():
                    continue
                rec = json.loads(line)
                if rec.get("previous_event_hash") != expected_prev:
                    return False, "PREVIOUS_EVENT_HASH_TAMPER_DETECTED"
                body = f"{rec['directive_id']}:{rec['capability_id']}:{rec['requested_target']}:{rec['parameter_hash']}:{rec['derived_risk_class']}:{rec['human_approval_required']}:{rec['approval_id']}:{rec['authorized']}:{rec['rejection_reason']}:{rec['timestamp']}:{rec['previous_event_hash']}"
                expected_hash = hashlib.sha256(body.encode("utf-8")).hexdigest()
                if rec.get("event_hash") != expected_hash:
                    return False, "EVENT_HASH_TAMPER_DETECTED"
                expected_prev = rec.get("event_hash")
            return True, None
        except Exception as e:
            return False, f"VERIFICATION_ERROR: {str(e)}"


def evaluate_execution_authorization(
    directive_id: str,
    capability_id: str,
    parameters: Dict[str, Any],
    requested_target: str,
    authorized_workspace_root: Path,
    human_approval_data: Optional[Dict[str, Any]] = None,
    self_declared_risk: Optional[str] = None,
    audit_trail: Optional[AuthorizationAuditTrail] = None
) -> Tuple[bool, Optional[ExecutionAuthorizationToken], Optional[str]]:
    """
    Evaluates execution authorization for an authenticated directive against strict capability policy.
    Returns (authorized: bool, token: Optional[ExecutionAuthorizationToken], reason: Optional[str]).
    """
    # Deny-by-default check
    if not directive_id or not capability_id:
        return False, None, "DENY_BY_DEFAULT_MISSING_IDENTIFIER"

    # Capability Allowlist Verification
    if capability_id in FORBIDDEN_WILDCARDS:
        return False, None, "WILDCARD_CAPABILITY_REJECTED"

    cap_info = CAPABILITY_ALLOWLIST.get(capability_id)
    if not cap_info:
        return False, None, "UNKNOWN_CAPABILITY_REJECTED"

    # Parameter Schema & Shell Injection Protection
    schema = cap_info["parameters_schema"]
    param_str = json.dumps(parameters, sort_keys=True)
    if len(param_str) > 65536:
        return False, None, "OVERSIZED_INPUT_REJECTED"

    for param_name, value in parameters.items():
        if param_name not in schema:
            return False, None, "UNKNOWN_PARAMETER_REJECTED"
        expected_type = schema[param_name]
        if not isinstance(value, expected_type):
            return False, None, "INVALID_PARAMETER_TYPE_REJECTED"

        # Check shell metacharacters, forbidden privilege keywords, and unauthorized remotes
        if isinstance(value, str):
            if SHELL_METACHARS_PATTERN.search(value):
                return False, None, "SHELL_INJECTION_REJECTED"
            if ".." in value:
                return False, None, "PATH_TRAVERSAL_REJECTED"
            for kw in FORBIDDEN_PRIVILEGE_KEYWORDS:
                if kw in value.lower():
                    return False, None, "PRIVILEGE_ESCALATION_REJECTED"
            if param_name == "remote":
                if not (value == "origin" or value == "upstream" or value.startswith("refs/heads/")):
                    return False, None, "UNAUTHORIZED_REMOTE_REJECTED"

    # Check for missing required parameters
    for req_param in schema.keys():
        if req_param not in parameters:
            return False, None, "STRICT_PARAMETER_SCHEMA_ENFORCED"

    # Target Scope Boundary
    allowed_targets = cap_info["allowed_targets"]
    if requested_target not in allowed_targets:
        return False, None, "OUT_OF_SCOPE_TARGET_REJECTED"

    # Risk Classification & Self-Downgrade Prevention
    derived_risk, risk_valid = derive_risk_class(capability_id, self_declared_risk)
    if not risk_valid:
        return False, None, "SELF_DECLARED_LOW_RISK_BYPASS_REJECTED"

    # Human Approval Boundary for Critical Actions
    approval_id = None
    if cap_info["human_approval_required"] or derived_risk == RiskClass.CRITICAL:
        if not human_approval_data:
            return False, None, "MISSING_HUMAN_APPROVAL_BLOCKED"
        
        # Verify approval is bound to exact directive & parameters
        computed_param_hash = hashlib.sha256(param_str.encode("utf-8")).hexdigest()
        rec = human_approval_data.get("rec")
        if rec:
            ok_reval, err_reval = revalidate_approval_for_execution(
                rec, directive_id, capability_id, computed_param_hash, requested_target, derived_risk.value
            )
            if not ok_reval:
                return False, None, err_reval

        if human_approval_data.get("directive_id") != directive_id:
            return False, None, "APPROVAL_SCOPE_BOUND_TO_ACTION"

        if human_approval_data.get("parameter_hash") != computed_param_hash:
            return False, None, "APPROVAL_SCOPE_BOUND_TO_PARAMETERS"

        approval_id = human_approval_data.get("approval_id")

    param_hash = hashlib.sha256(param_str.encode("utf-8")).hexdigest()
    token = ExecutionAuthorizationToken(
        directive_id, capability_id, param_hash, requested_target, derived_risk, approval_id
    )

    if audit_trail:
        audit_trail.append_decision(
            directive_id, capability_id, requested_target, param_hash, derived_risk.value,
            cap_info["human_approval_required"], approval_id, True, None
        )

    return True, token, None
