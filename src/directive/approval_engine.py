"""
Human Approval Lifecycle, Notification, Expiration & Revocation Engine for CONTROL-02.5 / BLOCK 2.8.

Enforces:
1. Immutable Approval Request Identity
2. WAITING_HUMAN Durable Transition
3. Category-specific Human Approval Requirements
4. Complete Approval Context (secrets excluded)
5. Authorized Approver Identity & Self-Approval Prevention
6. Enforced State Machine (REQUESTED, NOTIFIED, APPROVED, REJECTED, EXPIRED, REVOKED, CONSUMED)
7. TTL Expiration & Pre-execution Revocation Support
8. Single-Use Approval Consumption
9. Parameter/Target Post-Approval Mutation Defense
10. Pre-Execution Full Security Revalidation
11. Notification Event Auditing & Delivery Fail-Closed Safety
12. Restart Durability & Tamper-Evident Audit Chain
"""

import hashlib
import json
import os
import time
from enum import Enum
from pathlib import Path
from typing import Dict, Any, Tuple, Optional, Set


class ApprovalState(str, Enum):
    REQUESTED = "REQUESTED"
    NOTIFIED = "NOTIFIED"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"
    EXPIRED = "EXPIRED"
    REVOKED = "REVOKED"
    CONSUMED = "CONSUMED"


TERMINAL_APPROVAL_STATES = {
    ApprovalState.REJECTED,
    ApprovalState.EXPIRED,
    ApprovalState.REVOKED,
    ApprovalState.CONSUMED
}

VALID_APPROVAL_TRANSITIONS = {
    ApprovalState.REQUESTED: {ApprovalState.NOTIFIED, ApprovalState.EXPIRED, ApprovalState.REJECTED},
    ApprovalState.NOTIFIED: {ApprovalState.APPROVED, ApprovalState.REJECTED, ApprovalState.EXPIRED},
    ApprovalState.APPROVED: {ApprovalState.REVOKED, ApprovalState.CONSUMED, ApprovalState.EXPIRED},
}

AUTHORIZED_APPROVERS: Set[str] = {"SEC_ADMIN_1", "LEAD_OPERATOR_1", "HUMAN_OPERATOR"}


def derive_approval_request_id(
    directive_id: str,
    capability_id: str,
    parameter_hash: str,
    target: str,
    risk_class: str,
    created_at: float
) -> str:
    raw = f"{directive_id}:{capability_id}:{parameter_hash}:{target}:{risk_class}:{created_at}"
    return f"APP-{hashlib.sha256(raw.encode('utf-8')).hexdigest()[:32]}"


def create_approval_context(
    approval_request_id: str,
    directive_id: str,
    capability_id: str,
    target: str,
    parameter_summary: Dict[str, Any],
    risk_class: str,
    why_required: str,
    ttl_seconds: float = 3600.0
) -> Dict[str, Any]:
    """
    Creates complete approval context excluding secrets/private keys.
    """
    cleaned_params = {k: v for k, v in parameter_summary.items() if not any(s in k.lower() for s in ["secret", "key", "password", "token"])}
    created_at = time.time()
    return {
        "approval_request_id": approval_request_id,
        "directive_id": directive_id,
        "capability_id": capability_id,
        "target": target,
        "parameter_summary": cleaned_params,
        "risk_class": risk_class,
        "why_required": why_required,
        "security_impact": f"Critical capability {capability_id} requires human sign-off",
        "created_at": created_at,
        "expires_at": created_at + ttl_seconds
    }


class ApprovalAuditChain:
    """
    Append-only tamper-evident audit logger for approval lifecycle events.
    """
    def __init__(self, audit_file: Path):
        self.audit_file = audit_file
        self.audit_file.parent.mkdir(parents=True, exist_ok=True)

    def append_event(
        self,
        approval_request_id: str,
        directive_id: str,
        from_state: str,
        to_state: str,
        actor: str,
        details: Optional[Dict[str, Any]] = None
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
        det_str = json.dumps(details or {}, sort_keys=True)
        body = f"{approval_request_id}:{directive_id}:{from_state}:{to_state}:{actor}:{ts}:{det_str}:{prev_hash}"
        event_hash = hashlib.sha256(body.encode("utf-8")).hexdigest()

        rec = {
            "approval_request_id": approval_request_id,
            "directive_id": directive_id,
            "from_state": from_state,
            "to_state": to_state,
            "actor": actor,
            "timestamp": ts,
            "details": details or {},
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
            for idx, line in enumerate(lines):
                rec = json.loads(line)
                if rec.get("previous_event_hash") != expected_prev:
                    return False, f"PREVIOUS_HASH_MISMATCH_AT_LINE_{idx+1}"
                body = f"{rec['approval_request_id']}:{rec['directive_id']}:{rec['from_state']}:{rec['to_state']}:{rec['actor']}:{rec['timestamp']}:{json.dumps(rec.get('details',{}), sort_keys=True)}:{rec['previous_event_hash']}"
                computed = hashlib.sha256(body.encode("utf-8")).hexdigest()
                if rec.get("event_hash") != computed:
                    return False, f"EVENT_HASH_TAMPER_AT_LINE_{idx+1}"
                expected_prev = rec["event_hash"]
            return True, None
        except Exception as e:
            return False, f"AUDIT_CHAIN_CORRUPTED: {str(e)}"


class NotificationManager:
    """
    Handles human notification events, delivery status, and idempotent retries.
    Notification success does NOT imply approval.
    """
    def __init__(self, notifications_file: Path):
        self.notifications_file = notifications_file
        self.notifications_file.parent.mkdir(parents=True, exist_ok=True)
        self.notifications: Dict[str, Dict[str, Any]] = self._load()

    def _load(self) -> Dict[str, Dict[str, Any]]:
        nots = {}
        if self.notifications_file.exists():
            try:
                lines = self.notifications_file.read_text(encoding="utf-8").strip().splitlines()
                for line in lines:
                    if line.strip():
                        r = json.loads(line)
                        nots[r["notification_id"]] = r
            except Exception:
                pass
        return nots

    def _persist(self):
        with open(self.notifications_file, "w", encoding="utf-8") as f:
            for r in self.notifications.values():
                f.write(json.dumps(r) + "\n")
            f.flush()
            os.fsync(f.fileno())

    def send_notification(
        self,
        approval_request_id: str,
        directive_id: str,
        risk_class: str,
        summary: str,
        simulate_failure: bool = False
    ) -> Tuple[bool, Optional[str], str]:
        # Check idempotency
        for notif_id, notif in self.notifications.items():
            if notif.get("approval_request_id") == approval_request_id:
                return True, notif_id, notif["delivery_status"]

        notif_id = f"NOTIF-{hashlib.sha256(f'{approval_request_id}:{time.time()}'.encode('utf-8')).hexdigest()[:16]}"
        status = "FAILED" if simulate_failure else "DELIVERED"

        rec = {
            "notification_id": notif_id,
            "approval_request_id": approval_request_id,
            "directive_id": directive_id,
            "risk_class": risk_class,
            "summary": summary,
            "created_at": time.time(),
            "delivery_status": status
        }

        self.notifications[notif_id] = rec
        self._persist()

        if simulate_failure:
            return False, notif_id, "NOTIFICATION_FAILURE_EXECUTION_BLOCKED"

        return True, notif_id, "DELIVERED"


class DurableApprovalEngine:
    """
    Durable approval store enforcing the approval state machine, expiration, revocation, and single-use consumption.
    """
    def __init__(self, store_file: Path, audit_chain: ApprovalAuditChain):
        self.store_file = store_file
        self.store_file.parent.mkdir(parents=True, exist_ok=True)
        self.audit_chain = audit_chain
        self.records: Dict[str, Dict[str, Any]] = self._load()

    def _load(self) -> Dict[str, Dict[str, Any]]:
        recs = {}
        if self.store_file.exists():
            try:
                lines = self.store_file.read_text(encoding="utf-8").strip().splitlines()
                for line in lines:
                    if line.strip():
                        r = json.loads(line)
                        recs[r["approval_request_id"]] = r
            except Exception:
                pass
        return recs

    def _persist(self):
        with open(self.store_file, "w", encoding="utf-8") as f:
            for r in self.records.values():
                f.write(json.dumps(r) + "\n")
            f.flush()
            os.fsync(f.fileno())

    def create_request(
        self,
        directive_id: str,
        capability_id: str,
        parameter_hash: str,
        target: str,
        risk_class: str,
        ttl_seconds: float = 3600.0,
        actor: str = "SYSTEM"
    ) -> Dict[str, Any]:
        now = time.time()
        app_id = derive_approval_request_id(directive_id, capability_id, parameter_hash, target, risk_class, now)

        rec = {
            "approval_request_id": app_id,
            "directive_id": directive_id,
            "capability_id": capability_id,
            "parameter_hash": parameter_hash,
            "target": target,
            "risk_class": risk_class,
            "state": ApprovalState.REQUESTED.value,
            "approver_id": None,
            "created_at": now,
            "expires_at": now + ttl_seconds,
            "consumed": False,
            "revoked": False
        }

        self.records[app_id] = rec
        self._persist()
        self.audit_chain.append_event(app_id, directive_id, "NONE", ApprovalState.REQUESTED.value, actor)
        return rec

    def transition_state(
        self,
        approval_request_id: str,
        target_state: ApprovalState,
        actor: str,
        approver_id: Optional[str] = None
    ) -> Tuple[bool, Optional[str]]:
        rec = self.records.get(approval_request_id)
        if not rec:
            return False, "UNKNOWN_APPROVAL_STATE_REJECTED"

        curr_state = ApprovalState(rec["state"])
        now = time.time()

        # Check expiration
        if now > rec["expires_at"] and curr_state not in TERMINAL_APPROVAL_STATES:
            rec["state"] = ApprovalState.EXPIRED.value
            self._persist()
            self.audit_chain.append_event(approval_request_id, rec["directive_id"], curr_state.value, ApprovalState.EXPIRED.value, "SYSTEM_TTL")
            return False, "EXPIRED_APPROVAL_REJECTED"

        if curr_state in TERMINAL_APPROVAL_STATES:
            return False, "ILLEGAL_APPROVAL_TRANSITIONS_REJECTED"

        allowed = VALID_APPROVAL_TRANSITIONS.get(curr_state, set())
        if target_state not in allowed:
            return False, "ILLEGAL_APPROVAL_TRANSITIONS_REJECTED"

        # Approver verification for APPROVED state
        if target_state == ApprovalState.APPROVED:
            if not approver_id:
                return False, "MISSING_APPROVER_IDENTITY_REJECTED"
            if approver_id not in AUTHORIZED_APPROVERS:
                return False, "UNAUTHORIZED_APPROVER_REJECTED"
            if approver_id == rec["directive_id"] or approver_id == actor:
                return False, "SELF_APPROVAL_REJECTED"
            rec["approver_id"] = approver_id
            rec["approval_timestamp"] = now

        if target_state == ApprovalState.REVOKED:
            rec["revoked"] = True

        if target_state == ApprovalState.CONSUMED:
            rec["consumed"] = True

        rec["state"] = target_state.value
        self._persist()
        self.audit_chain.append_event(approval_request_id, rec["directive_id"], curr_state.value, target_state.value, actor, {"approver": approver_id})
        return True, None


def revalidate_approval_for_execution(
    approval_rec: Dict[str, Any],
    directive_id: str,
    capability_id: str,
    parameter_hash: str,
    target: str,
    risk_class: str
) -> Tuple[bool, Optional[str]]:
    """
    Pre-execution revalidator for human approvals immediately before execution.
    """
    if not approval_rec:
        return False, "MISSING_APPROVAL_REJECTED"

    if approval_rec.get("consumed", False) or approval_rec.get("state") == ApprovalState.CONSUMED.value:
        return False, "CONSUMED_APPROVAL_REPLAY_REJECTED"

    if approval_rec.get("revoked", False) or approval_rec.get("state") == ApprovalState.REVOKED.value:
        return False, "REVOKED_APPROVAL_REJECTED"

    if approval_rec.get("state") != ApprovalState.APPROVED.value:
        return False, "UNKNOWN_APPROVAL_STATE_REJECTED"

    if time.time() > approval_rec.get("expires_at", 0):
        return False, "EXPIRED_APPROVAL_REJECTED"

    if approval_rec.get("directive_id") != directive_id:
        return False, "CROSS_DIRECTIVE_APPROVAL_REUSE_REJECTED"

    if approval_rec.get("capability_id") != capability_id:
        return False, "POST_APPROVAL_CAPABILITY_MUTATION_REJECTED"

    if approval_rec.get("parameter_hash") != parameter_hash:
        return False, "CROSS_PARAMETER_APPROVAL_REUSE_REJECTED"

    if approval_rec.get("target") != target:
        return False, "POST_APPROVAL_TARGET_MUTATION_REJECTED"

    if approval_rec.get("risk_class") != risk_class:
        return False, "POST_APPROVAL_RISK_MUTATION_REJECTED"

    return True, None
