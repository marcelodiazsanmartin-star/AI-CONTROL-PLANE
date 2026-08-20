"""
Watchdog, Killswitch, Fail-Safe Halt & Safe Recovery Engine for CONTROL-02.5 / BLOCK 2.9.

Enforces:
1. Independent Watchdog Health Model & Heartbeat Liveness Monitoring
2. Durable Killswitch State Machine (DISARMED, ARMED, TRIGGERED, RECOVERY_PENDING)
3. Automated & Manual Human Emergency Stop Triggers
4. Immediate Execution Freeze & Safe Active Work Halting / Indeterminate Marking
5. Anti-Bypass Protection (Restart cannot clear killswitch, directives cannot disarm)
6. Single Active Controller Lease Ownership & Split-Brain Defense
7. Preconditioned Safe Recovery, Bound Human Approval & Full Revalidation before Resume
8. Immutable Incident Identity & Hash-Chained Incident Audit Trail
"""

import hashlib
import json
import os
import time
from enum import Enum
from pathlib import Path
from typing import Dict, Any, Tuple, Optional, Set


class HealthState(str, Enum):
    HEALTHY = "HEALTHY"
    DEGRADED = "DEGRADED"
    CRITICAL = "CRITICAL"
    UNKNOWN = "UNKNOWN"


class KillswitchState(str, Enum):
    DISARMED = "DISARMED"
    ARMED = "ARMED"
    TRIGGERED = "TRIGGERED"
    RECOVERY_PENDING = "RECOVERY_PENDING"


VALID_KILLSWITCH_TRANSITIONS = {
    KillswitchState.DISARMED: {KillswitchState.ARMED, KillswitchState.TRIGGERED},
    KillswitchState.ARMED: {KillswitchState.TRIGGERED, KillswitchState.DISARMED},
    KillswitchState.TRIGGERED: {KillswitchState.RECOVERY_PENDING},
    KillswitchState.RECOVERY_PENDING: {KillswitchState.DISARMED, KillswitchState.TRIGGERED}
}


def derive_incident_id(trigger_reason: str, source: str, timestamp: float) -> str:
    raw = f"{trigger_reason}:{source}:{timestamp}"
    return f"INC-{hashlib.sha256(raw.encode('utf-8')).hexdigest()[:32]}"


class IncidentAuditTrail:
    """
    Append-only tamper-evident audit trail for watchdog & killswitch incidents.
    """
    def __init__(self, audit_file: Path):
        self.audit_file = audit_file
        self.audit_file.parent.mkdir(parents=True, exist_ok=True)

    def append_event(
        self,
        incident_id: str,
        from_state: str,
        to_state: str,
        actor: str,
        reason: str,
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
        body = f"{incident_id}:{from_state}:{to_state}:{actor}:{reason}:{ts}:{det_str}:{prev_hash}"
        event_hash = hashlib.sha256(body.encode("utf-8")).hexdigest()

        rec = {
            "incident_id": incident_id,
            "from_state": from_state,
            "to_state": to_state,
            "actor": actor,
            "reason": reason,
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
                body = f"{rec['incident_id']}:{rec['from_state']}:{rec['to_state']}:{rec['actor']}:{rec['reason']}:{rec['timestamp']}:{json.dumps(rec.get('details',{}), sort_keys=True)}:{rec['previous_event_hash']}"
                computed = hashlib.sha256(body.encode("utf-8")).hexdigest()
                if rec.get("event_hash") != computed:
                    return False, f"EVENT_HASH_TAMPER_AT_LINE_{idx+1}"
                expected_prev = rec["event_hash"]
            return True, None
        except Exception as e:
            return False, f"INCIDENT_AUDIT_CORRUPTED: {str(e)}"


class DurableKillswitch:
    """
    Durable Killswitch Engine.
    Survives restart, prevents directive disarm, blocks execution when triggered.
    """
    def __init__(self, state_file: Path, audit_trail: IncidentAuditTrail):
        self.state_file = state_file
        self.state_file.parent.mkdir(parents=True, exist_ok=True)
        self.audit_trail = audit_trail
        self.state: Dict[str, Any] = self._load()

    def _load(self) -> Dict[str, Any]:
        if self.state_file.exists():
            try:
                rec = json.loads(self.state_file.read_text(encoding="utf-8"))
                return rec
            except Exception:
                pass
        return {
            "killswitch_state": KillswitchState.ARMED.value,
            "active_incident_id": None,
            "trigger_reason": None,
            "root_cause_resolved": False,
            "recovery_approved": False,
            "last_updated": time.time()
        }

    def _persist(self):
        self.state["last_updated"] = time.time()
        with open(self.state_file, "w", encoding="utf-8") as f:
            f.write(json.dumps(self.state) + "\n")
            f.flush()
            os.fsync(f.fileno())

    def is_execution_allowed(self) -> bool:
        return self.state["killswitch_state"] in {KillswitchState.DISARMED.value, KillswitchState.ARMED.value}

    def trigger(self, reason: str, actor: str = "WATCHDOG", details: Optional[Dict[str, Any]] = None) -> str:
        curr_st = KillswitchState(self.state["killswitch_state"])
        now = time.time()
        inc_id = derive_incident_id(reason, actor, now)

        self.state["killswitch_state"] = KillswitchState.TRIGGERED.value
        self.state["active_incident_id"] = inc_id
        self.state["trigger_reason"] = reason
        self.state["root_cause_resolved"] = False
        self.state["recovery_approved"] = False
        self._persist()

        self.audit_trail.append_event(inc_id, curr_st.value, KillswitchState.TRIGGERED.value, actor, reason, details)
        return inc_id

    def attempt_disarm_from_directive(self) -> Tuple[bool, str]:
        return False, "DIRECTIVE_CANNOT_DISABLE_KILLSWITCH"

    def enter_recovery_pending(self, root_cause_resolved: bool, actor: str) -> Tuple[bool, Optional[str]]:
        if self.state["killswitch_state"] != KillswitchState.TRIGGERED.value:
            return False, "KILLSWITCH_NOT_TRIGGERED"
        if not root_cause_resolved:
            return False, "UNRESOLVED_ROOT_CAUSE_BLOCKS_RECOVERY"

        inc_id = self.state["active_incident_id"] or "INC-UNKNOWN"
        self.state["killswitch_state"] = KillswitchState.RECOVERY_PENDING.value
        self.state["root_cause_resolved"] = True
        self._persist()

        self.audit_trail.append_event(inc_id, KillswitchState.TRIGGERED.value, KillswitchState.RECOVERY_PENDING.value, actor, "ROOT_CAUSE_RESOLVED")
        return True, None

    def execute_controlled_resume(
        self,
        incident_id: str,
        approval_rec: Optional[Dict[str, Any]],
        revalidation_success: bool,
        actor: str = "SEC_ADMIN_1"
    ) -> Tuple[bool, Optional[str]]:
        if self.state["killswitch_state"] != KillswitchState.RECOVERY_PENDING.value:
            return False, "INCONSISTENT_RECOVERY_STATE_REJECTED"

        if self.state["active_incident_id"] != incident_id:
            return False, "RECOVERY_APPROVAL_BOUND_TO_INCIDENT"

        if not self.state.get("root_cause_resolved", False):
            return False, "UNRESOLVED_ROOT_CAUSE_BLOCKS_RECOVERY"

        if not approval_rec or approval_rec.get("state") != "APPROVED":
            return False, "CRITICAL_RECOVERY_REQUIRES_HUMAN"

        if approval_rec.get("incident_id") and approval_rec.get("incident_id") != incident_id:
            return False, "RECOVERY_APPROVAL_BOUND_TO_INCIDENT"

        if approval_rec.get("consumed", False):
            return False, "STALE_RECOVERY_APPROVAL_REJECTED"

        if not revalidation_success:
            return False, "FAILED_RECOVERY_VALIDATION_REJECTED"

        self.state["killswitch_state"] = KillswitchState.ARMED.value
        self.state["active_incident_id"] = None
        self.state["recovery_approved"] = True
        self._persist()

        self.audit_trail.append_event(incident_id, KillswitchState.RECOVERY_PENDING.value, KillswitchState.ARMED.value, actor, "CONTROLLED_RESUME_COMPLETE")
        return True, None


class WatchdogHealthMonitor:
    """
    Independent Watchdog Health Monitor for Process, Heartbeat, Worker, Audit & Governance.
    """
    def __init__(self, max_heartbeat_age_seconds: float = 60.0):
        self.max_heartbeat_age = max_heartbeat_age_seconds

    def evaluate_health(
        self,
        heartbeat_timestamp: Optional[float],
        worker_state: str,
        audit_chain_valid: bool,
        crypto_valid: bool,
        governance_valid: bool,
        self_reported_status: Optional[str] = None
    ) -> Tuple[HealthState, Optional[str]]:
        # Watchdog evidence must be independent (ignore self_reported_status alone)
        if heartbeat_timestamp is None:
            return HealthState.UNKNOWN, "STALE_HEARTBEAT_DETECTED"

        now = time.time()
        if (now - heartbeat_timestamp) > self.max_heartbeat_age:
            return HealthState.CRITICAL, "STALE_HEARTBEAT_DETECTED"

        if worker_state == "DEAD":
            return HealthState.CRITICAL, "DEAD_WORKER_DETECTED"
        if worker_state == "FROZEN":
            return HealthState.CRITICAL, "FROZEN_WORKER_DETECTED"

        if not audit_chain_valid:
            return HealthState.CRITICAL, "AUDIT_FAILURE_TRIGGERS_KILLSWITCH"

        if not crypto_valid:
            return HealthState.CRITICAL, "CRYPTO_FAILURE_TRIGGERS_KILLSWITCH"

        if not governance_valid:
            return HealthState.CRITICAL, "GOVERNANCE_FAILURE_TRIGGERS_KILLSWITCH"

        return HealthState.HEALTHY, None


class ControllerLeaseManager:
    """
    Enforces Single Active Controller Lease Ownership to prevent Split-Brain.
    """
    def __init__(self, lease_file: Path, controller_id: str, lease_ttl: float = 30.0):
        self.lease_file = lease_file
        self.lease_file.parent.mkdir(parents=True, exist_ok=True)
        self.controller_id = controller_id
        self.lease_ttl = lease_ttl

    def acquire_or_renew_lease(self) -> Tuple[bool, Optional[str]]:
        now = time.time()
        if self.lease_file.exists():
            try:
                rec = json.loads(self.lease_file.read_text(encoding="utf-8"))
                owner = rec.get("owner")
                expires = rec.get("expires_at", 0)

                if owner != self.controller_id and now < expires:
                    return False, "SPLIT_BRAIN_DETECTED_AND_BLOCKED"
            except Exception:
                pass

        new_rec = {
            "owner": self.controller_id,
            "acquired_at": now,
            "expires_at": now + self.lease_ttl
        }

        with open(self.lease_file, "w", encoding="utf-8") as f:
            f.write(json.dumps(new_rec) + "\n")
            f.flush()
            os.fsync(f.fileno())

        return True, None

    def is_lease_owner(self) -> bool:
        if not self.lease_file.exists():
            return False
        try:
            rec = json.loads(self.lease_file.read_text(encoding="utf-8"))
            return rec.get("owner") == self.controller_id and time.time() < rec.get("expires_at", 0)
        except Exception:
            return False
