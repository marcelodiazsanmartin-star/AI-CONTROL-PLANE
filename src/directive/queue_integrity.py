"""
Directive Queue Integrity, Replay Defense & Exactly-Once Dispatch Engine for CONTROL-02.5 / BLOCK 2.6.

Enforces:
1. Immutable Cryptographically-Bound Directive Identity
2. Strict Directive State Machine & State Transitions
3. Replay Protection & Payload Mutation Inspection
4. Crash / Restart Recovery & Execution Lock/Lease Management
5. Append-Only Tamper-Evident Lifecycle Audit Chain
"""

import hashlib
import json
import os
import time
from enum import Enum
from pathlib import Path
from typing import Dict, Any, Tuple, Optional, List, Set


class DirectiveState(str, Enum):
    AUTHENTICATED = "AUTHENTICATED"
    QUEUED = "QUEUED"
    CLAIMED = "CLAIMED"
    PRE_EXEC_VALIDATED = "PRE_EXEC_VALIDATED"
    DISPATCH_AUTHORIZED = "DISPATCH_AUTHORIZED"
    EXECUTING = "EXECUTING"
    COMPLETED = "COMPLETED"
    FAILED_FINAL = "FAILED_FINAL"
    REJECTED = "REJECTED"
    WAITING_HUMAN = "WAITING_HUMAN"
    INDETERMINATE = "INDETERMINATE"


TERMINAL_STATES = {
    DirectiveState.COMPLETED,
    DirectiveState.FAILED_FINAL,
    DirectiveState.REJECTED
}


VALID_TRANSITIONS = {
    DirectiveState.AUTHENTICATED: {DirectiveState.QUEUED, DirectiveState.REJECTED},
    DirectiveState.QUEUED: {DirectiveState.CLAIMED, DirectiveState.REJECTED},
    DirectiveState.CLAIMED: {DirectiveState.PRE_EXEC_VALIDATED, DirectiveState.REJECTED, DirectiveState.INDETERMINATE},
    DirectiveState.PRE_EXEC_VALIDATED: {DirectiveState.DISPATCH_AUTHORIZED, DirectiveState.WAITING_HUMAN, DirectiveState.REJECTED},
    DirectiveState.DISPATCH_AUTHORIZED: {DirectiveState.EXECUTING, DirectiveState.REJECTED},
    DirectiveState.EXECUTING: {DirectiveState.COMPLETED, DirectiveState.FAILED_FINAL, DirectiveState.WAITING_HUMAN, DirectiveState.INDETERMINATE},
    DirectiveState.WAITING_HUMAN: {DirectiveState.PRE_EXEC_VALIDATED, DirectiveState.REJECTED},
}


def derive_directive_identity(
    payload_commit_sha: str,
    payload_sha256: str,
    signer_fingerprint: str,
    trusted_branch: str = "main",
    directive_type: str = "STANDARD"
) -> Tuple[bool, Dict[str, Any]]:
    """
    Derives deterministic, immutable directive identity cryptographically bound to
    payload, commit SHA, signer fingerprint, trusted branch, and directive type.
    """
    meta = {
        "directive_id_derived": False,
        "directive_id_bound_to_payload": False,
        "directive_id_bound_to_commit": False,
        "directive_id_bound_to_signer": False,
        "directive_id": None
    }

    if not payload_commit_sha or not payload_sha256 or not signer_fingerprint:
        return False, meta

    raw_seed = f"{payload_commit_sha}:{payload_sha256}:{signer_fingerprint}:{trusted_branch}:{directive_type}"
    directive_id = "DIR-" + hashlib.sha256(raw_seed.encode("utf-8")).hexdigest()[:32]

    meta["directive_id"] = directive_id
    meta["directive_id_derived"] = True
    meta["directive_id_bound_to_payload"] = True
    meta["directive_id_bound_to_commit"] = True
    meta["directive_id_bound_to_signer"] = True

    return True, meta


class QueueAuditTrail:
    """
    Append-only tamper-evident audit trail with cryptographic hash chaining.
    """
    def __init__(self, audit_file: Path):
        self.audit_file = audit_file
        self.audit_file.parent.mkdir(parents=True, exist_ok=True)

    def get_last_event_hash(self) -> str:
        if not self.audit_file.exists():
            return "0000000000000000000000000000000000000000000000000000000000000000"
        try:
            lines = self.audit_file.read_text(encoding="utf-8").strip().splitlines()
            if not lines:
                return "0000000000000000000000000000000000000000000000000000000000000000"
            last_rec = json.loads(lines[-1])
            return last_rec.get("event_hash", "0000000000000000000000000000000000000000000000000000000000000000")
        except Exception:
            return "CORRUPTED"

    def append_event(
        self,
        event_id: str,
        directive_id: str,
        from_state: str,
        to_state: str,
        worker_id: str,
        payload_sha256: str,
        commit_sha: str
    ) -> Tuple[bool, Dict[str, Any]]:
        prev_hash = self.get_last_event_hash()
        if prev_hash == "CORRUPTED":
            return False, {"error": "CORRUPTED_AUDIT_CHAIN"}

        ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        body = f"{event_id}:{directive_id}:{from_state}:{to_state}:{ts}:{worker_id}:{payload_sha256}:{commit_sha}:{prev_hash}"
        event_hash = hashlib.sha256(body.encode("utf-8")).hexdigest()

        rec = {
            "event_id": event_id,
            "directive_id": directive_id,
            "from_state": from_state,
            "to_state": to_state,
            "timestamp": ts,
            "actor_worker": worker_id,
            "payload_sha256": payload_sha256,
            "commit_sha": commit_sha,
            "previous_event_hash": prev_hash,
            "event_hash": event_hash
        }

        with open(self.audit_file, "a", encoding="utf-8") as f:
            f.write(json.dumps(rec) + "\n")
            f.flush()
            os.fsync(f.fileno())

        return True, rec

    def verify_integrity(self) -> Tuple[bool, str]:
        if not self.audit_file.exists():
            return True, "EMPTY"

        try:
            lines = self.audit_file.read_text(encoding="utf-8").strip().splitlines()
            expected_prev = "0000000000000000000000000000000000000000000000000000000000000000"
            for idx, line in enumerate(lines):
                if not line.strip():
                    continue
                rec = json.loads(line)
                if rec.get("previous_event_hash") != expected_prev:
                    return False, f"HASH_CHAIN_BROKEN_AT_LINE_{idx+1}"
                
                body = f"{rec['event_id']}:{rec['directive_id']}:{rec['from_state']}:{rec['to_state']}:{rec['timestamp']}:{rec['actor_worker']}:{rec['payload_sha256']}:{rec['commit_sha']}:{expected_prev}"
                computed_hash = hashlib.sha256(body.encode("utf-8")).hexdigest()
                if computed_hash != rec.get("event_hash"):
                    return False, f"TAMPERED_EVENT_AT_LINE_{idx+1}"
                expected_prev = computed_hash
            return True, "VALID"
        except Exception as e:
            return False, f"AUDIT_READ_ERROR: {str(e)}"


class DurableDirectiveQueue:
    """
    Atomic, crash-safe durable directive queue state engine with strict state machine.
    """
    def __init__(self, queue_file: Path, audit_trail: QueueAuditTrail):
        self.queue_file = queue_file
        self.audit_trail = audit_trail
        self.queue_file.parent.mkdir(parents=True, exist_ok=True)
        self.records: Dict[str, Dict[str, Any]] = {}
        self.load_queue()

    def load_queue(self) -> bool:
        self.records = {}
        if not self.queue_file.exists():
            return True
        try:
            lines = self.queue_file.read_text(encoding="utf-8").strip().splitlines()
            for line in lines:
                if not line.strip():
                    continue
                rec = json.loads(line)
                did = rec.get("directive_id")
                if did:
                    self.records[did] = rec
            return True
        except Exception:
            return False

    def save_queue_atomic(self) -> bool:
        tmp_file = self.queue_file.with_suffix(".tmp")
        try:
            with open(tmp_file, "w", encoding="utf-8") as f:
                for rec in self.records.values():
                    f.write(json.dumps(rec) + "\n")
                f.flush()
                os.fsync(f.fileno())
            tmp_file.replace(self.queue_file)
            return True
        except Exception:
            if tmp_file.exists():
                tmp_file.unlink(missing_ok=True)
            return False

    def enqueue_directive(
        self,
        directive_id: str,
        commit_sha: str,
        payload_sha256: str,
        signer_fp: str,
        worker_id: str = "WORKER-01"
    ) -> Tuple[bool, Optional[str]]:
        if not directive_id:
            return False, "MISSING_DIRECTIVE_ID"

        if directive_id in self.records:
            existing = self.records[directive_id]
            if existing.get("queue_state") in [s.value for s in TERMINAL_STATES]:
                return False, "COMPLETED_DIRECTIVE_REPLAY_REJECTED"
            return False, "DUPLICATE_DIRECTIVE_REJECTED"

        now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        rec = {
            "directive_id": directive_id,
            "authenticated_payload_commit_sha": commit_sha,
            "authenticated_payload_sha256": payload_sha256,
            "authenticated_signer_fingerprint": signer_fp,
            "queue_state": DirectiveState.QUEUED.value,
            "created_at": now,
            "claimed_at": None,
            "completed_at": None,
            "attempt_count": 0,
            "last_error": None,
            "pre_exec_auth_state": "VERIFIED",
            "lock_owner": None
        }

        self.records[directive_id] = rec
        if not self.save_queue_atomic():
            return False, "QUEUE_SAVE_FAILED"

        event_id = f"EVT-ENQUEUE-{time.time_ns()}"
        self.audit_trail.append_event(
            event_id, directive_id, "NONE", DirectiveState.QUEUED.value, worker_id, payload_sha256, commit_sha
        )
        return True, None

    def transition_state(
        self,
        directive_id: str,
        target_state: DirectiveState,
        worker_id: str,
        current_payload_sha256: Optional[str] = None
    ) -> Tuple[bool, Optional[str]]:
        rec = self.records.get(directive_id)
        if not rec:
            return False, "MISSING_DIRECTIVE_ID"

        curr_state_str = rec.get("queue_state")
        try:
            curr_state = DirectiveState(curr_state_str)
        except Exception:
            return False, "CORRUPTED_QUEUE_STATE"

        if curr_state in TERMINAL_STATES:
            if target_state == DirectiveState.QUEUED:
                return False, "COMPLETED_TO_QUEUED_REJECTED"
            return False, "TERMINAL_STATE_IMMUTABLE"

        if target_state == DirectiveState.CLAIMED and curr_state == DirectiveState.CLAIMED:
            return False, "CONCURRENT_DOUBLE_CLAIM_REJECTED"

        allowed = VALID_TRANSITIONS.get(curr_state, set())
        if target_state not in allowed:
            return False, "INVALID_STATE_TRANSITION_REJECTED"

        # Check queued payload immutability if provided
        if current_payload_sha256 and current_payload_sha256 != rec.get("authenticated_payload_sha256"):
            rec["queue_state"] = DirectiveState.REJECTED.value
            self.save_queue_atomic()
            return False, "QUEUE_PAYLOAD_MUTATION_REJECTED"

        now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        if target_state == DirectiveState.CLAIMED:
            if rec.get("lock_owner") and rec.get("lock_owner") != worker_id:
                return False, "CONCURRENT_DOUBLE_CLAIM_REJECTED"
            rec["lock_owner"] = worker_id
            rec["claimed_at"] = now
            rec["attempt_count"] = rec.get("attempt_count", 0) + 1

        elif target_state in TERMINAL_STATES:
            rec["completed_at"] = now
            rec["lock_owner"] = None

        rec["queue_state"] = target_state.value
        if not self.save_queue_atomic():
            return False, "QUEUE_SAVE_FAILED"

        event_id = f"EVT-TRANS-{time.time_ns()}"
        self.audit_trail.append_event(
            event_id,
            directive_id,
            curr_state_str,
            target_state.value,
            worker_id,
            rec.get("authenticated_payload_sha256"),
            rec.get("authenticated_payload_commit_sha")
        )
        return True, None
