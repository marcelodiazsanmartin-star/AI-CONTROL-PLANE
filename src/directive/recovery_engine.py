"""
CONTROL-03 — Recovery Engine

Implements the canonical Control Plane Recovery Engine lifecycle:
SAFE FAILURE → RETRY → CHECKPOINT RECOVERY → INTEGRITY VALIDATION → SAFE CONTINUATION

Enforces fail-closed defaults, retry storm detection, checkpoint cryptographic integrity,
append-only audit trail, watchdog/killswitch supremacy, and strict external service isolation invariants.
"""

import os
import json
import time
import hashlib
import hmac
from enum import Enum
from pathlib import Path
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, Optional, Tuple, List


class FailureClass(str, Enum):
    RECOVERABLE = "RECOVERABLE"
    UNRECOVERABLE = "UNRECOVERABLE"


class RecoveryState(str, Enum):
    IDLE = "IDLE"
    FAIL_DETECTED = "FAIL_DETECTED"
    RETRYING = "RETRYING"
    CHECKPOINT_SAVED = "CHECKPOINT_SAVED"
    CHECKPOINT_RESTORED = "CHECKPOINT_RESTORED"
    INTEGRITY_VERIFIED = "INTEGRITY_VERIFIED"
    RECONCILED = "RECONCILED"
    CONTINUING = "CONTINUING"
    HUMAN_REQUIRED = "HUMAN_REQUIRED"
    KILLED_BY_WATCHDOG = "KILLED_BY_WATCHDOG"


class RecoveryCheckpoint:
    def __init__(
        self,
        directive_id: str,
        attempt_count: int,
        state_vector: Dict[str, Any],
        payload_hash: str,
        timestamp: str = None,
        signature: str = None
    ):
        self.directive_id = directive_id
        self.attempt_count = attempt_count
        self.state_vector = state_vector
        self.payload_hash = payload_hash
        self.timestamp = timestamp or datetime.now(timezone.utc).isoformat()
        self.signature = signature or ""

    def compute_signature(self, secret_key: str) -> str:
        """
        Computes HMAC-SHA256 signature over canonical checkpoint content.
        """
        data = f"{self.directive_id}:{self.attempt_count}:{self.payload_hash}:{self.timestamp}:{json.dumps(self.state_vector, sort_keys=True)}"
        return hmac.new(secret_key.encode("utf-8"), data.encode("utf-8"), hashlib.sha256).hexdigest()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "directive_id": self.directive_id,
            "attempt_count": self.attempt_count,
            "state_vector": self.state_vector,
            "payload_hash": self.payload_hash,
            "timestamp": self.timestamp,
            "signature": self.signature
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "RecoveryCheckpoint":
        return cls(
            directive_id=d["directive_id"],
            attempt_count=d["attempt_count"],
            state_vector=d["state_vector"],
            payload_hash=d["payload_hash"],
            timestamp=d["timestamp"],
            signature=d.get("signature", "")
        )


class RecoveryAuditTrail:
    """
    Append-only ledger recording all failure, retry, checkpoint, integrity,
    and human escalation lifecycle events.
    """
    def __init__(self, ledger_file: Path):
        self.ledger_file = Path(ledger_file)
        self.ledger_file.parent.mkdir(parents=True, exist_ok=True)
        if not self.ledger_file.exists():
            self.ledger_file.write_text("", encoding="utf-8")

    def record_event(self, event_type: str, directive_id: str, details: Dict[str, Any]) -> Dict[str, Any]:
        timestamp = datetime.now(timezone.utc).isoformat()
        event = {
            "timestamp": timestamp,
            "event_type": event_type,
            "directive_id": directive_id,
            "details": details
        }

        # Calculate chain hash for tamper-evident append-only ledger
        prev_hash = "GENESIS"
        if self.ledger_file.exists() and self.ledger_file.stat().st_size > 0:
            lines = [l for l in self.ledger_file.read_text(encoding="utf-8").splitlines() if l.strip()]
            if lines:
                try:
                    last_obj = json.loads(lines[-1])
                    prev_hash = last_obj.get("event_hash", "GENESIS")
                except Exception:
                    prev_hash = "CORRUPTED_CHAIN"

        event["prev_hash"] = prev_hash
        raw_str = f"{timestamp}:{event_type}:{directive_id}:{prev_hash}:{json.dumps(details, sort_keys=True)}"
        event["event_hash"] = hashlib.sha256(raw_str.encode("utf-8")).hexdigest()

        with open(self.ledger_file, "a", encoding="utf-8") as f:
            f.write(json.dumps(event) + "\n")

        return event

    def verify_ledger_integrity(self) -> Tuple[bool, str]:
        if not self.ledger_file.exists() or self.ledger_file.stat().st_size == 0:
            return True, "EMPTY_LEDGER"

        lines = [l for l in self.ledger_file.read_text(encoding="utf-8").splitlines() if l.strip()]
        expected_prev = "GENESIS"
        for idx, l in enumerate(lines):
            try:
                obj = json.loads(l)
                if obj.get("prev_hash") != expected_prev:
                    return False, f"CHAIN_BREAK_AT_LINE_{idx+1}"
                raw_str = f"{obj['timestamp']}:{obj['event_type']}:{obj['directive_id']}:{expected_prev}:{json.dumps(obj['details'], sort_keys=True)}"
                calc_hash = hashlib.sha256(raw_str.encode("utf-8")).hexdigest()
                if calc_hash != obj.get("event_hash"):
                    return False, f"HASH_MISMATCH_AT_LINE_{idx+1}"
                expected_prev = calc_hash
            except Exception as e:
                return False, f"PARSE_ERROR_AT_LINE_{idx+1}: {str(e)}"

        return True, "INTEGRITY_VALIDATED"


class RecoveryEngine:
    """
    Control Plane Recovery Engine: SAFE FAILURE → RETRY → CHECKPOINT RECOVERY → INTEGRITY VALIDATION → SAFE CONTINUATION
    """
    def __init__(
        self,
        checkpoint_dir: Path,
        audit_file: Path,
        secret_key: str = "CONTROL_PLANE_RECOVERY_SECRET_KEY_V1",
        max_retries: int = 3,
        retry_window_seconds: int = 60,
        checkpoint_max_age_seconds: int = 3600
    ):
        self.checkpoint_dir = Path(checkpoint_dir)
        self.checkpoint_dir.mkdir(parents=True, exist_ok=True)
        self.audit = RecoveryAuditTrail(audit_file)
        self.secret_key = secret_key
        self.max_retries = max_retries
        self.retry_window_seconds = retry_window_seconds
        self.checkpoint_max_age_seconds = checkpoint_max_age_seconds
        self.retry_history: Dict[str, List[float]] = {}
        self.executed_directives: Dict[str, str] = {}

    def classify_failure(self, error_type: str, error_msg: str, context: Dict[str, Any] = None) -> Tuple[FailureClass, str]:
        """
        Classifies errors into RECOVERABLE vs UNRECOVERABLE.
        Enforces strict external service isolation (ORACLE/MICRO cannot be mutated).
        """
        context = context or {}

        # Invariant Check: Attempt to modify ORACLE-AI or MICRO-MARKET-ORACLE external services
        target = str(context.get("target", "")).upper()
        action = str(context.get("action", "")).upper()
        if "ORACLE" in target or "MICRO" in target or "EXTERNAL" in target or "STRATEGY" in action or "FINANCIAL" in action:
            self.audit.record_event("UNAUTHORIZED_EXTERNAL_MUTATION_ATTEMPT", context.get("directive_id", "UNKNOWN"), {
                "target": target, "action": action, "error_msg": error_msg
            })
            return FailureClass.UNRECOVERABLE, "EXTERNAL_SERVICE_MUTATION_FORBIDDEN"

        # Check unrecoverable errors
        unrecoverable_keywords = [
            "CORRUPT", "TAMPERED", "KILLSWITCH", "UNAUTHORIZED", "REPLAY",
            "SPLIT_BRAIN", "SIGNATURE_MISMATCH", "CAPABILITY_DENIED", "AUDIT_FAIL"
        ]

        msg_upper = f"{error_type} {error_msg}".upper()
        for kw in unrecoverable_keywords:
            if kw in msg_upper:
                return FailureClass.UNRECOVERABLE, f"CRITICAL_FAILURE_{kw}"

        # Transient/Recoverable errors
        recoverable_keywords = [
            "TIMEOUT", "LOCK_CONTENTION", "TRANSIENT_IO", "TEMPORARY_UNAVAILABLE", "QUEUE_BUSY"
        ]

        for kw in recoverable_keywords:
            if kw in msg_upper:
                return FailureClass.RECOVERABLE, f"RECOVERABLE_{kw}"

        # Default fail-closed to UNRECOVERABLE if ambiguous
        return FailureClass.UNRECOVERABLE, "UNCLASSIFIED_FAILURE_FAIL_CLOSED"

    def attempt_retry(self, directive_id: str) -> Tuple[bool, int, str]:
        """
        Evaluates retry authorization. Detects retry storms and recovery loops.
        """
        now = time.time()
        history = self.retry_history.get(directive_id, [])
        # Filter window
        recent = [t for t in history if (now - t) <= self.retry_window_seconds]
        recent.append(now)
        self.retry_history[directive_id] = recent

        attempt_count = len(recent)

        if attempt_count > self.max_retries:
            self.audit.record_event("RETRY_STORM_DETECTED", directive_id, {
                "attempt_count": attempt_count,
                "max_retries": self.max_retries,
                "window_seconds": self.retry_window_seconds
            })
            return False, attempt_count, "RETRY_STORM_LIMIT_EXCEEDED"

        self.audit.record_event("SAFE_RETRY_INITIATED", directive_id, {
            "attempt_count": attempt_count,
            "max_retries": self.max_retries
        })
        return True, attempt_count, "RETRY_AUTHORIZED"

    def save_checkpoint(self, directive_id: str, attempt_count: int, state_vector: Dict[str, Any], payload_hash: str) -> RecoveryCheckpoint:
        """
        Creates and persists a cryptographically signed checkpoint.
        """
        cp = RecoveryCheckpoint(
            directive_id=directive_id,
            attempt_count=attempt_count,
            state_vector=state_vector,
            payload_hash=payload_hash
        )
        cp.signature = cp.compute_signature(self.secret_key)

        cp_file = self.checkpoint_dir / f"checkpoint_{directive_id}_{attempt_count}.json"
        cp_file.write_text(json.dumps(cp.to_dict(), indent=2), encoding="utf-8")

        self.audit.record_event("CHECKPOINT_SAVED", directive_id, {
            "checkpoint_file": str(cp_file),
            "attempt_count": attempt_count,
            "payload_hash": payload_hash,
            "signature": cp.signature
        })
        return cp

    def restore_checkpoint(
        self,
        directive_id: str,
        attempt_count: int,
        expected_payload_hash: str
    ) -> Tuple[Optional[RecoveryCheckpoint], str]:
        """
        Loads and validates cryptographic integrity of a checkpoint.
        Rejects corrupt, tampered, or stale checkpoints.
        """
        cp_file = self.checkpoint_dir / f"checkpoint_{directive_id}_{attempt_count}.json"
        if not cp_file.exists():
            self.audit.record_event("CHECKPOINT_NOT_FOUND", directive_id, {"checkpoint_file": str(cp_file)})
            return None, "CHECKPOINT_FILE_NOT_FOUND"

        try:
            content = cp_file.read_text(encoding="utf-8")
            data = json.loads(content)
            cp = RecoveryCheckpoint.from_dict(data)
        except Exception as e:
            self.audit.record_event("CHECKPOINT_CORRUPTED", directive_id, {"error": str(e)})
            return None, "CHECKPOINT_CORRUPT_JSON"

        # 1. Signature Verification
        expected_sig = cp.compute_signature(self.secret_key)
        if not hmac.compare_digest(cp.signature, expected_sig):
            self.audit.record_event("CHECKPOINT_TAMPERED", directive_id, {
                "signature_given": cp.signature,
                "signature_computed": expected_sig
            })
            return None, "CHECKPOINT_SIGNATURE_INVALID"

        # 2. Payload Hash Reconciliation
        if cp.payload_hash != expected_payload_hash:
            self.audit.record_event("CHECKPOINT_HASH_MISMATCH", directive_id, {
                "expected_hash": expected_payload_hash,
                "actual_hash": cp.payload_hash
            })
            return None, "CHECKPOINT_PAYLOAD_HASH_MISMATCH"

        # 3. Timestamp Freshness Check
        try:
            cp_dt = datetime.fromisoformat(cp.timestamp)
            if cp_dt.tzinfo is None:
                cp_dt = cp_dt.replace(tzinfo=timezone.utc)
            now_dt = datetime.now(timezone.utc)
            if (now_dt - cp_dt).total_seconds() > self.checkpoint_max_age_seconds:
                self.audit.record_event("CHECKPOINT_STALE", directive_id, {
                    "checkpoint_time": cp.timestamp,
                    "max_age_seconds": self.checkpoint_max_age_seconds
                })
                return None, "CHECKPOINT_STALE_TIMESTAMP"
        except Exception as e:
            self.audit.record_event("CHECKPOINT_INVALID_TIMESTAMP", directive_id, {"error": str(e)})
            return None, "CHECKPOINT_INVALID_TIMESTAMP"

        self.audit.record_event("CHECKPOINT_RESTORED_AND_VERIFIED", directive_id, {
            "attempt_count": cp.attempt_count,
            "payload_hash": cp.payload_hash
        })
        return cp, "CHECKPOINT_INTEGRITY_VALIDATED"

    def execute_safe_recovery(
        self,
        directive_id: str,
        error_type: str,
        error_msg: str,
        state_vector: Dict[str, Any],
        payload_hash: str,
        context: Dict[str, Any] = None,
        watchdog_killswitch_active: bool = False
    ) -> Dict[str, Any]:
        """
        Full recovery flow: SAFE FAILURE → RETRY → CHECKPOINT RECOVERY → INTEGRITY VALIDATION → SAFE CONTINUATION
        Escalates to HUMAN_REQUIRED / fail-closed if any integrity/authorization check fails.
        """
        context = context or {}

        # 1. Watchdog / Killswitch Supremacy Check
        if watchdog_killswitch_active:
            self.audit.record_event("RECOVERY_BLOCKED_BY_KILLSWITCH", directive_id, {"reason": "KILLSWITCH_ACTIVE"})
            return {
                "executed": False,
                "recovery_state": RecoveryState.KILLED_BY_WATCHDOG,
                "human_required": True,
                "reason": "KILLSWITCH_ACTIVE_SUPREME_AUTHORITY"
            }

        # 2. Replay & Duplicate Execution Guard
        if self.executed_directives.get(directive_id) == "COMPLETED":
            self.audit.record_event("DUPLICATE_EXECUTION_BLOCKED", directive_id, {"reason": "ALREADY_COMPLETED"})
            return {
                "executed": False,
                "recovery_state": RecoveryState.HUMAN_REQUIRED,
                "human_required": True,
                "reason": "DUPLICATE_EXECUTION_ATTEMPT_REJECTED"
            }

        # 3. Classify Failure
        fail_class, class_reason = self.classify_failure(error_type, error_msg, context)
        if fail_class == FailureClass.UNRECOVERABLE:
            self.audit.record_event("UNRECOVERABLE_FAILURE_ESCALATED", directive_id, {"reason": class_reason})
            return {
                "executed": False,
                "recovery_state": RecoveryState.HUMAN_REQUIRED,
                "human_required": True,
                "reason": class_reason
            }

        # 4. Attempt Retry
        retry_ok, attempt_count, retry_reason = self.attempt_retry(directive_id)
        if not retry_ok:
            return {
                "executed": False,
                "recovery_state": RecoveryState.HUMAN_REQUIRED,
                "human_required": True,
                "reason": retry_reason
            }

        # 5. Save Checkpoint
        cp = self.save_checkpoint(directive_id, attempt_count, state_vector, payload_hash)

        # 6. Restore & Verify Checkpoint Integrity
        restored_cp, restore_status = self.restore_checkpoint(directive_id, attempt_count, payload_hash)
        if not restored_cp:
            return {
                "executed": False,
                "recovery_state": RecoveryState.HUMAN_REQUIRED,
                "human_required": True,
                "reason": f"CHECKPOINT_RECOVERY_FAILED_{restore_status}"
            }

        # 7. Validate Continuation Integrity
        ledger_ok, ledger_msg = self.audit.verify_ledger_integrity()
        if not ledger_ok:
            self.audit.record_event("AUDIT_LEDGER_CORRUPTED", directive_id, {"reason": ledger_msg})
            return {
                "executed": False,
                "recovery_state": RecoveryState.HUMAN_REQUIRED,
                "human_required": True,
                "reason": f"AUDIT_LEDGER_INTEGRITY_FAILED_{ledger_msg}"
            }

        # 8. Mark Executed & Safe Continuation
        self.executed_directives[directive_id] = "COMPLETED"
        self.audit.record_event("SAFE_CONTINUATION_AUTHORIZED", directive_id, {
            "attempt_count": attempt_count,
            "restored_state": restored_cp.state_vector
        })

        return {
            "executed": True,
            "recovery_state": RecoveryState.CONTINUING,
            "human_required": False,
            "attempt_count": attempt_count,
            "restored_state": restored_cp.state_vector,
            "reason": "SAFE_CONTINUATION_SUCCESSFUL"
        }
