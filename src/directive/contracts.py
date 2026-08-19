"""
Directive Channel Contracts, States, Envelopes, and Data Structures

Implements strict separation between DIRECTIVE PAYLOAD (immutable execution logic)
and DIRECTIVE ENVELOPE (external security & cryptographic provenance).
"""

from enum import Enum
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone


class DirectiveState(str, Enum):
    DISCOVERED = "DISCOVERED"
    VALIDATING = "VALIDATING"
    ACCEPTED = "ACCEPTED"
    REJECTED = "REJECTED"
    WAITING_HUMAN = "WAITING_HUMAN"
    QUEUED = "QUEUED"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"


class ValidationStatus(str, Enum):
    AUTHENTIC = "AUTHENTIC"
    INVALID_SOURCE = "INVALID_SOURCE"
    COMMIT_NOT_FOUND = "COMMIT_NOT_FOUND"
    COMMIT_EXISTS_BUT_DIRECTIVE_ABSENT = "COMMIT_EXISTS_BUT_DIRECTIVE_ABSENT"
    NOT_IN_APPROVED_BRANCH = "NOT_IN_APPROVED_BRANCH"
    CONTENT_MISMATCH = "CONTENT_MISMATCH"
    REPLAY_DETECTED = "REPLAY_DETECTED"
    EXPIRED = "EXPIRED"
    CLOCK_SKEW_EXCEEDED = "CLOCK_SKEW_EXCEEDED"
    SCHEMA_INVALID = "SCHEMA_INVALID"
    ACTION_NOT_ALLOWED = "ACTION_NOT_ALLOWED"
    FAIL_CLOSED_GITHUB_UNAVAILABLE = "FAIL_CLOSED_GITHUB_UNAVAILABLE"
    COMMIT_SIGNATURE_MISSING = "COMMIT_SIGNATURE_MISSING"
    COMMIT_SIGNATURE_INVALID = "COMMIT_SIGNATURE_INVALID"
    UNTRUSTED_COMMIT_SIGNER = "UNTRUSTED_COMMIT_SIGNER"
    PAYLOAD_COMMIT_NOT_REACHABLE = "PAYLOAD_COMMIT_NOT_REACHABLE"
    REMOTE_BRANCH_UNAVAILABLE = "REMOTE_BRANCH_UNAVAILABLE"
    STATE_CONFLICT = "STATE_CONFLICT"
    QUEUE_CORRUPTION = "QUEUE_CORRUPTION"
    QUEUE_PERSISTENCE_FAILURE = "QUEUE_PERSISTENCE_FAILURE"
    QUEUE_RECORD_MISMATCH = "QUEUE_RECORD_MISMATCH"
    TOCTOU_REVALIDATION_FAILED = "TOCTOU_REVALIDATION_FAILED"


@dataclass
class DirectivePayload:
    """
    Immutable execution payload without self-referential git metadata.
    """
    directive_version: str
    directive_id: str
    project: str
    target_project: str
    target_stage: str
    action_type: str
    action: str
    created_at: str
    expires_at: str
    issued_by: str
    requires_human_approval: bool
    allowed_scope: List[str]
    preconditions: Dict[str, Any]
    success_criteria: Dict[str, Any]
    failure_policy: str
    rollback_policy: str
    payload: Dict[str, Any]

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "DirectivePayload":
        if "payload_object" in d and isinstance(d["payload_object"], dict):
            d = d["payload_object"]
        return cls(
            directive_version=str(d.get("directive_version", "")),
            directive_id=str(d.get("directive_id", "")),
            project=str(d.get("project", "")),
            target_project=str(d.get("target_project", "")),
            target_stage=str(d.get("target_stage", "")),
            action_type=str(d.get("action_type", "")),
            action=str(d.get("action", "")),
            created_at=str(d.get("created_at", "")),
            expires_at=str(d.get("expires_at", "")),
            issued_by=str(d.get("issued_by", "")),
            requires_human_approval=bool(d.get("requires_human_approval", False)),
            allowed_scope=list(d.get("allowed_scope", [])),
            preconditions=dict(d.get("preconditions", {})),
            success_criteria=dict(d.get("success_criteria", {})),
            failure_policy=str(d.get("failure_policy", "")),
            rollback_policy=str(d.get("rollback_policy", "")),
            payload=dict(d.get("payload", {}))
        )


Directive = DirectivePayload


@dataclass
class DirectiveEnvelope:
    """
    Separate security metadata envelope referencing the payload.
    """
    directive_id: str
    payload_commit_sha: str
    payload_blob_sha: str
    payload_sha256: str
    trusted_remote: str
    trusted_branch: str
    authentication_version: str = "2.0"
    signature_present: bool = False
    signature_valid: bool = False
    signer_identity: str = ""
    signer_allowed: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "DirectiveEnvelope":
        if "envelope" in d and isinstance(d["envelope"], dict):
            d = d["envelope"]
        return cls(
            directive_id=str(d.get("directive_id", "")),
            payload_commit_sha=str(d.get("payload_commit_sha", d.get("source_commit_sha", ""))),
            payload_blob_sha=str(d.get("payload_blob_sha", "")),
            payload_sha256=str(d.get("payload_sha256", "")),
            trusted_remote=str(d.get("trusted_remote", d.get("source_repository", ""))),
            trusted_branch=str(d.get("trusted_branch", d.get("source_branch", ""))),
            authentication_version=str(d.get("authentication_version", "2.0")),
            signature_present=bool(d.get("signature_present", False)),
            signature_valid=bool(d.get("signature_valid", False)),
            signer_identity=str(d.get("signer_identity", "")),
            signer_allowed=bool(d.get("signer_allowed", False))
        )


@dataclass
class DirectiveAck:
    directive_id: str
    received_at: str
    source_commit_sha: str
    validation_status: str
    decision: str
    decision_reason: str
    human_required: bool
    queued: bool
    executed: bool
    control_plane_commit_sha: str
    readback_verified: bool = True
    observer_version: str = "2.0"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ConsumedRecord:
    directive_id: str
    source_commit_sha: str
    first_seen_at: str
    decision: str
    decision_reason: str
    processed_at: str
    idempotency_key: str = ""
    payload_sha256: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class QueuedDirectiveItem:
    directive_id: str
    directive_source_sha: str
    directive_blob_sha: str
    directive_payload_sha256: str
    accepted_at: str
    queue_state: str = "READY_FOR_FUTURE_EXECUTOR"
    target_project: str = ""
    action_type: str = ""
    requires_human_approval: bool = False
    executed: bool = False
    execution_attempts: int = 0
    readback_verified: bool = False
    idempotency_key: str = ""
    signer_identity: str = ""
    directive_payload: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class DirectiveChannelStatus:
    status: str = "RUNNING"
    last_poll: Optional[str] = None
    last_directive_seen: Optional[str] = None
    last_directive_id: Optional[str] = None
    accepted_count: int = 0
    rejected_count: int = 0
    waiting_human_count: int = 0
    queued_count: int = 0
    replay_rejections: int = 0
    schema_rejections: int = 0
    auth_rejections: int = 0
    github_errors: int = 0
    state_conflicts: int = 0
    toctou_failures: int = 0
    last_error: Optional[str] = None
    channel_version: str = "2.0.0"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
