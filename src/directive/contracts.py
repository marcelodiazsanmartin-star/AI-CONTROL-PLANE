"""
Directive Channel Contracts, States, and Data Structures
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
    NOT_IN_APPROVED_BRANCH = "NOT_IN_APPROVED_BRANCH"
    CONTENT_MISMATCH = "CONTENT_MISMATCH"
    REPLAY_DETECTED = "REPLAY_DETECTED"
    EXPIRED = "EXPIRED"
    CLOCK_SKEW_EXCEEDED = "CLOCK_SKEW_EXCEEDED"
    SCHEMA_INVALID = "SCHEMA_INVALID"
    ACTION_NOT_ALLOWED = "ACTION_NOT_ALLOWED"
    FAIL_CLOSED_GITHUB_UNAVAILABLE = "FAIL_CLOSED_GITHUB_UNAVAILABLE"


@dataclass
class Directive:
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
    source_repository: str
    source_branch: str
    source_commit_sha: str
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
    def from_dict(cls, d: Dict[str, Any]) -> "Directive":
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
            source_repository=str(d.get("source_repository", "")),
            source_branch=str(d.get("source_branch", "")),
            source_commit_sha=str(d.get("source_commit_sha", "")),
            requires_human_approval=bool(d.get("requires_human_approval", False)),
            allowed_scope=list(d.get("allowed_scope", [])),
            preconditions=dict(d.get("preconditions", {})),
            success_criteria=dict(d.get("success_criteria", {})),
            failure_policy=str(d.get("failure_policy", "")),
            rollback_policy=str(d.get("rollback_policy", "")),
            payload=dict(d.get("payload", {}))
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
    observer_version: str = "1.0.0"

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
    last_error: Optional[str] = None
    channel_version: str = "1.0.0"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
