"""
Normalized Project State Contract, Canonical States, and Verification Triples
"""

from enum import Enum
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone


class CanonicalState(str, Enum):
    RUNNING = "RUNNING"
    DEVELOPING = "DEVELOPING"
    IDLE_VALID = "IDLE_VALID"
    STALE = "STALE"
    RECOVERING = "RECOVERING"
    BLOCKED = "BLOCKED"
    HUMAN_REQUIRED = "HUMAN_REQUIRED"
    COMPLETED = "COMPLETED"
    UNKNOWN = "UNKNOWN"


class VerificationStatus(str, Enum):
    VERIFIED = "VERIFIED"
    LOCAL_ONLY = "LOCAL_ONLY"
    REMOTE_ONLY = "REMOTE_ONLY"
    CONFLICT = "CONFLICT"
    BRANCH_NOT_FOUND = "BRANCH_NOT_FOUND"
    AUTH_FAILURE = "AUTH_FAILURE"
    NETWORK_FAILURE = "NETWORK_FAILURE"
    TIMEOUT = "TIMEOUT"
    GIT_FAILURE = "GIT_FAILURE"
    UNKNOWN = "UNKNOWN"


@dataclass
class VerifiedField:
    local_observed_value: Any
    remote_verified_value: Any
    verification_status: VerificationStatus = VerificationStatus.UNKNOWN

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["verification_status"] = (
            self.verification_status.value
            if isinstance(self.verification_status, VerificationStatus)
            else str(self.verification_status)
        )
        return d


@dataclass
class EvidenceItem:
    source_name: str
    filepath: str
    file_exists: bool
    last_modified_iso: Optional[str] = None
    age_seconds: Optional[float] = None
    parsed_data: Optional[Dict[str, Any]] = None
    parse_error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class NormalizedProjectState:
    # CONTROL-01 Required Fields
    project: str
    stage: Optional[str] = None
    branch: Optional[str] = None
    remote_head: Optional[str] = None
    local_head: Optional[str] = None
    process_expected: bool = False
    process_running: bool = False
    unexpected_process: bool = False  # Set True when process_expected=False but process_running=True
    last_heartbeat: Optional[str] = None
    last_successful_cycle: Optional[str] = None
    last_error: Optional[str] = None
    test_status: Optional[Dict[str, Any]] = field(default_factory=dict)
    critical_gates: Optional[Dict[str, Any]] = field(default_factory=dict)
    human_decision_required: bool = False
    next_action: Optional[str] = None
    evidence_freshness: Dict[str, Optional[float]] = field(default_factory=dict)

    # CONTROL-02 Required State Machine Fields
    status: CanonicalState = CanonicalState.UNKNOWN
    reason: str = "Uninitialized state"
    observed_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    heartbeat_age_seconds: Optional[float] = None
    last_known_good: Optional[str] = None
    retry_count: int = 0
    human_required: bool = False
    evidence_sources: List[str] = field(default_factory=list)
    confidence: float = 0.0
    state_conflict: bool = False
    conflicting_sources: List[str] = field(default_factory=list)

    # PRECEDENCE & AUDIT METADATA
    evidence_precedence_used: List[str] = field(default_factory=list)
    status_source: str = "UNKNOWN"
    status_age_seconds: Optional[float] = None
    observer_errors: List[str] = field(default_factory=list)
    external_project_activity_detected: bool = False

    # REMOTE VERIFICATION TRIPLES & DIAGNOSTICS
    verified_stage: Optional[VerifiedField] = None
    verified_branch: Optional[VerifiedField] = None
    verified_head: Optional[VerifiedField] = None
    verified_status: Optional[VerifiedField] = None
    verified_process_expected: Optional[VerifiedField] = None
    verified_process_running: Optional[VerifiedField] = None

    remote_query_command: Optional[str] = None
    remote_query_ref: Optional[str] = None
    remote_query_returncode: Optional[int] = None
    remote_query_timeout: bool = False
    remote_query_stderr_category: str = "UNKNOWN"

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["status"] = self.status.value if isinstance(self.status, CanonicalState) else str(self.status)
        for key in ["verified_stage", "verified_branch", "verified_head", "verified_status",
                    "verified_process_expected", "verified_process_running"]:
            val = getattr(self, key)
            if val and hasattr(val, "to_dict"):
                d[key] = val.to_dict()
        return d
