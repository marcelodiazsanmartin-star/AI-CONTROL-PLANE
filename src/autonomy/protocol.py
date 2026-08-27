"""Provider-neutral, fail-closed AF-02 external worker envelopes."""
from __future__ import annotations

from dataclasses import dataclass

PROTOCOL_VERSION = "AF02/1"
REAL_PROJECT_MUTATION_ENABLED = False


@dataclass(frozen=True)
class WorkerProfile:
    worker_id: str
    worker_kind: str
    capabilities: tuple[str, ...]
    allowed_targets: tuple[str, ...]
    max_capacity: int
    heartbeat_sla: float


@dataclass(frozen=True)
class SessionHello:
    worker_id: str
    worker_kind: str
    capabilities: tuple[str, ...]
    allowed_targets: tuple[str, ...]
    session_id: str
    heartbeat_sequence: int
    observed_at: float
    capacity: int
    provider_state: str = "UNKNOWN"
    transport_state: str = "UNKNOWN"
    protocol_version: str = PROTOCOL_VERSION


@dataclass(frozen=True)
class HeartbeatEnvelope:
    worker_id: str
    session_id: str
    sequence: int
    observed_at: float
    capacity: int
    protocol_version: str = PROTOCOL_VERSION


@dataclass(frozen=True)
class DispatchEnvelope:
    dispatch_id: str
    task_id: str
    worker_id: str
    session_id: str
    lease_id: str
    lease_expires_at: float
    capability: str
    target_project: str
    protocol_version: str = PROTOCOL_VERSION


@dataclass(frozen=True)
class AckEnvelope:
    dispatch_id: str
    task_id: str
    worker_id: str
    session_id: str
    lease_id: str
    observed_at: float
    protocol_version: str = PROTOCOL_VERSION


@dataclass(frozen=True)
class EvidenceReference:
    evidence_id: str
    sha256: str


@dataclass(frozen=True)
class ResultEnvelope:
    dispatch_id: str
    task_id: str
    worker_id: str
    session_id: str
    lease_id: str
    observed_at: float
    status: str
    evidence: tuple[EvidenceReference, ...]
    protocol_version: str = PROTOCOL_VERSION
