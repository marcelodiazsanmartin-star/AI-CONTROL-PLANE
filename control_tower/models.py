"""Canonical, read-only Phase 0 dashboard data contract."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any


class RuntimeStatus(str, Enum):
    HEALTHY = "HEALTHY"
    WORKING = "WORKING"
    DEGRADED = "DEGRADED"
    STALE = "STALE"
    OFFLINE = "OFFLINE"
    UNKNOWN = "UNKNOWN"
    BLOCKED = "BLOCKED"


class TruthStatus(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    PENDING = "PENDING"
    UNKNOWN = "UNKNOWN"
    NOT_CONNECTED = "NOT_CONNECTED"
    BLOCKED = "BLOCKED"


class AlertLevel(str, Enum):
    INFO = "INFO"
    WARNING = "WARNING"
    ACTION_REQUIRED = "ACTION_REQUIRED"
    HUMAN_APPROVAL = "HUMAN_APPROVAL"
    CRITICAL = "CRITICAL"
    ORACLE = "ORACLE"


@dataclass(frozen=True)
class Evidence:
    id: str
    label: str
    status: TruthStatus
    source: str | None = None
    verified_at: datetime | None = None


@dataclass(frozen=True)
class Gate:
    id: str
    label: str
    weight: float
    status: TruthStatus
    evidence_ids: tuple[str, ...] = ()
    evidence_complete: bool = False
    blocker: str | None = None


@dataclass(frozen=True)
class Milestone:
    id: str
    label: str
    weight: float
    progress: float
    status: TruthStatus = TruthStatus.PENDING


@dataclass(frozen=True)
class Task:
    id: str
    project_id: str
    label: str
    stage: str
    progress: float | None
    active: bool = False
    blocker: str | None = None


@dataclass(frozen=True)
class Agent:
    id: str
    name: str
    availability: RuntimeStatus
    current_task: str | None
    task_stage: str | None
    progress: float | None
    heartbeat: datetime | None
    provider_status: str
    quota_status: str = "UNKNOWN"
    blocker: str | None = None


@dataclass(frozen=True)
class Alert:
    id: str
    level: AlertLevel
    title: str
    detail: str
    project_id: str | None = None


@dataclass(frozen=True)
class Approval:
    id: str
    label: str
    reason: str
    requested_at: datetime | None
    required: bool
    status: TruthStatus
    execution_enabled: bool = False


@dataclass(frozen=True)
class Runtime:
    project_id: str
    persisted_status: str | None
    observed_status: RuntimeStatus
    heartbeat: datetime | None
    source: str
    conflict: bool = False


@dataclass(frozen=True)
class Cost:
    project_id: str
    amount: float | None
    currency: str
    period: str
    source_status: TruthStatus


@dataclass(frozen=True)
class Project:
    id: str
    name: str
    description: str
    milestones: tuple[Milestone, ...] = ()
    certification_gates: tuple[Gate, ...] = ()
    operational_gates: tuple[Gate, ...] = ()
    next_action: str = "UNKNOWN"
    domain: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class SecurityPolicy:
    read_only: bool = True
    live_money_controls: bool = False
    approval_execution: bool = False
    strategy_mutation: bool = False
    risk_mutation: bool = False
    credential_mutation: bool = False


def serialize(value: Any) -> Any:
    """Convert contract values into JSON-safe primitives."""
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, Enum):
        return value.value
    if hasattr(value, "__dataclass_fields__"):
        return {key: serialize(item) for key, item in asdict(value).items()}
    if isinstance(value, dict):
        return {key: serialize(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [serialize(item) for item in value]
    return value
