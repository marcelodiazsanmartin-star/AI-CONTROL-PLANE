"""Deterministic, fail-closed dashboard calculations."""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Iterable

from control_tower.models import Gate, Milestone, RuntimeStatus, TruthStatus

STALE_AFTER = timedelta(minutes=5)
MAX_CLOCK_SKEW = timedelta(seconds=30)


def _valid_weight(weight: float) -> bool:
    """Reject booleans, non-numeric values, zero, and negative weights."""
    return not isinstance(weight, bool) and isinstance(weight, (int, float)) and weight > 0


def _valid_progress(progress: float) -> bool:
    return not isinstance(progress, bool) and isinstance(progress, (int, float))


def weighted_milestone_progress(items: Iterable[Milestone]) -> float | None:
    """Return explicit weighted progress or UNKNOWN (``None``) for invalid input."""
    values = tuple(items)
    if not values or any(
        not _valid_weight(item.weight) or not _valid_progress(item.progress)
        for item in values
    ):
        return None
    weighted = sum(item.weight * min(100, max(0, item.progress)) for item in values)
    return round(weighted / sum(item.weight for item in values), 1)


def effective_gate_status(gate: Gate) -> TruthStatus:
    """A claimed PASS without complete referenced evidence fails closed."""
    if gate.blocker:
        return TruthStatus.BLOCKED
    if gate.status is TruthStatus.PASS and (
        not gate.evidence_complete or not gate.evidence_ids
    ):
        return TruthStatus.UNKNOWN
    return gate.status


def weighted_gate_readiness(items: Iterable[Gate]) -> float | None:
    """Count only effective PASS gates toward readiness."""
    values = tuple(items)
    if not values or any(not _valid_weight(item.weight) for item in values):
        return None
    earned = sum(
        item.weight
        for item in values
        if effective_gate_status(item) is TruthStatus.PASS
    )
    return round(100 * earned / sum(item.weight for item in values), 1)


def runtime_truth(
    persisted_status: str | None,
    heartbeat: datetime | None,
    now: datetime,
    *,
    observed_status: RuntimeStatus | None = None,
    blocker: str | None = None,
) -> RuntimeStatus:
    """Resolve runtime truth without treating persisted state as live evidence."""
    if blocker:
        return RuntimeStatus.BLOCKED
    if not isinstance(heartbeat, datetime) or not isinstance(now, datetime):
        return RuntimeStatus.UNKNOWN
    if heartbeat.tzinfo is None or now.tzinfo is None:
        return RuntimeStatus.UNKNOWN
    if heartbeat > now + MAX_CLOCK_SKEW:
        return RuntimeStatus.UNKNOWN
    if now - heartbeat > STALE_AFTER:
        return RuntimeStatus.STALE
    if observed_status is None:
        return RuntimeStatus.UNKNOWN
    if persisted_status and persisted_status.upper() != observed_status.value:
        return RuntimeStatus.BLOCKED
    return observed_status
