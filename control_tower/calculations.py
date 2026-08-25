"""Deterministic, fail-closed dashboard calculations with truth semantics."""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any, Iterable, Mapping

from control_tower.models import Evidence, Gate, Milestone, RuntimeStatus, TruthStatus

STALE_AFTER = timedelta(minutes=5)
MAX_CLOCK_SKEW = timedelta(seconds=30)
MAX_EVIDENCE_AGE = timedelta(hours=24)

STATUS_NORMALIZATION_MAP: dict[str, RuntimeStatus] = {
    "RUNNING": RuntimeStatus.WORKING,
    "WORKING": RuntimeStatus.WORKING,
    "ONLINE": RuntimeStatus.WORKING,
    "ACTIVE": RuntimeStatus.WORKING,
    "UP": RuntimeStatus.WORKING,
    "HEALTHY": RuntimeStatus.HEALTHY,
    "OK": RuntimeStatus.HEALTHY,
    "DEGRADED": RuntimeStatus.DEGRADED,
    "DEGRADED_STALE": RuntimeStatus.DEGRADED,
    "STALE": RuntimeStatus.STALE,
    "OUTDATED": RuntimeStatus.STALE,
    "OFFLINE": RuntimeStatus.OFFLINE,
    "STOPPED": RuntimeStatus.OFFLINE,
    "EXITED": RuntimeStatus.OFFLINE,
    "DOWN": RuntimeStatus.OFFLINE,
    "BLOCKED": RuntimeStatus.BLOCKED,
    "CONFLICT": RuntimeStatus.BLOCKED,
    "ERROR": RuntimeStatus.BLOCKED,
    "UNKNOWN": RuntimeStatus.UNKNOWN,
}


def normalize_runtime_status(value: Any) -> RuntimeStatus:
    """Explicit deterministic normalization for runtime status strings."""
    if isinstance(value, RuntimeStatus):
        return value
    if not isinstance(value, str):
        return RuntimeStatus.UNKNOWN
    cleaned = value.strip().upper()
    return STATUS_NORMALIZATION_MAP.get(cleaned, RuntimeStatus.UNKNOWN)


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


def effective_gate_status(
    gate: Gate,
    evidence_map: Mapping[str, Evidence] | None = None,
    now: datetime | None = None,
    max_evidence_age: timedelta = MAX_EVIDENCE_AGE,
) -> TruthStatus:
    """A claimed PASS without complete verified fresh referenced evidence fails closed.

    CT-01R1 Truth Semantics:
    - Evidence ID must resolve
    - Evidence status must be PASS
    - Evidence provenance must be present/verified
    - Evidence freshness must satisfy freshness requirement if verified_at is present
    """
    if gate.blocker:
        return TruthStatus.BLOCKED
    if gate.status is TruthStatus.PASS:
        if not gate.evidence_complete or not gate.evidence_ids:
            return TruthStatus.UNKNOWN
        if evidence_map is not None:
            for ev_id in gate.evidence_ids:
                if ev_id not in evidence_map:
                    return TruthStatus.UNKNOWN
                ev = evidence_map[ev_id]
                if ev.status is TruthStatus.BLOCKED:
                    return TruthStatus.BLOCKED
                if ev.status is not TruthStatus.PASS:
                    return TruthStatus.UNKNOWN
                # Provenance requirement
                if not ev.provenance or not ev.provenance.strip():
                    return TruthStatus.UNKNOWN
                # Freshness requirement
                if now is not None and ev.verified_at is not None:
                    if ev.verified_at.tzinfo is None or now.tzinfo is None:
                        return TruthStatus.UNKNOWN
                    if ev.verified_at > now + MAX_CLOCK_SKEW:
                        return TruthStatus.UNKNOWN
                    if now - ev.verified_at > max_evidence_age:
                        return TruthStatus.UNKNOWN
        return TruthStatus.PASS
    return gate.status


def weighted_gate_readiness(
    items: Iterable[Gate],
    evidence_map: Mapping[str, Evidence] | None = None,
    now: datetime | None = None,
) -> float | None:
    """Count only effective PASS gates toward readiness."""
    values = tuple(items)
    if not values or any(not _valid_weight(item.weight) for item in values):
        return None
    earned = sum(
        item.weight
        for item in values
        if effective_gate_status(item, evidence_map=evidence_map, now=now) is TruthStatus.PASS
    )
    return round(100 * earned / sum(item.weight for item in values), 1)


def runtime_truth(
    persisted_status: str | None,
    heartbeat: datetime | None,
    now: datetime,
    *,
    observed_status: RuntimeStatus | str | None = None,
    blocker: str | None = None,
) -> RuntimeStatus:
    """Resolve runtime truth with strict stale-precedence."""
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

    norm_obs = normalize_runtime_status(observed_status)
    if norm_obs is RuntimeStatus.UNKNOWN:
        return RuntimeStatus.UNKNOWN

    if persisted_status:
        norm_per = normalize_runtime_status(persisted_status)
        if norm_per is RuntimeStatus.UNKNOWN:
            return RuntimeStatus.BLOCKED
        if norm_per != norm_obs:
            return RuntimeStatus.BLOCKED

    return norm_obs
