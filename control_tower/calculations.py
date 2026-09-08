"""Deterministic, fail-closed dashboard calculations with truth and semantic provenance semantics."""

from __future__ import annotations

import re
from datetime import datetime, timedelta
from typing import Any, Iterable, Mapping

from control_tower.models import Evidence, Gate, Milestone, RuntimeStatus, TruthStatus

STALE_AFTER = timedelta(minutes=5)
MAX_CLOCK_SKEW = timedelta(seconds=30)
MAX_EVIDENCE_AGE = timedelta(hours=24)

SHA256_HEX_REGEX = re.compile(r"^[a-f0-9]{64}$")
GIT_HEX_REGEX = re.compile(r"^[a-f0-9]{40,64}$")

PLACEHOLDER_PROVENANCE_TOKENS = frozenset({
    "placeholder",
    "stub",
    "none",
    "test",
    "sec:verified",
    "host:verified",
    "dom:verified",
    "iso:verified",
    "auth:verified",
    "governance:hash:valid",
    "queue:projection:verified",
    "test_evidence_sha:verified",
})

TRUSTED_VERIFIER_IDS: frozenset[str] = frozenset({
    "verifier:gov_baseline_rules",
    "verifier:crypto_test_report_check",
    "verifier:multi_priority_auth_check",
    "verifier:read_only_loopback_policy",
    "verifier:adapter_failure_isolation",
    "verifier:strict_host_header_validation",
    "verifier:safe_dom_no_innerhtml",
    "verifier:queue_read_only_projection",
    "verifier:unit_test_certified",
    "verifier:loopback_check",
})

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


def is_valid_cryptographic_provenance(prov: str | None) -> bool:
    """Validate format of cryptographic provenance strictly against format rules."""
    if not prov or not isinstance(prov, str):
        return False
    p = prov.strip().lower()
    if p in PLACEHOLDER_PROVENANCE_TOKENS:
        return False
    if p.startswith("sha256:"):
        digest = p[7:]
        return bool(SHA256_HEX_REGEX.match(digest))
    if p.startswith("hash:"):
        digest = p[5:]
        return bool(SHA256_HEX_REGEX.match(digest))
    if p.startswith("git:"):
        git_hash = p[4:]
        return bool(GIT_HEX_REGEX.match(git_hash))
    if p.startswith("canonical:"):
        parts = p[10:].split("#sha256:")
        if len(parts) == 2 and parts[0] and SHA256_HEX_REGEX.match(parts[1]):
            return True
        return False
    return False


def is_trusted_verifier(verifier_id: str | None) -> bool:
    """Check if verifier_id is non-empty and belongs to the exact trusted verifier allowlist."""
    if not verifier_id or not isinstance(verifier_id, str):
        return False
    v = verifier_id.strip()
    if not v or "fail" in v.lower():
        return False
    return v in TRUSTED_VERIFIER_IDS


def validate_evidence_semantics(
    ev: Evidence,
    now: datetime | None = None,
    expected_code_identity: str | None = None,
    max_evidence_age: timedelta = MAX_EVIDENCE_AGE,
) -> bool:
    """Validate that evidence proves an executed verification result with mandatory verifier, result, and code identity."""
    # 1. Gate/Evidence claimed status must be PASS
    if ev.status is not TruthStatus.PASS:
        return False

    # 2. verification_result is MANDATORY and must be exactly 'PASS'
    if not ev.verification_result or ev.verification_result.strip().upper() != "PASS":
        return False

    # 3. verifier_id is MANDATORY, non-empty, and from exact trusted verifier registry (R-CT04-05A)
    if not is_trusted_verifier(ev.verifier_id):
        return False

    # 4. code_identity is MANDATORY, non-empty, and valid hex digest
    if not ev.code_identity or not isinstance(ev.code_identity, str):
        return False
    code_id = ev.code_identity.strip().lower()
    if not (SHA256_HEX_REGEX.match(code_id) or GIT_HEX_REGEX.match(code_id)):
        return False

    # 5. Cryptographic provenance format must be valid and strictly consistent with code_identity (R-CT04-05B)
    if not is_valid_cryptographic_provenance(ev.provenance):
        return False
    prov = ev.provenance.strip().lower()
    if prov.startswith("sha256:") and prov[7:] != code_id:
        return False
    if prov.startswith("hash:") and prov[5:] != code_id:
        return False
    if prov.startswith("git:") and prov[4:] != code_id:
        return False
    if prov.startswith("canonical:"):
        parts = prov[10:].split("#sha256:")
        if len(parts) != 2 or parts[1].lower() != code_id:
            return False

    # 6. If expected_code_identity is specified, code_identity must match it
    if expected_code_identity is not None:
        if code_id != expected_code_identity.strip().lower():
            return False

    # 7. verified_at is MANDATORY, timezone-aware, not in future, not stale
    if ev.verified_at is None:
        return False
    if ev.verified_at.tzinfo is None:
        return False
    if now is not None:
        if now.tzinfo is None:
            return False
        if ev.verified_at > now + MAX_CLOCK_SKEW:
            return False
        if now - ev.verified_at > max_evidence_age:
            return False

    return True


def effective_gate_status(
    gate: Gate,
    evidence_map: Mapping[str, Evidence] | None = None,
    now: datetime | None = None,
    expected_code_identity: str | None = None,
    max_evidence_age: timedelta = MAX_EVIDENCE_AGE,
) -> TruthStatus:
    """A claimed PASS without complete verified fresh referenced evidence fails closed.

    CT-01R1 / CT-04 Truth Semantics:
    - Evidence ID must resolve
    - Evidence status must be PASS
    - Verification result is mandatory and must be PASS
    - Verifier identity is mandatory and trusted
    - Code identity is mandatory and matches cryptographic provenance
    - Evidence provenance must be immutable/cryptographic (sha256:, hash:, git:, canonical:)
    - Evidence verified_at must be present, non-future, and within SLA
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
                if not validate_evidence_semantics(
                    ev,
                    now=now,
                    expected_code_identity=expected_code_identity,
                    max_evidence_age=max_evidence_age,
                ):
                    return TruthStatus.UNKNOWN
        return TruthStatus.PASS
    return gate.status


def weighted_gate_readiness(
    items: Iterable[Gate],
    evidence_map: Mapping[str, Evidence] | None = None,
    now: datetime | None = None,
    expected_code_identity: str | None = None,
) -> float | None:
    """Count only effective PASS gates toward readiness."""
    values = tuple(items)
    if not values or any(not _valid_weight(item.weight) for item in values):
        return None
    earned = sum(
        item.weight
        for item in values
        if effective_gate_status(item, evidence_map=evidence_map, now=now, expected_code_identity=expected_code_identity) is TruthStatus.PASS
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
