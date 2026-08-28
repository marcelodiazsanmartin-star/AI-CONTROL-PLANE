"""Authority-owned Ed25519 external-adapter trust profiles for AF-05."""
from __future__ import annotations

import base64
import hashlib
import json
import math
import re
from dataclasses import dataclass

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .store import BlockedError, IntegrityBlockedError

AUTHENTICATION_SCOPE = "AUTHENTICATED_EXTERNAL_ADAPTER"
SIGNATURE_ALGORITHM = "ED25519"
_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}")
ALLOWED_CAPABILITIES = frozenset({
    "OBSERVE_STATUS", "AUDIT_READ", "ANALYZE_READ_ONLY", "GENERATE_REPORT",
    "RUN_READ_ONLY_TESTS", "OBSERVE_READ_ONLY", "PREPARE_READ_ONLY", "NO_OP",
})


def identifier(value: object, label: str) -> str:
    if not isinstance(value, str) or not _IDENTIFIER.fullmatch(value):
        raise BlockedError(f"invalid {label}")
    return value


def canonical_json(value: object) -> bytes:
    try:
        return json.dumps(value, sort_keys=True, separators=(",", ":"),
                          ensure_ascii=True, allow_nan=False).encode("ascii")
    except (TypeError, ValueError) as exc:
        raise BlockedError("non-canonical signed payload") from exc


def signed_bytes(domain: str, value: dict[str, object]) -> bytes:
    if not domain.startswith("AI-CONTROL-PLANE/AF05/"):
        raise BlockedError("invalid signature domain")
    body = {key: item for key, item in value.items() if key != "signature"}
    return domain.encode("ascii") + b"\n" + canonical_json(body)


@dataclass(frozen=True)
class TrustedWorkerProfile:
    worker_id: str
    worker_kind: str
    key_id: str
    public_key_base64: str
    capabilities: tuple[str, ...]
    allowed_targets: tuple[str, ...]
    max_capacity: int
    heartbeat_sla: float
    enabled: bool = True
    revoked: bool = False
    profile_version: int = 1
    signature_algorithm: str = SIGNATURE_ALGORITHM


@dataclass(frozen=True)
class VerifiedProfile:
    profile: TrustedWorkerProfile
    public_key: Ed25519PublicKey
    fingerprint: str
    digest: str


class TrustedWorkerRegistry:
    """Immutable authority input; workers have no enrollment or mutation method."""

    def __init__(self, profiles: tuple[TrustedWorkerProfile, ...]):
        self._profiles: dict[str, VerifiedProfile] = {}
        for profile in profiles:
            verified = self._verify_profile(profile)
            if profile.worker_id in self._profiles:
                raise IntegrityBlockedError("duplicate trusted worker")
            self._profiles[profile.worker_id] = verified

    @staticmethod
    def _verify_profile(profile: TrustedWorkerProfile) -> VerifiedProfile:
        identifier(profile.worker_id, "worker_id"); identifier(profile.worker_kind, "worker_kind")
        identifier(profile.key_id, "key_id")
        if profile.signature_algorithm != SIGNATURE_ALGORITHM:
            raise BlockedError("unsupported signature algorithm")
        if not isinstance(profile.profile_version, int) or isinstance(profile.profile_version, bool) or profile.profile_version <= 0:
            raise BlockedError("invalid profile version")
        capabilities = tuple(sorted(set(profile.capabilities)))
        targets = tuple(sorted(set(profile.allowed_targets)))
        if not capabilities or not targets or any(item not in ALLOWED_CAPABILITIES for item in capabilities):
            raise BlockedError("invalid trusted capability or target")
        for item in (*capabilities, *targets): identifier(item, "trusted label")
        if (isinstance(profile.max_capacity, bool) or not isinstance(profile.max_capacity, int)
                or profile.max_capacity <= 0 or profile.max_capacity > 1024
                or isinstance(profile.heartbeat_sla, bool)
                or not isinstance(profile.heartbeat_sla, (int, float))
                or not math.isfinite(float(profile.heartbeat_sla)) or profile.heartbeat_sla <= 0):
            raise BlockedError("invalid trusted capacity or SLA")
        try:
            raw = base64.b64decode(profile.public_key_base64, validate=True)
            if len(raw) != 32: raise ValueError("length")
            public_key = Ed25519PublicKey.from_public_bytes(raw)
        except Exception as exc:
            raise BlockedError("invalid Ed25519 public key") from exc
        fingerprint = hashlib.sha256(raw).hexdigest()
        manifest = {
            "worker_id": profile.worker_id, "worker_kind": profile.worker_kind,
            "key_id": profile.key_id, "signature_algorithm": profile.signature_algorithm,
            "public_key_fingerprint": fingerprint, "capabilities": capabilities,
            "allowed_targets": targets, "max_capacity": profile.max_capacity,
            "heartbeat_sla": float(profile.heartbeat_sla), "enabled": profile.enabled,
            "revoked": profile.revoked, "profile_version": profile.profile_version,
            "verification_scope": AUTHENTICATION_SCOPE,
        }
        return VerifiedProfile(profile, public_key, fingerprint,
                               hashlib.sha256(canonical_json(manifest)).hexdigest())

    def get(self, worker_id: str) -> VerifiedProfile:
        profile = self._profiles.get(identifier(worker_id, "worker_id"))
        if profile is None or not profile.profile.enabled or profile.profile.revoked:
            raise BlockedError("worker trust unavailable")
        return profile

    def all(self) -> tuple[VerifiedProfile, ...]:
        return tuple(self._profiles[key] for key in sorted(self._profiles))
