"""Public data contracts and verification; no production private authority."""

from __future__ import annotations

import base64
import hashlib
import json
import re
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping, Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

ZERO_HASH = "0" * 64
HEX64 = re.compile(r"^[0-9a-f]{64}$")
IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")


class TrustAnchorError(RuntimeError):
    """Explicit fail-closed trust-boundary rejection."""


class AuthorityUnavailableError(TrustAnchorError):
    """Authoritative storage or signing capability is unavailable."""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _canonical(value: Mapping[str, Any]) -> bytes:
    return json.dumps(dict(value), sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("utf-8")


def _digest(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _identifier(name: str, value: str) -> str:
    if not isinstance(value, str) or not IDENTIFIER.fullmatch(value):
        raise TrustAnchorError(f"INVALID_{name.upper()}")
    return value


def _hash(name: str, value: str) -> str:
    if not isinstance(value, str) or not HEX64.fullmatch(value):
        raise TrustAnchorError(f"INVALID_{name.upper()}")
    return value


def _signature(value: str) -> bytes:
    try:
        result = base64.b64decode(value.encode("ascii"), validate=True)
    except Exception as exc:
        raise TrustAnchorError("AUTHORIZATION_SIGNATURE_MALFORMED") from exc
    if len(result) != 64:
        raise TrustAnchorError("AUTHORIZATION_SIGNATURE_MALFORMED")
    return result


@dataclass(frozen=True)
class GovernedRunIdentity:
    project_id: str
    run_id: str
    anchor_namespace_id: str
    code_under_test_sha: str
    governance_version: str
    created_at: str
    authority_id: str


@dataclass(frozen=True)
class AnchorAuthorization:
    authority_id: str
    project_id: str
    run_id: str
    anchor_namespace_id: str
    code_under_test_sha: str
    anchor_locator_or_identity: str
    governance_version: str
    issued_at: str
    authorization_sequence: int
    authorization_integrity: str

    def unsigned(self) -> dict[str, Any]:
        result = asdict(self)
        result.pop("authorization_integrity")
        return result

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "AnchorAuthorization":
        if set(value) != set(cls.__dataclass_fields__):
            raise TrustAnchorError("AUTHORIZATION_FIELDS_INVALID")
        try:
            return cls(**{**value, "authorization_sequence": int(value["authorization_sequence"])})
        except (TypeError, ValueError) as exc:
            raise TrustAnchorError("AUTHORIZATION_MALFORMED") from exc


@dataclass(frozen=True)
class CheckpointProposal:
    run_id: str
    anchor_namespace_id: str
    checkpoint_sequence: int
    checkpoint_hash: str
    manifest_hash: str
    previous_accepted_hash: str
    code_under_test_sha: str
    checkpoint_bytes: bytes
    manifest_bytes: bytes

    def __post_init__(self) -> None:
        # Freeze caller-owned buffers before any hashing, validation or I/O.
        for field in ("checkpoint_bytes", "manifest_bytes"):
            value = getattr(self, field)
            if not isinstance(value, (bytes, bytearray, memoryview)):
                raise TrustAnchorError("CHECKPOINT_INPUT_INVALID")
            object.__setattr__(self, field, bytes(value))
        if type(self.checkpoint_sequence) is not int or self.checkpoint_sequence < 0:
            raise TrustAnchorError("CHECKPOINT_SEQUENCE_INVALID")


class AnchorAuthorizationVerifier:
    """Public-only verifier suitable for the ORACLE consumer boundary."""

    def __init__(self, authority_id: str, public_key_bytes: bytes):
        self.authority_id = _identifier("authority_id", authority_id)
        try:
            self._public_key = Ed25519PublicKey.from_public_bytes(public_key_bytes)
        except (TypeError, ValueError) as exc:
            raise TrustAnchorError("PUBLIC_VERIFIER_INVALID") from exc

    @property
    def public_key_bytes(self) -> bytes:
        return self._public_key.public_bytes(serialization.Encoding.Raw,
                                             serialization.PublicFormat.Raw)

    def verify(self, authorization: AnchorAuthorization | Mapping[str, Any], **expected: str) -> AnchorAuthorization:
        artifact = authorization if isinstance(authorization, AnchorAuthorization) else AnchorAuthorization.from_dict(authorization)
        if artifact.authority_id != self.authority_id:
            raise TrustAnchorError("UNKNOWN_AUTHORITY")
        aliases = {"anchor_namespace_id": "anchor_namespace_id",
                   "code_under_test_sha": "code_under_test_sha",
                   "governance_version": "governance_version",
                   "project_id": "project_id", "run_id": "run_id"}
        for name, attribute in aliases.items():
            if name in expected and expected[name] != getattr(artifact, attribute):
                raise TrustAnchorError(f"{name.upper()}_MISMATCH")
        if artifact.authorization_sequence < 1:
            raise TrustAnchorError("AUTHORIZATION_SEQUENCE_INVALID")
        try:
            self._public_key.verify(_signature(artifact.authorization_integrity),
                                    _canonical(artifact.unsigned()))
        except InvalidSignature as exc:
            raise TrustAnchorError("AUTHORIZATION_SIGNATURE_INVALID") from exc
        return artifact


