"""Signed external journal contracts; local storage is never the witness."""

from __future__ import annotations

import base64
import hashlib
import json
import re
from abc import ABC, abstractmethod
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .authority import TrustAnchorError, ZERO_HASH, _hash, _identifier


def canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("utf-8")


def digest(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


@dataclass(frozen=True)
class DeploymentIdentity:
    """Release-pinned values, installed in the service image by governance."""

    gcp_project: str
    project_number: str
    bucket: str
    bucket_created_at: str
    kms_key_version: str
    public_key_pem: str
    deployment_identity: str
    governance_version: str
    service_email: str
    oracle_subject: str
    admin_subject: str
    audience: str
    retention_seconds: int
    service_subject: str
    service_revision: str
    genesis_record_hash: str
    bucket_iam_policy_sha256: str
    kms_iam_policy_sha256: str
    witness_type: str = "GOOGLE_CLOUD_STORAGE"

    def validate(self) -> None:
        if self.witness_type != "GOOGLE_CLOUD_STORAGE":
            raise TrustAnchorError("PRODUCTION_WITNESS_TYPE_REQUIRED")
        for name in ("gcp_project", "bucket", "deployment_identity", "governance_version"):
            _identifier(name, getattr(self, name))
        for name in ("genesis_record_hash", "bucket_iam_policy_sha256", "kms_iam_policy_sha256"):
            _hash(name, getattr(self, name))
        _identifier("service_revision", self.service_revision)
        if (not re.fullmatch(r"[0-9]+", self.project_number)
                or type(self.retention_seconds) is not int or self.retention_seconds < 1
                or not self.bucket_created_at
                or not self.audience.startswith("https://")
                or not self.service_email.endswith(".iam.gserviceaccount.com")
                or not all(isinstance(s, str) and re.fullmatch(r"[0-9]+", s)
                           for s in (self.oracle_subject, self.admin_subject, self.service_subject))
                or len({self.oracle_subject, self.admin_subject, self.service_subject}) != 3
                or not re.fullmatch(r"projects/" + re.escape(self.gcp_project)
                    + r"/locations/[^/]+/keyRings/[^/]+/cryptoKeys/[^/]+/cryptoKeyVersions/[1-9][0-9]*",
                    self.kms_key_version)):
            raise TrustAnchorError("DEPLOYMENT_IDENTITY_INVALID")
        self.public_key()
        try:
            stamp = datetime.fromisoformat(self.bucket_created_at)
            if stamp.tzinfo is None:
                raise ValueError("timezone required")
        except (TypeError, ValueError) as exc:
            raise TrustAnchorError("DEPLOYMENT_IDENTITY_INVALID") from exc

    def public_key(self) -> Ed25519PublicKey:
        try:
            key = serialization.load_pem_public_key(self.public_key_pem.encode("ascii"))
            if not isinstance(key, Ed25519PublicKey):
                raise ValueError("Ed25519 required")
            return key
        except Exception as exc:
            raise TrustAnchorError("AUTHORITY_FINGERPRINT_MISMATCH") from exc

    @property
    def authority_fingerprint(self) -> str:
        public = self.public_key().public_bytes(serialization.Encoding.DER,
                                                serialization.PublicFormat.SubjectPublicKeyInfo)
        return digest(canonical({
            "kms_key_version": self.kms_key_version, "public_key_sha256": digest(public),
            "deployment_identity": self.deployment_identity, "bucket": self.bucket,
            "bucket_created_at": self.bucket_created_at, "project_number": self.project_number,
            "gcp_project": self.gcp_project, "governance_version": self.governance_version,
            "service_email": self.service_email, "service_subject": self.service_subject,
            "service_revision": self.service_revision, "oracle_subject": self.oracle_subject,
            "admin_subject": self.admin_subject, "audience": self.audience,
            "retention_seconds": self.retention_seconds,
            "bucket_iam_policy_sha256": self.bucket_iam_policy_sha256,
            "kms_iam_policy_sha256": self.kms_iam_policy_sha256,
        }))

    def check_configuration(self, configuration: dict[str, Any]) -> None:
        self.validate()
        if configuration.get("witness_type") != "GOOGLE_CLOUD_STORAGE":
            raise TrustAnchorError("PRODUCTION_WITNESS_TYPE_REQUIRED")
        expected = asdict(self)
        if any(configuration.get(k) != expected[k] for k in
               ("kms_key_version", "public_key_pem")):
            raise TrustAnchorError("AUTHORITY_FINGERPRINT_MISMATCH")
        if any(configuration.get(k) != expected[k] for k in
               ("bucket", "gcp_project", "project_number", "bucket_created_at")):
            raise TrustAnchorError("WITNESS_IDENTITY_MISMATCH")
        if configuration != expected:
            raise TrustAnchorError("AUTHORITY_IDENTITY_MISMATCH")


class Signer(ABC):
    @abstractmethod
    def sign(self, message: bytes) -> bytes:
        """Sign canonical bytes without exposing private key material."""


@dataclass(frozen=True)
class WitnessRecord:
    record_type: str
    schema_version: int
    authority_fingerprint: str
    deployment_identity: str
    project_id: str
    run_id: str
    anchor_namespace_id: str
    code_under_test_sha: str
    governance_version: str
    sequence: int
    previous_record_hash: str
    payload_json: str
    payload_hash: str
    timestamp: str
    kms_key_version: str
    signature: str

    def unsigned(self) -> dict[str, Any]:
        result = asdict(self)
        result.pop("signature")
        return result

    @property
    def record_hash(self) -> str:
        return digest(self.encode())

    def encode(self) -> bytes:
        return canonical(asdict(self))

    @classmethod
    def decode(cls, data: bytes) -> WitnessRecord:
        try:
            record = cls(**json.loads(data))
            if record.encode() != data:
                raise ValueError("noncanonical record")
            return record
        except Exception as exc:
            raise TrustAnchorError("WITNESS_RECORD_INVALID") from exc

    def verify(self, identity: DeploymentIdentity) -> None:
        if (self.authority_fingerprint != identity.authority_fingerprint
                or self.deployment_identity != identity.deployment_identity
                or self.kms_key_version != identity.kms_key_version
                or self.governance_version != identity.governance_version):
            raise TrustAnchorError("AUTHORITY_IDENTITY_MISMATCH")
        try:
            if (self.record_type not in {"DEPLOYMENT_GENESIS", "AUTHORIZATION_EPOCH", "CHECKPOINT_HEAD"}
                    or type(self.schema_version) is not int or self.schema_version != 1
                    or type(self.sequence) is not int or self.sequence < 0):
                raise ValueError("record schema")
            for name in ("project_id", "run_id", "anchor_namespace_id"):
                _identifier(name, getattr(self, name))
            for name in ("code_under_test_sha", "previous_record_hash", "payload_hash"):
                _hash(name, getattr(self, name))
            if digest(self.payload_json.encode("utf-8")) != self.payload_hash:
                raise ValueError("payload hash")
            if canonical(json.loads(self.payload_json)).decode() != self.payload_json:
                raise ValueError("payload encoding")
            stamp = datetime.fromisoformat(self.timestamp)
            if stamp.tzinfo is None or stamp.utcoffset() != timezone.utc.utcoffset(stamp):
                raise ValueError("timestamp")
            identity.public_key().verify(base64.b64decode(self.signature, validate=True),
                                         canonical(self.unsigned()))
        except Exception as exc:
            raise TrustAnchorError("WITNESS_RECORD_INVALID") from exc


class MonotonicWitness(ABC):
    """No delete, reset, overwrite, or arbitrary object-write capability."""

    @abstractmethod
    def verify_authority_identity(self) -> None:
        """Authenticate the witness and attest its pinned deployment posture."""

    @abstractmethod
    def read_current_state(self) -> tuple[WitnessRecord, ...]:
        """Read the entire authority journal, including all governed runs."""

    @abstractmethod
    def append_authorization_epoch(self, record: WitnessRecord) -> None:
        """Atomically create the next authorization record."""

    @abstractmethod
    def append_checkpoint_head(self, record: WitnessRecord) -> None:
        """Atomically create the next checkpoint record."""

    def verify_continuity(self, identity: DeploymentIdentity) -> tuple[WitnessRecord, ...]:
        self.verify_authority_identity()
        records = self.read_current_state()
        if (not records or records[0].record_type != "DEPLOYMENT_GENESIS"
                or records[0].record_hash != identity.genesis_record_hash):
            raise TrustAnchorError("GOVERNED_GENESIS_REQUIRED")
        previous = ZERO_HASH
        for sequence, record in enumerate(records):
            record.verify(identity)
            if record.sequence != sequence or record.previous_record_hash != previous:
                raise TrustAnchorError("WITNESS_CONTINUITY_FAILURE")
            if sequence and record.record_type == "DEPLOYMENT_GENESIS":
                raise TrustAnchorError("GENESIS_REPLACEMENT_REJECTED")
            previous = record.record_hash
        return records

    def verify_run_identity(self, identity: DeploymentIdentity, run_id: str) -> WitnessRecord:
        records = self.verify_continuity(identity)
        for record in records:
            if record.run_id == run_id and record.record_type == "AUTHORIZATION_EPOCH":
                return record
        raise TrustAnchorError("UNKNOWN_RUN")
