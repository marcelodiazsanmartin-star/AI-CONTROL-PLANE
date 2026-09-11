"""Pinned Google REST adapters. No resource creation, local keys, or ADC fallback."""

from __future__ import annotations

import base64
from datetime import datetime, timezone
from typing import Any
from urllib.parse import quote

from .authority import AuthorityUnavailableError, TrustAnchorError
from .iam import KMS_REQUIRED, KMS_FORBIDDEN, WITNESS_REQUIRED, WITNESS_FORBIDDEN
from .witness import DeploymentIdentity, MonotonicWitness, Signer, WitnessRecord, canonical, digest


class CreateConflict(TrustAnchorError):
    """The immutable sequence slot already exists; never overwrite or retry forward."""


class GoogleRestTransport:
    """Created only in the separate service with attached workload credentials."""

    def __init__(self, session):
        self._session = session

    def request(self, method: str, url: str, **kwargs) -> Any:
        try:
            response = self._session.request(method, url, timeout=20,
                                             allow_redirects=False, **kwargs)
            if response.status_code == 412:
                raise CreateConflict("WITNESS_CREATE_CONFLICT")
            if response.status_code not in (200, 201):
                raise AuthorityUnavailableError("GOOGLE_API_UNAVAILABLE")
            return response.content if kwargs.get("params", {}).get("alt") == "media" else response.json()
        except TrustAnchorError:
            raise
        except Exception as exc:
            raise AuthorityUnavailableError("GOOGLE_API_UNAVAILABLE") from exc


def policy_hash(policy: dict) -> str:
    # Etag is an optimistic concurrency token, not a capability. Preserve all
    # bindings/conditions/version; require the governed canonical policy bytes.
    return digest(canonical({k: v for k, v in policy.items() if k != "etag"}))


class GoogleCloudKMSSigner(Signer):
    """KMS PureEdDSA signs raw canonical bytes; only public material is local."""

    def __init__(self, identity: DeploymentIdentity, transport: GoogleRestTransport):
        self.identity = identity
        self._transport = transport
        self._url = "https://cloudkms.googleapis.com/v1/" + identity.kms_key_version

    def attest(self) -> None:
        try:
            version = self._transport.request("GET", self._url)
            public = self._transport.request("GET", self._url + "/publicKey")
            key_url = self._url.rsplit("/cryptoKeyVersions/", 1)[0]
            policy = self._transport.request("GET", key_url + ":getIamPolicy",
                                             params={"options.requestedPolicyVersion": 3})
            granted = self._transport.request("POST", key_url + ":testIamPermissions",
                json={"permissions": sorted(KMS_REQUIRED | KMS_FORBIDDEN)})
            if set(granted.get("permissions", [])) != KMS_REQUIRED:
                raise TrustAnchorError("KMS_CAPABILITY_ATTESTATION_FAILED")
            if (version["name"] != self.identity.kms_key_version
                    or version["state"] != "ENABLED"
                    or version["algorithm"] != "EC_SIGN_ED25519"
                    or public["name"] != self.identity.kms_key_version
                    or public["algorithm"] != "EC_SIGN_ED25519"
                    or public["pem"] != self.identity.public_key_pem
                    or policy_hash(policy) != self.identity.kms_iam_policy_sha256):
                raise TrustAnchorError("KMS_ATTESTATION_FAILED")
        except TrustAnchorError:
            raise
        except Exception as exc:
            raise AuthorityUnavailableError("KMS_ATTESTATION_UNAVAILABLE") from exc

    def sign(self, message: bytes) -> bytes:
        message = bytes(message)
        self.attest()
        try:
            result = self._transport.request("POST", self._url + ":asymmetricSign",
                json={"data": base64.b64encode(message).decode("ascii")})
            if result["name"] != self.identity.kms_key_version:
                raise TrustAnchorError("KMS_SIGNER_REDIRECTION_REJECTED")
            signature = base64.b64decode(result["signature"], validate=True)
            # End-to-end cryptographic check binds the exact input and pinned
            # public key, including a corrupt/redirected signing response.
            self.identity.public_key().verify(signature, message)
            return signature
        except TrustAnchorError:
            raise
        except Exception as exc:
            raise AuthorityUnavailableError("KMS_SIGNATURE_UNVERIFIABLE") from exc


class GoogleCloudMonotonicWitness(MonotonicWitness):
    """One immutable object per global sequence, created with generation=0.

    Every read uses authenticated, uncached GCS REST, verifies protected object
    generations and rejects retention expiry. Local storage never participates
    in ordering. An ambiguous append fails closed; an operator reconciles it.
    """

    def __init__(self, identity: DeploymentIdentity, transport: GoogleRestTransport):
        identity.validate()
        self.identity = identity
        self._transport = transport
        self._bucket_url = "https://storage.googleapis.com/storage/v1/b/" + quote(identity.bucket, safe="")
        self._prefix = "journal/" + identity.deployment_identity + "/"

    def verify_authority_identity(self) -> None:
        try:
            bucket = self._transport.request("GET", self._bucket_url)
            policy = self._transport.request("GET", self._bucket_url + "/iam",
                                             params={"optionsRequestedPolicyVersion": 3})
            granted = self._transport.request("GET", self._bucket_url + "/iam/testPermissions",
                params={"permissions": sorted(WITNESS_REQUIRED | WITNESS_FORBIDDEN)})
            if set(granted.get("permissions", [])) != WITNESS_REQUIRED:
                raise TrustAnchorError("WITNESS_CAPABILITY_ATTESTATION_FAILED")
            retention = bucket["retentionPolicy"]
            iam = bucket["iamConfiguration"]
            if (bucket["name"] != self.identity.bucket
                    or str(bucket["projectNumber"]) != self.identity.project_number
                    or bucket["timeCreated"] != self.identity.bucket_created_at
                    or retention.get("isLocked") is not True
                    or int(retention["retentionPeriod"]) < self.identity.retention_seconds
                    or not retention.get("effectiveTime")
                    or iam["uniformBucketLevelAccess"].get("enabled") is not True
                    or iam.get("publicAccessPrevention") != "enforced"
                    or bucket.get("versioning", {}).get("enabled", False)
                    or bucket.get("lifecycle", {}).get("rule", [])
                    or policy_hash(policy) != self.identity.bucket_iam_policy_sha256):
                raise TrustAnchorError("WITNESS_STARTUP_ATTESTATION_FAILED")
        except TrustAnchorError:
            raise
        except Exception as exc:
            raise AuthorityUnavailableError("WITNESS_ATTESTATION_UNAVAILABLE") from exc

    def read_current_state(self) -> tuple[WitnessRecord, ...]:
        self.verify_authority_identity()
        try:
            objects = []
            token = None
            seen_tokens = set()
            while True:
                params = {"prefix": self._prefix}
                if token:
                    params["pageToken"] = token
                page = self._transport.request("GET", self._bucket_url + "/o", params=params)
                objects.extend(page.get("items", []))
                token = page.get("nextPageToken")
                if not token:
                    break
                if token in seen_tokens:
                    raise TrustAnchorError("WITNESS_PAGINATION_INVALID")
                seen_tokens.add(token)
            records = []
            for sequence, obj in enumerate(sorted(objects, key=lambda x: x["name"])):
                name = self._prefix + f"{sequence:020d}.json"
                if obj["name"] != name or obj.get("bucket") != self.identity.bucket:
                    raise TrustAnchorError("WITNESS_CONTINUITY_FAILURE")
                expiry = datetime.fromisoformat(obj["retentionExpirationTime"])
                if expiry.tzinfo is None or expiry <= datetime.now(timezone.utc):
                    raise TrustAnchorError("WITNESS_RETENTION_EXPIRED")
                generation = str(obj["generation"])
                if not generation.isdigit() or int(generation) < 1:
                    raise TrustAnchorError("WITNESS_GENERATION_INVALID")
                data = self._transport.request("GET", self._bucket_url + "/o/" + quote(name, safe=""),
                    params={"alt": "media", "generation": generation, "ifGenerationMatch": generation},
                    headers={"Cache-Control": "no-cache"})
                records.append(WitnessRecord.decode(data))
            return tuple(records)
        except TrustAnchorError:
            raise
        except Exception as exc:
            raise AuthorityUnavailableError("WITNESS_READ_UNAVAILABLE") from exc

    def _append(self, record: WitnessRecord, expected_type: str) -> None:
        if record.record_type != expected_type:
            raise TrustAnchorError("WITNESS_APPEND_TYPE_INVALID")
        record.verify(self.identity)
        current = self.verify_continuity(self.identity)
        if record.sequence != len(current) or record.previous_record_hash != current[-1].record_hash:
            raise TrustAnchorError("WITNESS_APPEND_CONFLICT")
        name = self._prefix + f"{record.sequence:020d}.json"
        self._transport.request("POST", "https://storage.googleapis.com/upload/storage/v1/b/"
            + quote(self.identity.bucket, safe="") + "/o",
            params={"uploadType": "media", "name": name, "ifGenerationMatch": 0},
            data=record.encode(), headers={"Content-Type": "application/json"})
        # Never report acceptance based solely on an upload response.
        after = self.verify_continuity(self.identity)
        if len(after) <= record.sequence or after[record.sequence] != record:
            raise TrustAnchorError("WITNESS_APPEND_UNCONFIRMED")

    def append_authorization_epoch(self, record: WitnessRecord) -> None:
        self._append(record, "AUTHORIZATION_EPOCH")

    def append_checkpoint_head(self, record: WitnessRecord) -> None:
        self._append(record, "CHECKPOINT_HEAD")
