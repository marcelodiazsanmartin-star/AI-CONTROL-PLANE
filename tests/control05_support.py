"""Offline fixtures only. Private keys and provisioning exist solely in tests."""

import base64
import copy
import json
import threading
from dataclasses import asdict, replace
from types import SimpleNamespace
from urllib.parse import unquote

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from src.trust_anchor.authority import AuthorityUnavailableError, TrustAnchorError, ZERO_HASH
from src.trust_anchor.google_cloud import CreateConflict, GoogleCloudKMSSigner, GoogleCloudMonotonicWitness, policy_hash
from src.trust_anchor.iam import KMS_REQUIRED, WITNESS_REQUIRED
from src.trust_anchor.service import LocalState, TrustAnchorService
from src.trust_anchor.witness import DeploymentIdentity, WitnessRecord, canonical, digest

RUN_REQUEST = {"action": "CREATE_NEW_GOVERNED_RUN", "project_id": "ORACLE-AI", "run_id": "run-1",
    "anchor_namespace_id": "namespace-1", "code_under_test_sha": "a" * 64,
    "governance_version": "CONTROL-05R1.1", "human_approval_id": "human-directive-001"}


class FakeAuthentication:
    def authenticate(self, bearer):
        if bearer == "admin-token":
            return "ADMIN"
        if bearer == "oracle-token":
            return "ORACLE"
        raise TrustAnchorError("CALLER_AUTHENTICATION_REJECTED")


class FakeGoogleCloud:
    """Independent rollback domain, faithfully implements GCS generation CAS."""

    def __init__(self, key, identity):
        self.key = key
        self.identity = identity
        self.objects = {}
        self.calls = []
        self.available = True
        self.fail_after_append = False
        self.corrupt_signature = False
        self.lock = threading.Lock()
        self.barrier = None
        self.kms_permissions = sorted(KMS_REQUIRED)
        self.witness_permissions = sorted(WITNESS_REQUIRED)
        self.bucket_policy = {"version": 3, "bindings": [{"role": "projects/test/roles/witness",
            "members": ["serviceAccount:" + identity.service_email]}]}
        self.kms_policy = {"version": 1, "bindings": [{"role": "roles/cloudkms.signerVerifier",
            "members": ["serviceAccount:" + identity.service_email]}]}
        self.bucket = {"name": identity.bucket, "projectNumber": identity.project_number,
            "timeCreated": identity.bucket_created_at,
            "retentionPolicy": {"isLocked": True, "retentionPeriod": str(identity.retention_seconds),
                                "effectiveTime": identity.bucket_created_at},
            "iamConfiguration": {"uniformBucketLevelAccess": {"enabled": True}, "publicAccessPrevention": "enforced"}}

    def seed(self, record):
        name = "journal/" + self.identity.deployment_identity + f"/{record.sequence:020d}.json"
        self.objects[name] = {"data": record.encode(), "metadata": {"name": name,
            "bucket": self.identity.bucket, "generation": str(record.sequence + 100),
            "retentionExpirationTime": "2099-01-01T00:00:00Z"}}

    def request(self, method, url, **kwargs):
        self.calls.append((method, url, copy.deepcopy(kwargs)))
        if not self.available:
            raise AuthorityUnavailableError("FAKE_EXTERNAL_WITNESS_UNAVAILABLE")
        if "cloudkms.googleapis.com" in url:
            if url.endswith(":testIamPermissions"):
                return {"permissions": self.kms_permissions}
            if url.endswith(":getIamPolicy"):
                return copy.deepcopy(self.kms_policy)
            if url.endswith("/publicKey"):
                return {"name": self.identity.kms_key_version, "algorithm": "EC_SIGN_ED25519",
                        "pem": self.identity.public_key_pem}
            if url.endswith(":asymmetricSign"):
                message = base64.b64decode(kwargs["json"]["data"])
                signature = self.key.sign(message + b"changed" if self.corrupt_signature else message)
                return {"name": self.identity.kms_key_version, "signature": base64.b64encode(signature).decode()}
            return {"name": self.identity.kms_key_version, "algorithm": "EC_SIGN_ED25519", "state": "ENABLED"}
        if "/upload/" in url:
            if self.barrier:
                self.barrier.wait(timeout=5)
            assert method == "POST" and kwargs["params"]["ifGenerationMatch"] == 0
            name = kwargs["params"]["name"]
            with self.lock:
                if name in self.objects:
                    raise CreateConflict("WITNESS_CREATE_CONFLICT")
                record = WitnessRecord.decode(kwargs["data"])
                self.seed(record)
            if self.fail_after_append:
                raise AuthorityUnavailableError("AMBIGUOUS_UPLOAD_TIMEOUT")
            return self.objects[name]["metadata"]
        if url.endswith("/iam/testPermissions"):
            return {"permissions": self.witness_permissions}
        if url.endswith("/iam"):
            return copy.deepcopy(self.bucket_policy)
        if url.endswith("/o"):
            prefix = kwargs["params"]["prefix"]
            return {"items": [copy.deepcopy(value["metadata"]) for name, value in self.objects.items() if name.startswith(prefix)]}
        if "/o/" in url:
            obj = self.objects[unquote(url.split("/o/")[1])]
            assert kwargs["params"]["generation"] == obj["metadata"]["generation"]
            assert kwargs["params"]["ifGenerationMatch"] == obj["metadata"]["generation"]
            return obj["data"]
        return copy.deepcopy(self.bucket)


def rig(tmp_path):
    key = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
    public = key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    identity = DeploymentIdentity(gcp_project="test-project", project_number="123456", bucket="test-witness",
        bucket_created_at="2026-01-01T00:00:00Z",
        kms_key_version="projects/test-project/locations/test/keyRings/anchor/cryptoKeys/sign/cryptoKeyVersions/1",
        public_key_pem=public, deployment_identity="deployment-1", governance_version="CONTROL-05R1.1",
        service_email="trust-anchor@test-project.iam.gserviceaccount.com", oracle_subject="101", admin_subject="102",
        audience="https://trust-anchor-example.run.app", retention_seconds=3155760000, service_subject="103",
        service_revision="trust-anchor-00001", genesis_record_hash=ZERO_HASH,
        bucket_iam_policy_sha256=ZERO_HASH, kms_iam_policy_sha256=ZERO_HASH)
    cloud = FakeGoogleCloud(key, identity)
    identity = replace(identity, bucket_iam_policy_sha256=policy_hash(cloud.bucket_policy),
                       kms_iam_policy_sha256=policy_hash(cloud.kms_policy))
    payload = canonical({"approved_run_requests": [digest(canonical(RUN_REQUEST))]}).decode()
    genesis = WitnessRecord("DEPLOYMENT_GENESIS", 1, identity.authority_fingerprint, identity.deployment_identity,
        "CONTROL-PLANE", "deployment-genesis", "deployment-genesis", "d" * 64, identity.governance_version, 0,
        ZERO_HASH, payload, digest(payload.encode()), "2026-01-01T00:00:00+00:00", identity.kms_key_version, "")
    genesis = replace(genesis, signature=base64.b64encode(key.sign(canonical(genesis.unsigned()))).decode())
    identity = replace(identity, genesis_record_hash=genesis.record_hash)
    cloud.identity = identity
    cloud.seed(genesis)
    witness = GoogleCloudMonotonicWitness(identity, cloud)
    signer = GoogleCloudKMSSigner(identity, cloud)
    local = LocalState(tmp_path / "head.json")
    local.path.write_bytes(LocalState.snapshot(identity, (genesis,)))
    auth = FakeAuthentication()
    service = TrustAnchorService(identity, witness, signer, auth, local)
    return SimpleNamespace(identity=identity, cloud=cloud, witness=witness, signer=signer,
        local=local, auth=auth, service=service, key=key, genesis=genesis)


def create_run(r):
    return WitnessRecord(**r.service.handle("admin-token", "create_run", RUN_REQUEST))


def checkpoint(authorization, sequence=0, previous=ZERO_HASH, data=b"checkpoint", manifest=b"manifest"):
    return {"run_id": authorization.run_id, "anchor_namespace_id": authorization.anchor_namespace_id,
        "code_under_test_sha": authorization.code_under_test_sha, "checkpoint_sequence": sequence,
        "checkpoint_hash": digest(data), "manifest_hash": digest(manifest), "previous_accepted_hash": previous,
        "checkpoint_b64": base64.b64encode(data).decode(), "manifest_b64": base64.b64encode(manifest).decode(),
        "authorization_record_hash": authorization.record_hash}


def append_checkpoint(r, authorization, **kwargs):
    return WitnessRecord(**r.service.handle("oracle-token", "propose_checkpoint", checkpoint(authorization, **kwargs)))
