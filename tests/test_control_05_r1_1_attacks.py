"""Adversarial production-contract tests; all cloud operations use offline doubles."""

import base64
import copy
import io
import json
import threading
from concurrent.futures import ThreadPoolExecutor
from dataclasses import FrozenInstanceError, asdict, replace

import pytest

from src.trust_anchor.authority import CheckpointProposal, TrustAnchorError, ZERO_HASH
from src.trust_anchor.google_cloud import GoogleCloudMonotonicWitness, GoogleRestTransport
from src.trust_anchor.http_api import TrustAnchorWSGI
from src.trust_anchor.service import LocalState, TrustAnchorService
from src.trust_anchor.witness import WitnessRecord, canonical, digest
from tests.control05_support import RUN_REQUEST, append_checkpoint, checkpoint, create_run, rig
from tests.test_control_05_r1_1_functional import rpc


@pytest.mark.parametrize("operation", ["create_run", "renew_authorization", "replace_genesis", "sign", "append", "redirect_witness"])
def test_oracle_has_no_authority_capability(tmp_path, operation):
    r = rig(tmp_path)
    before = copy.deepcopy(r.cloud.objects)
    with pytest.raises(TrustAnchorError, match="CAPABILITY_DENIED"):
        r.service.handle("oracle-token", operation, RUN_REQUEST)
    assert r.cloud.objects == before


@pytest.mark.parametrize(("token", "path"), [("oracle-token", "/admin/create_run"),
    ("admin-token", "/oracle/propose_checkpoint"), ("forged-admin", "/admin/create_run"),
    ("", "/admin/create_run"), ("oracle-token", "/oracle/../admin/create_run")])
def test_api_capability_separation(tmp_path, token, path):
    r = rig(tmp_path)
    assert rpc(TrustAnchorWSGI(r.service), path, token, RUN_REQUEST)[0] == "403 Forbidden"
    assert len(r.cloud.objects) == 1


def test_genesis_needs_preapproved_exact_request(tmp_path):
    r = rig(tmp_path)
    for request in ({**RUN_REQUEST, "code_under_test_sha": "b" * 64},
                    {**RUN_REQUEST, "human_approval_id": "invented"},
                    {**RUN_REQUEST, "action": "AUTO_GENESIS"}):
        with pytest.raises(TrustAnchorError):
            r.service.handle("admin-token", "create_run", request)
    assert len(r.cloud.objects) == 1


def test_genesis_replacement_and_duplicate_run_rejected(tmp_path):
    r = rig(tmp_path)
    create_run(r)
    with pytest.raises(TrustAnchorError, match="ALREADY_REGISTERED"):
        create_run(r)
    with pytest.raises(TrustAnchorError, match="APPEND_TYPE"):
        r.witness.append_authorization_epoch(r.genesis)


@pytest.mark.parametrize("missing", ["all", "genesis", "local"])
def test_no_runtime_autoprovisioning(tmp_path, missing):
    r = rig(tmp_path)
    if missing in {"all", "genesis"}:
        r.cloud.objects.clear()
    if missing in {"all", "local"}:
        r.local.path.unlink()
    calls = len(r.cloud.calls)
    with pytest.raises(TrustAnchorError):
        TrustAnchorService(r.identity, r.witness, r.signer, r.auth, r.local)
    assert all(method == "GET" for method, _, _ in r.cloud.calls[calls:])
    if missing in {"all", "local"}:
        assert not r.local.path.exists()


@pytest.mark.parametrize("coordinated", [False, True])
def test_full_local_and_coordinated_pc_rollback(tmp_path, coordinated):
    r = rig(tmp_path)
    authorization = create_run(r)
    local_before = r.local.path.read_bytes()
    oracle_before = checkpoint(authorization)
    first = append_checkpoint(r, authorization)
    external_after = copy.deepcopy(r.cloud.objects)
    # Restore every byte of local authority operational state. Coordinated case
    # additionally restores the ORACLE-side proposal to the same old epoch.
    r.local.path.write_bytes(local_before)
    with pytest.raises(TrustAnchorError, match="LOCAL_STATE_ROLLBACK"):
        TrustAnchorService(r.identity, r.witness, r.signer, r.auth, r.local)
    if coordinated:
        with pytest.raises(TrustAnchorError, match="LOCAL_STATE_ROLLBACK"):
            r.service.handle("oracle-token", "propose_checkpoint", oracle_before)
    assert r.cloud.objects == external_after
    assert r.witness.verify_continuity(r.identity)[-1] == first


def test_oracle_only_rollback_rejected_by_external_head(tmp_path):
    r = rig(tmp_path)
    authorization = create_run(r)
    old = checkpoint(authorization)
    append_checkpoint(r, authorization)
    with pytest.raises(TrustAnchorError, match="SEQUENCE_NOT_MONOTONIC"):
        r.service.handle("oracle-token", "propose_checkpoint", old)


def test_cloned_local_storage_cannot_replace_cloud(tmp_path):
    r = rig(tmp_path)
    authorization = create_run(r)
    clone = LocalState(tmp_path / "cloned-head.json")
    clone.path.write_bytes(r.local.path.read_bytes())
    append_checkpoint(r, authorization)
    with pytest.raises(TrustAnchorError, match="LOCAL_STATE_ROLLBACK"):
        TrustAnchorService(r.identity, r.witness, r.signer, r.auth, clone)
    r.cloud.available = False
    with pytest.raises(TrustAnchorError, match="UNAVAILABLE"):
        TrustAnchorService(r.identity, r.witness, r.signer, r.auth, clone)


@pytest.mark.parametrize(("field", "value"), [("bucket", "attacker-bucket"), ("gcp_project", "attacker-project"),
    ("project_number", "888"), ("bucket_created_at", "2027-01-01T00:00:00Z"),
    ("kms_key_version", "projects/attacker/locations/x/keyRings/x/cryptoKeys/x/cryptoKeyVersions/1"),
    ("public_key_pem", "forged"), ("deployment_identity", "cloned"), ("service_email", "attacker@example.com"),
    ("audience", "https://attacker.example"), ("oracle_subject", "102"), ("admin_subject", "101"),
    ("genesis_record_hash", "f" * 64), ("witness_type", "LOCAL_SQLITE"),
    ("bucket_iam_policy_sha256", "f" * 64), ("retention_seconds", 1)])
def test_configuration_redirection_rejected(tmp_path, field, value):
    r = rig(tmp_path)
    changed = {**asdict(r.identity), field: value}
    with pytest.raises(TrustAnchorError):
        r.identity.check_configuration(changed)


@pytest.mark.parametrize("mutation", ["unlocked", "short", "missing", "recreated", "project", "versioning", "lifecycle",
    "acl", "public", "iam", "expired"])
def test_witness_startup_attestation_fails_closed(tmp_path, mutation):
    r = rig(tmp_path)
    if mutation == "unlocked":
        r.cloud.bucket["retentionPolicy"]["isLocked"] = False
    elif mutation == "short":
        r.cloud.bucket["retentionPolicy"]["retentionPeriod"] = "1"
    elif mutation == "missing":
        del r.cloud.bucket["retentionPolicy"]
    elif mutation == "recreated":
        r.cloud.bucket["timeCreated"] = "2026-09-11T00:00:00Z"
    elif mutation == "project":
        r.cloud.bucket["projectNumber"] = "999"
    elif mutation == "versioning":
        r.cloud.bucket["versioning"] = {"enabled": True}
    elif mutation == "lifecycle":
        r.cloud.bucket["lifecycle"] = {"rule": [{"action": {"type": "Delete"}}]}
    elif mutation == "acl":
        r.cloud.bucket["iamConfiguration"]["uniformBucketLevelAccess"]["enabled"] = False
    elif mutation == "public":
        r.cloud.bucket["iamConfiguration"]["publicAccessPrevention"] = "inherited"
    elif mutation == "iam":
        r.cloud.bucket_policy["bindings"].append({"role": "roles/storage.admin", "members": ["allUsers"]})
    elif mutation == "expired":
        next(iter(r.cloud.objects.values()))["metadata"]["retentionExpirationTime"] = "2000-01-01T00:00:00Z"
    with pytest.raises(TrustAnchorError):
        r.service.handle("oracle-token", "get_head", {"run_id": "run-1"})


@pytest.mark.parametrize("operation", ["get_head", "get_authorization", "propose_checkpoint", "create_run"])
def test_witness_unavailable_no_cache_fallback(tmp_path, operation):
    r = rig(tmp_path)
    create_run(r)
    r.cloud.available = False
    role = "admin-token" if operation == "create_run" else "oracle-token"
    with pytest.raises(TrustAnchorError, match="UNAVAILABLE"):
        r.service.handle(role, operation, {"run_id": "run-1"})


def test_signer_corruption_and_iam_change_rejected(tmp_path):
    r = rig(tmp_path)
    r.cloud.corrupt_signature = True
    with pytest.raises(TrustAnchorError, match="SIGNATURE_UNVERIFIABLE"):
        create_run(r)
    r.cloud.corrupt_signature = False
    r.cloud.kms_policy["bindings"] = []
    with pytest.raises(TrustAnchorError, match="KMS_ATTESTATION_FAILED"):
        create_run(r)
    assert len(r.cloud.objects) == 1


def test_immutable_input_defensive_snapshot(tmp_path):
    data, manifest = bytearray(b"original"), bytearray(b"manifest")
    proposal = CheckpointProposal("run-1", "namespace-1", 0, digest(data), digest(manifest), ZERO_HASH,
                                  "a" * 64, data, memoryview(manifest))
    data[:] = b"mutated!"
    manifest[:] = b"changed!"
    assert proposal.checkpoint_bytes == b"original" and proposal.manifest_bytes == b"manifest"
    assert type(proposal.checkpoint_bytes) is bytes and type(proposal.manifest_bytes) is bytes
    with pytest.raises(FrozenInstanceError):
        proposal.checkpoint_bytes = b"replaced"


@pytest.mark.parametrize("field", ["checkpoint_b64", "manifest_b64", "previous_accepted_hash", "anchor_namespace_id",
                                    "code_under_test_sha", "authorization_record_hash"])
def test_mutated_proposal_rejected(tmp_path, field):
    r = rig(tmp_path)
    authorization = create_run(r)
    proposal = checkpoint(authorization)
    proposal[field] = base64.b64encode(b"changed").decode() if field.endswith("_b64") else "b" * 64
    with pytest.raises(TrustAnchorError):
        r.service.handle("oracle-token", "propose_checkpoint", proposal)
    assert len(r.cloud.objects) == 2


def test_revoked_authorization_replay(tmp_path):
    r = rig(tmp_path)
    old = create_run(r)
    r.service.handle("admin-token", "renew_authorization", {"run_id": "run-1"})
    with pytest.raises(TrustAnchorError, match="AUTHORIZATION_REPLAY"):
        append_checkpoint(r, old)


def test_ambiguous_upload_never_accepts_or_recreates(tmp_path):
    r = rig(tmp_path)
    before = r.local.path.read_bytes()
    r.cloud.fail_after_append = True
    with pytest.raises(TrustAnchorError, match="AMBIGUOUS_UPLOAD_TIMEOUT"):
        create_run(r)
    assert len(r.cloud.objects) == 2 and r.local.path.read_bytes() == before
    with pytest.raises(TrustAnchorError, match="LOCAL_STATE_ROLLBACK"):
        create_run(r)


def test_two_service_instances_cannot_accept_conflicting_sequence(tmp_path):
    r = rig(tmp_path)
    other_local = LocalState(tmp_path / "other-head.json")
    other_local.path.write_bytes(r.local.path.read_bytes())
    other = TrustAnchorService(r.identity, r.witness, r.signer, r.auth, other_local)
    r.cloud.barrier = threading.Barrier(2)
    def call(service):
        try:
            return service.handle("admin-token", "create_run", RUN_REQUEST)
        except TrustAnchorError as exc:
            return str(exc)
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(call, [r.service, other]))
    assert sum(isinstance(result, dict) for result in results) == 1
    assert "WITNESS_CREATE_CONFLICT" in results
    assert len(r.cloud.objects) == 2


@pytest.mark.parametrize("damage", ["signature", "gap", "genesis", "noncanonical", "duplicate", "signed_semantic_fork"])
def test_corrupt_external_journal_rejected(tmp_path, damage):
    r = rig(tmp_path)
    auth = create_run(r)
    head = append_checkpoint(r, auth)
    names = sorted(r.cloud.objects)
    if damage == "signature":
        r.cloud.objects[names[-1]]["data"] = replace(head, signature="AAAA").encode()
    elif damage == "gap":
        del r.cloud.objects[names[1]]
    elif damage == "genesis":
        del r.cloud.objects[names[0]]
    elif damage == "noncanonical":
        r.cloud.objects[names[-1]]["data"] += b"\n"
    elif damage == "duplicate":
        r.cloud.objects[names[-1] + ".copy"] = copy.deepcopy(r.cloud.objects[names[-1]])
    else:
        payload = json.loads(head.payload_json)
        payload["previous_accepted_hash"] = "f" * 64
        encoded = canonical(payload).decode()
        fork = replace(head, payload_json=encoded, payload_hash=digest(encoded.encode()), signature="")
        fork = replace(fork, signature=base64.b64encode(r.key.sign(canonical(fork.unsigned()))).decode())
        r.cloud.objects[names[-1]]["data"] = fork.encode()
    with pytest.raises(TrustAnchorError):
        TrustAnchorService(r.identity, r.witness, r.signer, r.auth, r.local)


def test_transport_rejects_redirects_errors_and_exceptions():
    class Session:
        def request(self, method, url, **kwargs):
            assert kwargs["allow_redirects"] is False
            return type("Response", (), {"status_code": 302})()
    with pytest.raises(TrustAnchorError, match="GOOGLE_API_UNAVAILABLE"):
        GoogleRestTransport(Session()).request("GET", "https://storage.googleapis.com/example")


@pytest.mark.parametrize(("resource", "permission"), [("witness", "storage.objects.delete"),
    ("witness", "storage.buckets.update"), ("kms", "cloudkms.cryptoKeyVersions.destroy"),
    ("kms", "cloudkms.cryptoKeys.setIamPolicy")])
def test_excess_runtime_capabilities_rejected(tmp_path, resource, permission):
    r = rig(tmp_path)
    getattr(r.cloud, resource + "_permissions").append(permission)
    with pytest.raises(TrustAnchorError, match="CAPABILITY_ATTESTATION_FAILED"):
        create_run(r)
    assert len(r.cloud.objects) == 1


def test_cache_failure_preserves_accepted_external_record(tmp_path, monkeypatch):
    r = rig(tmp_path)
    before = r.local.path.read_bytes()
    def unavailable(*args):
        from src.trust_anchor.authority import AuthorityUnavailableError
        raise AuthorityUnavailableError("LOCAL_CACHE_ADVANCE_FAILED_EXTERNAL_RECORD_PRESERVED")
    monkeypatch.setattr(r.local, "advance", unavailable)
    with pytest.raises(TrustAnchorError, match="EXTERNAL_RECORD_PRESERVED"):
        create_run(r)
    assert len(r.cloud.objects) == 2 and r.local.path.read_bytes() == before
    with pytest.raises(TrustAnchorError, match="LOCAL_STATE_ROLLBACK"):
        create_run(r)
