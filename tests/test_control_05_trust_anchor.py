import hashlib

import pytest

from src.trust_anchor import CheckpointProposal, TrustAnchorAuthority, TrustAnchorError

CODE = "a" * 64


def new_run(authority, suffix="1"):
    return authority.create_governed_run(project_id="ORACLE-AI", run_id=f"run-{suffix}",
        anchor_namespace_id=f"namespace-{suffix}", code_under_test_sha=CODE,
        governance_version="R2.4.1", action="CREATE_NEW_GOVERNED_RUN")


def proposal(run, sequence, previous, data=b"checkpoint", manifest=b"manifest"):
    return CheckpointProposal(run.run_id, run.anchor_namespace_id, sequence,
        hashlib.sha256(data).hexdigest(), hashlib.sha256(manifest).hexdigest(),
        previous, run.code_under_test_sha, data, manifest)


@pytest.fixture
def authority(tmp_path):
    return TrustAnchorAuthority(tmp_path / "cp-authority", "authority-1")


def test_governed_run_binds_required_identity(authority):
    run = new_run(authority)
    assert (run.project_id, run.code_under_test_sha, run.authority_id) == ("ORACLE-AI", CODE, "authority-1")


def test_genesis_requires_governed_action(authority):
    with pytest.raises(TrustAnchorError, match="GENESIS_AUTHORITY_REQUIRED"):
        authority.create_governed_run(project_id="ORACLE-AI", code_under_test_sha=CODE,
            governance_version="R2.4.1", action="EMPTY_DIRECTORY")


def test_public_only_authorization_verifier(authority):
    run = new_run(authority)
    artifact = authority.get_anchor_authorization(run.run_id)
    verifier = authority.public_verifier()
    assert verifier.verify(artifact, project_id=run.project_id, run_id=run.run_id,
        anchor_namespace_id=run.anchor_namespace_id, code_under_test_sha=CODE,
        governance_version="R2.4.1") == artifact
    assert not hasattr(verifier, "_private_key")


def test_monotonic_history_survives_restart(authority):
    run = new_run(authority)
    artifact = authority.get_anchor_authorization(run.run_id)
    first = proposal(run, 0, "0" * 64)
    authority.propose_checkpoint_head(artifact, first)
    second = proposal(run, 1, first.checkpoint_hash, b"second", b"manifest-2")
    authority.propose_checkpoint_head(artifact, second)
    restarted = TrustAnchorAuthority(authority.authority_root, authority.authority_id)
    assert restarted.get_accepted_checkpoint_head(run.run_id)["checkpoint_hash"] == second.checkpoint_hash
    assert restarted.verify_history(run.run_id)


def test_checkpoint_bytes_are_cryptographically_bound(authority):
    run = new_run(authority)
    artifact = authority.get_anchor_authorization(run.run_id)
    value = proposal(run, 0, "0" * 64)
    bad = CheckpointProposal(**{**value.__dict__, "checkpoint_bytes": b"tampered"})
    with pytest.raises(TrustAnchorError, match="CHECKPOINT_HASH_MISMATCH"):
        authority.propose_checkpoint_head(artifact, bad)


def test_new_authorization_invalidates_old(authority):
    run = new_run(authority)
    old = authority.get_anchor_authorization(run.run_id)
    authority.get_anchor_authorization(run.run_id)
    with pytest.raises(TrustAnchorError, match="AUTHORIZATION_REPLAY_REJECTED"):
        authority.verify_anchor_authorization(old)
