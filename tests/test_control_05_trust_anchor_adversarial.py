import hashlib
import sqlite3

import pytest

from src.trust_anchor import (AnchorAuthorization, AnchorAuthorizationVerifier,
    CheckpointProposal, TrustAnchorAuthority, TrustAnchorError)

CODE = "b" * 64


def setup(tmp_path, suffix="1"):
    authority = TrustAnchorAuthority(tmp_path / "control-plane", "production-authority")
    run = authority.create_governed_run(project_id="ORACLE-AI", run_id=f"run-{suffix}",
        anchor_namespace_id=f"namespace-{suffix}", code_under_test_sha=CODE,
        governance_version="R2.4.1", action="CREATE_NEW_GOVERNED_RUN")
    return authority, run


def proposal(run, sequence=0, previous="0" * 64, data=b"cp", manifest=b"manifest"):
    return CheckpointProposal(run.run_id, run.anchor_namespace_id, sequence,
        hashlib.sha256(data).hexdigest(), hashlib.sha256(manifest).hexdigest(),
        previous, run.code_under_test_sha, data, manifest)


def test_arbitrary_external_directory_rejected(tmp_path):
    attacker = TrustAnchorAuthority(tmp_path / "arbitrary", "production-authority")
    with pytest.raises(TrustAnchorError, match="UNKNOWN_RUN"):
        attacker.get_anchor_authorization("run-production")


def test_empty_anchor_cannot_create_production_genesis(tmp_path):
    authority = TrustAnchorAuthority(tmp_path / "empty", "production-authority")
    with pytest.raises(TrustAnchorError, match="GENESIS_AUTHORITY_REQUIRED"):
        authority.create_governed_run(project_id="ORACLE-AI", code_under_test_sha=CODE,
            governance_version="R2.4.1", action="AUTO_GENESIS")


def test_old_authorization_replay_rejected(tmp_path):
    authority, run = setup(tmp_path)
    old = authority.get_anchor_authorization(run.run_id)
    authority.get_anchor_authorization(run.run_id)
    with pytest.raises(TrustAnchorError, match="AUTHORIZATION_REPLAY_REJECTED"):
        authority.verify_anchor_authorization(old)


@pytest.mark.parametrize(("field", "value", "error"), [
    ("run_id", "run-other", "RUN_MISMATCH"),
    ("anchor_namespace_id", "namespace-other", "NAMESPACE_MISMATCH"),
    ("code_under_test_sha", "c" * 64, "CODE_SHA_MISMATCH")])
def test_wrong_identity_binding_rejected(tmp_path, field, value, error):
    authority, run = setup(tmp_path)
    artifact = authority.get_anchor_authorization(run.run_id)
    changed = CheckpointProposal(**{**proposal(run).__dict__, field: value})
    with pytest.raises(TrustAnchorError, match=error):
        authority.propose_checkpoint_head(artifact, changed)


def test_history_rollback_rejected(tmp_path):
    authority, run = setup(tmp_path)
    artifact = authority.get_anchor_authorization(run.run_id)
    first = proposal(run)
    authority.propose_checkpoint_head(artifact, first)
    with pytest.raises(TrustAnchorError, match="CHECKPOINT_SEQUENCE_NOT_MONOTONIC"):
        authority.propose_checkpoint_head(artifact, first)


def test_history_truncation_rejected(tmp_path):
    authority, run = setup(tmp_path)
    artifact = authority.get_anchor_authorization(run.run_id)
    first = proposal(run)
    authority.propose_checkpoint_head(artifact, first)
    authority.propose_checkpoint_head(artifact, proposal(run, 1, first.checkpoint_hash, b"two"))
    with sqlite3.connect(authority._db_path) as db:
        db.execute("DELETE FROM accepted_checkpoints WHERE sequence=1")
    with pytest.raises(TrustAnchorError, match="HISTORY_TRUNCATION_OR_GAP_REJECTED"):
        authority.verify_history(run.run_id)


def test_history_fork_rejected(tmp_path):
    authority, run = setup(tmp_path)
    artifact = authority.get_anchor_authorization(run.run_id)
    first = proposal(run)
    authority.propose_checkpoint_head(artifact, first)
    with pytest.raises(TrustAnchorError, match="CHECKPOINT_FORK_OR_ROLLBACK_REJECTED"):
        authority.propose_checkpoint_head(artifact, proposal(run, 1, "f" * 64, b"fork"))


def test_duplicate_conflicting_sequence_rejected(tmp_path):
    authority, run = setup(tmp_path)
    artifact = authority.get_anchor_authorization(run.run_id)
    authority.propose_checkpoint_head(artifact, proposal(run))
    with pytest.raises(TrustAnchorError, match="CHECKPOINT_SEQUENCE_NOT_MONOTONIC"):
        authority.propose_checkpoint_head(artifact, proposal(run, data=b"conflict"))


def test_oracle_cannot_mint_authorization(tmp_path):
    authority, run = setup(tmp_path)
    artifact = authority.get_anchor_authorization(run.run_id)
    forged = AnchorAuthorization(**{**artifact.to_dict(), "issued_at": "forged"})
    with pytest.raises(TrustAnchorError, match="AUTHORIZATION_SIGNATURE_INVALID"):
        authority.public_verifier().verify(forged)
    assert not hasattr(authority.public_verifier(), "_private_key")


def test_test_authority_unavailable_in_production(tmp_path):
    authority, run = setup(tmp_path)
    verifier = AnchorAuthorizationVerifier("test-authority", authority.public_verifier().public_key_bytes)
    with pytest.raises(TrustAnchorError, match="UNKNOWN_AUTHORITY"):
        verifier.verify(authority.get_anchor_authorization(run.run_id))


def test_missing_control_plane_fails_closed(tmp_path):
    authority, run = setup(tmp_path)
    authority._db_path.unlink()
    with pytest.raises(TrustAnchorError):
        authority.get_accepted_checkpoint_head(run.run_id)


def test_control_plane_history_survives_oracle_rollback(tmp_path):
    authority, run = setup(tmp_path)
    artifact = authority.get_anchor_authorization(run.run_id)
    first = proposal(run)
    authority.propose_checkpoint_head(artifact, first)
    second = proposal(run, 1, first.checkpoint_hash, b"second")
    authority.propose_checkpoint_head(artifact, second)
    with pytest.raises(TrustAnchorError, match="CHECKPOINT_SEQUENCE_NOT_MONOTONIC"):
        authority.propose_checkpoint_head(artifact, proposal(run, 1, first.checkpoint_hash, b"stale"))
    assert authority.get_accepted_checkpoint_head(run.run_id)["checkpoint_hash"] == second.checkpoint_hash


def test_anchor_redirection_rejected(tmp_path):
    authority, run = setup(tmp_path)
    artifact = authority.get_anchor_authorization(run.run_id)
    forged = AnchorAuthorization(**{**artifact.to_dict(), "anchor_locator_or_identity": "file:///attacker"})
    with pytest.raises(TrustAnchorError, match="AUTHORIZATION_SIGNATURE_INVALID"):
        authority.verify_anchor_authorization(forged)


def test_manifest_hash_mismatch_rejected(tmp_path):
    authority, run = setup(tmp_path)
    artifact = authority.get_anchor_authorization(run.run_id)
    value = proposal(run)
    bad = CheckpointProposal(**{**value.__dict__, "manifest_bytes": b"changed"})
    with pytest.raises(TrustAnchorError, match="MANIFEST_HASH_MISMATCH"):
        authority.propose_checkpoint_head(artifact, bad)
