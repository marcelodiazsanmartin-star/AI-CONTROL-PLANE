"""TEST ONLY: legacy local authority; never a production witness or service."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import sqlite3
import threading
import uuid
from contextlib import closing
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping, Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from .authority import (AnchorAuthorization, AnchorAuthorizationVerifier, AuthorityUnavailableError, CheckpointProposal, GovernedRunIdentity, TrustAnchorError, ZERO_HASH, _now, _canonical, _digest, _identifier, _hash, _signature)

class TestOnlyTrustAnchorAuthority:
    """Private issuer; consumers never receive this object or its key."""

    def __init__(self, authority_root: Path, authority_id: str):
        self.authority_root = Path(authority_root).resolve()
        self.authority_id = _identifier("authority_id", authority_id)
        self._lock = threading.RLock()
        parts = {part.lower() for part in self.authority_root.parts}
        if (not self.authority_root.is_absolute() or
                self.authority_root == Path(self.authority_root.anchor) or
                parts.intersection({".git", "state", "reports", "directives"}) or
                (self.authority_root.exists() and self.authority_root.is_symlink())):
            raise TrustAnchorError("AUTHORITY_ROOT_UNSAFE")
        self.authority_root.mkdir(parents=True, exist_ok=True)
        self._key_path = self.authority_root / "authority.ed25519"
        self._db_path = self.authority_root / "anchor_history.sqlite3"
        self._private_key = self._load_key()
        self._initialize()

    def _load_key(self) -> Ed25519PrivateKey:
        try:
            if self._key_path.exists():
                data = self._key_path.read_bytes()
                if len(data) != 32:
                    raise AuthorityUnavailableError("AUTHORITY_PRIVATE_KEY_CORRUPT")
                return Ed25519PrivateKey.from_private_bytes(data)
            key = Ed25519PrivateKey.generate()
            data = key.private_bytes(serialization.Encoding.Raw,
                                     serialization.PrivateFormat.Raw,
                                     serialization.NoEncryption())
            fd = os.open(self._key_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            try:
                os.write(fd, data)
                os.fsync(fd)
            finally:
                os.close(fd)
            return key
        except TrustAnchorError:
            raise
        except Exception as exc:
            raise AuthorityUnavailableError("AUTHORITY_PRIVATE_KEY_UNAVAILABLE") from exc

    def public_verifier(self) -> AnchorAuthorizationVerifier:
        raw = self._private_key.public_key().public_bytes(serialization.Encoding.Raw,
                                                          serialization.PublicFormat.Raw)
        return AnchorAuthorizationVerifier(self.authority_id, raw)

    def _connect(self) -> sqlite3.Connection:
        try:
            db = sqlite3.connect(self._db_path, timeout=5, isolation_level=None)
            db.row_factory = sqlite3.Row
            db.execute("PRAGMA foreign_keys=ON")
            db.execute("PRAGMA journal_mode=WAL")
            db.execute("PRAGMA synchronous=FULL")
            return db
        except sqlite3.Error as exc:
            raise AuthorityUnavailableError("ANCHOR_HISTORY_UNAVAILABLE") from exc

    def _initialize(self) -> None:
        schema = """
        CREATE TABLE IF NOT EXISTS namespaces(namespace_id TEXT PRIMARY KEY, project_id TEXT NOT NULL, locator TEXT NOT NULL UNIQUE, created_at TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS governed_runs(run_id TEXT PRIMARY KEY, project_id TEXT NOT NULL, namespace_id TEXT NOT NULL UNIQUE, code_sha TEXT NOT NULL, governance_version TEXT NOT NULL, created_at TEXT NOT NULL, authority_id TEXT NOT NULL, latest_authorization_sequence INTEGER NOT NULL DEFAULT 0, latest_checkpoint_sequence INTEGER NOT NULL DEFAULT -1, latest_checkpoint_hash TEXT NOT NULL DEFAULT '0000000000000000000000000000000000000000000000000000000000000000', FOREIGN KEY(namespace_id) REFERENCES namespaces(namespace_id));
        CREATE TABLE IF NOT EXISTS authorizations(run_id TEXT NOT NULL, sequence INTEGER NOT NULL, artifact_sha256 TEXT NOT NULL, issued_at TEXT NOT NULL, PRIMARY KEY(run_id,sequence), FOREIGN KEY(run_id) REFERENCES governed_runs(run_id));
        CREATE TABLE IF NOT EXISTS accepted_checkpoints(run_id TEXT NOT NULL, sequence INTEGER NOT NULL, checkpoint_hash TEXT NOT NULL, manifest_hash TEXT NOT NULL, previous_accepted_hash TEXT NOT NULL, code_sha TEXT NOT NULL, accepted_at TEXT NOT NULL, acceptance_integrity TEXT NOT NULL, PRIMARY KEY(run_id,sequence), UNIQUE(run_id,checkpoint_hash), FOREIGN KEY(run_id) REFERENCES governed_runs(run_id));
        """
        try:
            with closing(self._connect()) as db:
                db.executescript(schema)
        except sqlite3.Error as exc:
            raise AuthorityUnavailableError("ANCHOR_HISTORY_UNAVAILABLE") from exc

    def _run(self, db: sqlite3.Connection, run_id: str) -> sqlite3.Row:
        row = db.execute("SELECT r.*,n.locator FROM governed_runs r JOIN namespaces n ON n.namespace_id=r.namespace_id WHERE run_id=?", (run_id,)).fetchone()
        if row is None:
            raise TrustAnchorError("UNKNOWN_RUN")
        if row["authority_id"] != self.authority_id:
            raise TrustAnchorError("UNKNOWN_AUTHORITY")
        return row

    def create_governed_run(self, *, project_id: str, code_under_test_sha: str,
                            governance_version: str, action: str,
                            run_id: Optional[str] = None,
                            anchor_namespace_id: Optional[str] = None) -> GovernedRunIdentity:
        if action != "CREATE_NEW_GOVERNED_RUN":
            raise TrustAnchorError("GENESIS_AUTHORITY_REQUIRED")
        project_id = _identifier("project_id", project_id)
        code_under_test_sha = _hash("code_under_test_sha", code_under_test_sha)
        governance_version = _identifier("governance_version", governance_version)
        run_id = _identifier("run_id", run_id or f"run-{uuid.uuid4().hex}")
        namespace = _identifier("anchor_namespace_id", anchor_namespace_id or f"anchor-{uuid.uuid4().hex}")
        created = _now()
        locator = f"cp-anchor://{self.authority_id}/{namespace}"
        try:
            with self._lock, closing(self._connect()) as db:
                db.execute("BEGIN IMMEDIATE")
                db.execute("INSERT INTO namespaces VALUES(?,?,?,?)", (namespace, project_id, locator, created))
                db.execute("INSERT INTO governed_runs VALUES(?,?,?,?,?,?,?,0,-1,?)", (run_id, project_id, namespace, code_under_test_sha, governance_version, created, self.authority_id, ZERO_HASH))
                db.commit()
        except sqlite3.IntegrityError as exc:
            raise TrustAnchorError("RUN_OR_NAMESPACE_ALREADY_REGISTERED") from exc
        return GovernedRunIdentity(project_id, run_id, namespace, code_under_test_sha,
                                   governance_version, created, self.authority_id)

    def get_anchor_authorization(self, run_id: str) -> AnchorAuthorization:
        issued = _now()
        try:
            with self._lock, closing(self._connect()) as db:
                db.execute("BEGIN IMMEDIATE")
                run = self._run(db, _identifier("run_id", run_id))
                sequence = run["latest_authorization_sequence"] + 1
                unsigned = {"authority_id": self.authority_id, "project_id": run["project_id"],
                            "run_id": run_id, "anchor_namespace_id": run["namespace_id"],
                            "code_under_test_sha": run["code_sha"], "anchor_locator_or_identity": run["locator"],
                            "governance_version": run["governance_version"], "issued_at": issued,
                            "authorization_sequence": sequence}
                signature = base64.b64encode(self._private_key.sign(_canonical(unsigned))).decode("ascii")
                artifact = AnchorAuthorization(**unsigned, authorization_integrity=signature)
                db.execute("INSERT INTO authorizations VALUES(?,?,?,?)", (run_id, sequence, _digest(_canonical(artifact.to_dict())), issued))
                db.execute("UPDATE governed_runs SET latest_authorization_sequence=? WHERE run_id=?", (sequence, run_id))
                db.commit()
                return artifact
        except TrustAnchorError:
            raise
        except sqlite3.Error as exc:
            raise AuthorityUnavailableError("ANCHOR_HISTORY_UNAVAILABLE") from exc

    def verify_anchor_authorization(self, authorization: AnchorAuthorization | Mapping[str, Any]) -> AnchorAuthorization:
        artifact = self.public_verifier().verify(authorization)
        try:
            with closing(self._connect()) as db:
                run = self._run(db, artifact.run_id)
                checks = [(artifact.project_id, run["project_id"], "PROJECT_MISMATCH"),
                          (artifact.anchor_namespace_id, run["namespace_id"], "NAMESPACE_MISMATCH"),
                          (artifact.code_under_test_sha, run["code_sha"], "CODE_SHA_MISMATCH"),
                          (artifact.governance_version, run["governance_version"], "GOVERNANCE_VERSION_MISMATCH"),
                          (artifact.anchor_locator_or_identity, run["locator"], "ANCHOR_REDIRECTION_REJECTED")]
                for actual, expected, error in checks:
                    if actual != expected:
                        raise TrustAnchorError(error)
                if artifact.authorization_sequence != run["latest_authorization_sequence"]:
                    raise TrustAnchorError("AUTHORIZATION_REPLAY_REJECTED")
                row = db.execute("SELECT artifact_sha256 FROM authorizations WHERE run_id=? AND sequence=?", (artifact.run_id, artifact.authorization_sequence)).fetchone()
                if row is None or row[0] != _digest(_canonical(artifact.to_dict())):
                    raise TrustAnchorError("AUTHORIZATION_NOT_ISSUED")
                return artifact
        except TrustAnchorError:
            raise
        except sqlite3.Error as exc:
            raise AuthorityUnavailableError("ANCHOR_HISTORY_UNAVAILABLE") from exc

    def propose_checkpoint_head(self, authorization: AnchorAuthorization | Mapping[str, Any], proposal: CheckpointProposal) -> dict[str, Any]:
        artifact = self.verify_anchor_authorization(authorization)
        checks = [(proposal.run_id, artifact.run_id, "RUN_MISMATCH"),
                  (proposal.anchor_namespace_id, artifact.anchor_namespace_id, "NAMESPACE_MISMATCH"),
                  (proposal.code_under_test_sha, artifact.code_under_test_sha, "CODE_SHA_MISMATCH")]
        for actual, expected, error in checks:
            if actual != expected:
                raise TrustAnchorError(error)
        _hash("checkpoint_hash", proposal.checkpoint_hash)
        _hash("manifest_hash", proposal.manifest_hash)
        _hash("previous_accepted_hash", proposal.previous_accepted_hash)
        if _digest(proposal.checkpoint_bytes) != proposal.checkpoint_hash:
            raise TrustAnchorError("CHECKPOINT_HASH_MISMATCH")
        if _digest(proposal.manifest_bytes) != proposal.manifest_hash:
            raise TrustAnchorError("MANIFEST_HASH_MISMATCH")
        try:
            with self._lock, closing(self._connect()) as db:
                db.execute("BEGIN IMMEDIATE")
                run = self._run(db, proposal.run_id)
                if artifact.authorization_sequence != run["latest_authorization_sequence"]:
                    raise TrustAnchorError("AUTHORIZATION_REPLAY_REJECTED")
                head = db.execute("SELECT * FROM accepted_checkpoints WHERE run_id=? ORDER BY sequence DESC LIMIT 1", (proposal.run_id,)).fetchone()
                expected_sequence = 0 if head is None else head["sequence"] + 1
                expected_previous = ZERO_HASH if head is None else head["checkpoint_hash"]
                if proposal.checkpoint_sequence != expected_sequence:
                    raise TrustAnchorError("CHECKPOINT_SEQUENCE_NOT_MONOTONIC")
                if proposal.previous_accepted_hash != expected_previous:
                    raise TrustAnchorError("CHECKPOINT_FORK_OR_ROLLBACK_REJECTED")
                accepted = _now()
                unsigned = {"run_id": proposal.run_id, "anchor_namespace_id": proposal.anchor_namespace_id,
                            "checkpoint_sequence": proposal.checkpoint_sequence, "checkpoint_hash": proposal.checkpoint_hash,
                            "manifest_hash": proposal.manifest_hash, "previous_accepted_hash": proposal.previous_accepted_hash,
                            "code_under_test_sha": proposal.code_under_test_sha, "accepted_at": accepted}
                integrity = base64.b64encode(self._private_key.sign(_canonical(unsigned))).decode("ascii")
                db.execute("INSERT INTO accepted_checkpoints VALUES(?,?,?,?,?,?,?,?)",
                           (proposal.run_id, proposal.checkpoint_sequence, proposal.checkpoint_hash,
                            proposal.manifest_hash, proposal.previous_accepted_hash,
                            proposal.code_under_test_sha, accepted, integrity))
                db.execute("UPDATE governed_runs SET latest_checkpoint_sequence=?, latest_checkpoint_hash=? WHERE run_id=?",
                           (proposal.checkpoint_sequence, proposal.checkpoint_hash, proposal.run_id))
                db.commit()
                return {**unsigned, "acceptance_integrity": integrity, "status": "ACCEPTED"}
        except TrustAnchorError:
            raise
        except sqlite3.IntegrityError as exc:
            raise TrustAnchorError("DUPLICATE_OR_CONFLICTING_SEQUENCE_REJECTED") from exc
        except sqlite3.Error as exc:
            raise AuthorityUnavailableError("ANCHOR_HISTORY_UNAVAILABLE") from exc

    def get_accepted_checkpoint_head(self, run_id: str) -> dict[str, Any]:
        try:
            with closing(self._connect()) as db:
                run = self._run(db, _identifier("run_id", run_id))
                row = db.execute("SELECT * FROM accepted_checkpoints WHERE run_id=? ORDER BY sequence DESC LIMIT 1", (run_id,)).fetchone()
                if row is None:
                    if run["latest_checkpoint_sequence"] != -1 or run["latest_checkpoint_hash"] != ZERO_HASH:
                        raise TrustAnchorError("HISTORY_TRUNCATION_OR_GAP_REJECTED")
                    return {"status": "NO_ACCEPTED_HEAD", "run_id": run_id}
                if (row["sequence"] != run["latest_checkpoint_sequence"] or
                        row["checkpoint_hash"] != run["latest_checkpoint_hash"]):
                    raise TrustAnchorError("HISTORY_TRUNCATION_OR_GAP_REJECTED")
                return self._verify_row(run, row)
        except TrustAnchorError:
            raise
        except sqlite3.Error as exc:
            raise AuthorityUnavailableError("ANCHOR_HISTORY_UNAVAILABLE") from exc

    def _verify_row(self, run: sqlite3.Row, row: sqlite3.Row) -> dict[str, Any]:
        unsigned = {"run_id": row["run_id"], "anchor_namespace_id": run["namespace_id"],
                    "checkpoint_sequence": row["sequence"], "checkpoint_hash": row["checkpoint_hash"],
                    "manifest_hash": row["manifest_hash"], "previous_accepted_hash": row["previous_accepted_hash"],
                    "code_under_test_sha": row["code_sha"], "accepted_at": row["accepted_at"]}
        try:
            self._private_key.public_key().verify(_signature(row["acceptance_integrity"]), _canonical(unsigned))
        except (InvalidSignature, TrustAnchorError) as exc:
            raise TrustAnchorError("ACCEPTED_HISTORY_INTEGRITY_FAILURE") from exc
        return {**unsigned, "acceptance_integrity": row["acceptance_integrity"], "status": "ACCEPTED"}

    def verify_history(self, run_id: str) -> bool:
        try:
            with closing(self._connect()) as db:
                run = self._run(db, _identifier("run_id", run_id))
                rows = db.execute("SELECT * FROM accepted_checkpoints WHERE run_id=? ORDER BY sequence", (run_id,)).fetchall()
                previous = ZERO_HASH
                for sequence, row in enumerate(rows):
                    if row["sequence"] != sequence:
                        raise TrustAnchorError("HISTORY_TRUNCATION_OR_GAP_REJECTED")
                    if row["previous_accepted_hash"] != previous:
                        raise TrustAnchorError("HISTORY_FORK_REJECTED")
                    if row["code_sha"] != run["code_sha"]:
                        raise TrustAnchorError("CODE_SHA_MISMATCH")
                    self._verify_row(run, row)
                    previous = row["checkpoint_hash"]
                if ((len(rows) - 1) != run["latest_checkpoint_sequence"] or
                        previous != run["latest_checkpoint_hash"]):
                    raise TrustAnchorError("HISTORY_TRUNCATION_OR_GAP_REJECTED")
                return True
        except TrustAnchorError:
            raise
        except sqlite3.Error as exc:
            raise AuthorityUnavailableError("ANCHOR_HISTORY_UNAVAILABLE") from exc
