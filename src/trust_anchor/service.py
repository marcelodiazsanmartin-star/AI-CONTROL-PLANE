"""Separate authority service core. Only authenticated, capability-scoped RPCs."""

from __future__ import annotations

import base64
import json
import os
import threading
import uuid
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .authority import CheckpointProposal, TrustAnchorError, AuthorityUnavailableError, ZERO_HASH, _hash, _identifier
from .witness import DeploymentIdentity, MonotonicWitness, Signer, WitnessRecord, canonical, digest


class LocalState:
    """Operational high-water cache, provisioned explicitly; never a witness."""

    def __init__(self, path: Path):
        self.path = Path(path)

    @staticmethod
    def snapshot(identity: DeploymentIdentity, records: tuple[WitnessRecord, ...]) -> bytes:
        return canonical({"authority_fingerprint": identity.authority_fingerprint,
                          "sequence": records[-1].sequence, "record_hash": records[-1].record_hash})

    def reconcile(self, identity: DeploymentIdentity, records: tuple[WitnessRecord, ...]) -> None:
        try:
            if self.path.is_symlink() or self.path.read_bytes() != self.snapshot(identity, records):
                raise TrustAnchorError("LOCAL_STATE_ROLLBACK_OR_DIVERGENCE")
        except TrustAnchorError:
            raise
        except Exception as exc:
            raise AuthorityUnavailableError("LOCAL_STATE_MISSING_OR_UNAVAILABLE") from exc

    def advance(self, identity: DeploymentIdentity, records: tuple[WitnessRecord, ...]) -> None:
        # Only after a verified external append. Failure never rolls back cloud.
        temporary = self.path.with_name(self.path.name + "." + uuid.uuid4().hex + ".pending")
        try:
            with temporary.open("xb") as stream:
                stream.write(self.snapshot(identity, records))
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, self.path)
        except Exception as exc:
            raise AuthorityUnavailableError("LOCAL_CACHE_ADVANCE_FAILED_EXTERNAL_RECORD_PRESERVED") from exc


class GoogleOIDCAuthenticator:
    """Validate signed Google tokens, expiry, issuer, exact audience and subject."""

    def __init__(self, identity: DeploymentIdentity, request):
        self.identity = identity
        self._request = request

    def authenticate(self, bearer: str) -> str:
        try:
            from google.oauth2.id_token import verify_oauth2_token
            claims = verify_oauth2_token(bearer, self._request, audience=self.identity.audience)
            now = datetime.now(timezone.utc).timestamp()
            if (claims.get("iss") not in ("https://accounts.google.com", "accounts.google.com")
                    or claims.get("aud") != self.identity.audience
                    or claims.get("email_verified") is not True
                    or type(claims.get("exp")) not in (int, float) or claims["exp"] <= now
                    or type(claims.get("iat")) not in (int, float) or claims["iat"] > now
                    or claims.get("sub") not in (self.identity.admin_subject, self.identity.oracle_subject)):
                raise TrustAnchorError("CALLER_AUTHENTICATION_REJECTED")
            return "ADMIN" if claims["sub"] == self.identity.admin_subject else "ORACLE"
        except TrustAnchorError:
            raise
        except Exception as exc:
            raise TrustAnchorError("CALLER_AUTHENTICATION_REJECTED") from exc


class TrustAnchorService:
    """Service-process implementation; never handed to an ORACLE consumer.

    Production construction is runtime.build_production_service. Test doubles
    can exercise this core but are not accepted by that production factory.
    """

    def __init__(self, identity: DeploymentIdentity, witness: MonotonicWitness,
                 signer: Signer, authenticator, local_state: LocalState):
        self.identity = identity
        self._witness = witness
        self._signer = signer
        self._authenticator = authenticator
        self._local = local_state
        self._lock = threading.RLock()
        self._reconcile()

    def _reconcile(self) -> tuple[WitnessRecord, ...]:
        records = self._witness.verify_continuity(self.identity)
        self._derive(records)
        self._local.reconcile(self.identity, records)
        return records

    def _derive(self, records: tuple[WitnessRecord, ...]) -> dict[str, dict]:
        runs = {}
        namespaces = set()
        used_approvals = set()
        try:
            genesis = json.loads(records[0].payload_json)
            if set(genesis) != {"approved_run_requests"} or not isinstance(genesis["approved_run_requests"], list):
                raise ValueError("genesis schema")
            for value in genesis["approved_run_requests"]:
                _hash("approved_request", value)
            for record in records[1:]:
                payload = json.loads(record.payload_json)
                if record.record_type == "AUTHORIZATION_EPOCH":
                    if set(payload) != {"epoch", "request"} or type(payload["epoch"]) is not int:
                        raise ValueError("epoch schema")
                    request = payload["request"]
                    if record.run_id not in runs:
                        self._validate_run_request(request)
                        if (payload["epoch"] != 1 or digest(canonical(request)) not in genesis["approved_run_requests"]
                                or record.anchor_namespace_id in namespaces
                                or request["human_approval_id"] in used_approvals):
                            raise ValueError("unapproved or duplicate genesis")
                        if any(request[k] != getattr(record, k) for k in
                               ("project_id", "run_id", "anchor_namespace_id", "code_under_test_sha", "governance_version")):
                            raise ValueError("genesis binding")
                        runs[record.run_id] = {"genesis": record, "authorization": record, "head": None}
                        namespaces.add(record.anchor_namespace_id)
                        used_approvals.add(request["human_approval_id"])
                    else:
                        run = runs[record.run_id]
                        self._same_run(record, run["genesis"])
                        old = json.loads(run["authorization"].payload_json)
                        if payload["epoch"] != old["epoch"] + 1 or request != old["request"]:
                            raise ValueError("epoch continuity")
                        run["authorization"] = record
                elif record.record_type == "CHECKPOINT_HEAD":
                    run = runs[record.run_id]
                    self._same_run(record, run["genesis"])
                    if set(payload) != {"checkpoint_sequence", "checkpoint_hash", "manifest_hash",
                                        "previous_accepted_hash", "authorization_record_hash"}:
                        raise ValueError("checkpoint schema")
                    for field in ("checkpoint_hash", "manifest_hash", "previous_accepted_hash", "authorization_record_hash"):
                        _hash(field, payload[field])
                    old = json.loads(run["head"].payload_json) if run["head"] else None
                    if (type(payload["checkpoint_sequence"]) is not int
                            or payload["checkpoint_sequence"] != (old["checkpoint_sequence"] + 1 if old else 0)
                            or payload["previous_accepted_hash"] != (old["checkpoint_hash"] if old else ZERO_HASH)
                            or payload["authorization_record_hash"] != run["authorization"].record_hash):
                        raise ValueError("checkpoint continuity")
                    run["head"] = record
                else:
                    raise ValueError("unexpected record")
            return runs
        except TrustAnchorError:
            raise
        except Exception as exc:
            raise TrustAnchorError("WITNESS_SEMANTIC_HISTORY_INVALID") from exc

    @staticmethod
    def _same_run(actual: WitnessRecord, expected: WitnessRecord) -> None:
        if any(getattr(actual, key) != getattr(expected, key) for key in
               ("project_id", "run_id", "anchor_namespace_id", "code_under_test_sha", "governance_version")):
            raise TrustAnchorError("RUN_IDENTITY_MISMATCH")

    def _validate_run_request(self, request: dict) -> None:
        if set(request) != {"action", "project_id", "run_id", "anchor_namespace_id",
                            "code_under_test_sha", "governance_version", "human_approval_id"}:
            raise TrustAnchorError("GENESIS_REQUEST_INVALID")
        if request["action"] != "CREATE_NEW_GOVERNED_RUN":
            raise TrustAnchorError("GENESIS_AUTHORITY_REQUIRED")
        for field in ("project_id", "run_id", "anchor_namespace_id", "human_approval_id"):
            _identifier(field, request[field])
        _hash("code_under_test_sha", request["code_under_test_sha"])
        if request["governance_version"] != self.identity.governance_version:
            raise TrustAnchorError("GOVERNANCE_VERSION_MISMATCH")

    def _record(self, records: tuple[WitnessRecord, ...], kind: str, run: dict, payload: dict) -> WitnessRecord:
        body = canonical(payload).decode("utf-8")
        record = WitnessRecord(kind, 1, self.identity.authority_fingerprint, self.identity.deployment_identity,
            run["project_id"], run["run_id"], run["anchor_namespace_id"], run["code_under_test_sha"],
            self.identity.governance_version, len(records), records[-1].record_hash, body,
            digest(body.encode("utf-8")), datetime.now(timezone.utc).isoformat(), self.identity.kms_key_version, "")
        return replace(record, signature=base64.b64encode(self._signer.sign(canonical(record.unsigned()))).decode("ascii"))

    def _append(self, records: tuple[WitnessRecord, ...], record: WitnessRecord) -> dict:
        record.verify(self.identity)
        self._derive((*records, record))
        if record.record_type == "AUTHORIZATION_EPOCH":
            self._witness.append_authorization_epoch(record)
        else:
            self._witness.append_checkpoint_head(record)
        after = self._witness.verify_continuity(self.identity)
        self._derive(after)
        if len(after) <= record.sequence or after[record.sequence] != record:
            raise TrustAnchorError("WITNESS_APPEND_UNCONFIRMED")
        self._local.advance(self.identity, after)
        return json.loads(record.encode())

    def handle(self, bearer: str, operation: str, request: dict[str, Any]) -> dict:
        role = self._authenticator.authenticate(bearer)
        capabilities = {"ADMIN": {"create_run", "renew_authorization", "get_authorization", "get_head"},
                        "ORACLE": {"get_authorization", "get_head", "propose_checkpoint"}}
        if operation not in capabilities.get(role, set()):
            raise TrustAnchorError("CAPABILITY_DENIED")
        # Snapshot the complete RPC, not just its outer mapping.
        try:
            request = json.loads(canonical(request))
        except Exception as exc:
            raise TrustAnchorError("REQUEST_INVALID") from exc
        with self._lock:
            records = self._reconcile()
            runs = self._derive(records)
            if operation == "create_run":
                self._validate_run_request(request)
                if request["run_id"] in runs:
                    raise TrustAnchorError("RUN_OR_NAMESPACE_ALREADY_REGISTERED")
                if digest(canonical(request)) not in json.loads(records[0].payload_json)["approved_run_requests"]:
                    raise TrustAnchorError("HUMAN_APPROVAL_REQUIRED")
                return self._append(records, self._record(records, "AUTHORIZATION_EPOCH", request,
                                                         {"epoch": 1, "request": request}))
            run_id = _identifier("run_id", request.get("run_id"))
            if run_id not in runs:
                raise TrustAnchorError("UNKNOWN_RUN")
            run = runs[run_id]
            if operation in {"get_authorization", "get_head", "renew_authorization"}:
                if set(request) != {"run_id"}:
                    raise TrustAnchorError("REQUEST_FIELDS_INVALID")
                if operation == "get_authorization":
                    return json.loads(run["authorization"].encode())
                if operation == "get_head":
                    return json.loads(run["head"].encode()) if run["head"] else {"status": "NO_ACCEPTED_HEAD", "run_id": run_id}
                payload = json.loads(run["authorization"].payload_json)
                payload["epoch"] += 1
                return self._append(records, self._record(records, "AUTHORIZATION_EPOCH", payload["request"], payload))
            return self._propose(records, run, request)

    def _propose(self, records: tuple[WitnessRecord, ...], run: dict, request: dict) -> dict:
        fields = {"run_id", "anchor_namespace_id", "checkpoint_sequence", "checkpoint_hash", "manifest_hash",
                  "previous_accepted_hash", "code_under_test_sha", "checkpoint_b64", "manifest_b64", "authorization_record_hash"}
        if set(request) != fields:
            raise TrustAnchorError("REQUEST_FIELDS_INVALID")
        try:
            proposal = CheckpointProposal(*(request[k] for k in ("run_id", "anchor_namespace_id", "checkpoint_sequence",
                "checkpoint_hash", "manifest_hash", "previous_accepted_hash", "code_under_test_sha")),
                base64.b64decode(request["checkpoint_b64"], validate=True),
                base64.b64decode(request["manifest_b64"], validate=True))
        except Exception as exc:
            raise TrustAnchorError("CHECKPOINT_INPUT_INVALID") from exc
        for field in ("run_id", "anchor_namespace_id", "code_under_test_sha"):
            if getattr(proposal, field) != getattr(run["genesis"], field):
                raise TrustAnchorError("RUN_IDENTITY_MISMATCH")
        if request["authorization_record_hash"] != run["authorization"].record_hash:
            raise TrustAnchorError("AUTHORIZATION_REPLAY_REJECTED")
        if digest(proposal.checkpoint_bytes) != proposal.checkpoint_hash or digest(proposal.manifest_bytes) != proposal.manifest_hash:
            raise TrustAnchorError("CHECKPOINT_OR_MANIFEST_HASH_MISMATCH")
        previous = json.loads(run["head"].payload_json) if run["head"] else None
        if proposal.checkpoint_sequence != (previous["checkpoint_sequence"] + 1 if previous else 0):
            raise TrustAnchorError("CHECKPOINT_SEQUENCE_NOT_MONOTONIC")
        if proposal.previous_accepted_hash != (previous["checkpoint_hash"] if previous else ZERO_HASH):
            raise TrustAnchorError("CHECKPOINT_FORK_OR_ROLLBACK_REJECTED")
        payload = {key: request[key] for key in ("checkpoint_sequence", "checkpoint_hash", "manifest_hash",
                                                "previous_accepted_hash", "authorization_record_hash")}
        return self._append(records, self._record(records, "CHECKPOINT_HEAD",
            json.loads(run["authorization"].payload_json)["request"], payload))

