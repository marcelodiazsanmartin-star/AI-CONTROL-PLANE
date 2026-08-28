"""AF-04 read-only directive queue ingestion with durable provenance binding."""
from __future__ import annotations

import hashlib
import json
import re
import sqlite3
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Callable, Iterable, Protocol

from src.directive.contracts import DirectiveEnvelope, DirectivePayload, ValidationStatus

from .store import AutonomyStore, BlockedError, IntegrityBlockedError, clean

MAX_QUEUE_BYTES = 2_097_152
MAX_RECORD_BYTES = 131_072
MAX_RECORDS = 4096
_HEX40 = re.compile(r"[0-9a-f]{40}")
_HEX64 = re.compile(r"[0-9a-f]{64}")
_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}")

ACTION_CAPABILITIES = {
    "STATUS_REQUEST": "OBSERVE_STATUS",
    "AUDIT_REQUEST": "AUDIT_READ",
    "READ_ONLY_ANALYSIS": "ANALYZE_READ_ONLY",
    "GENERATE_REPORT": "GENERATE_REPORT",
    "RUN_CONTROL_PLANE_TESTS": "RUN_READ_ONLY_TESTS",
    "RUN_READ_ONLY_OBSERVATION": "OBSERVE_READ_ONLY",
    "PREPARE_NEXT_STAGE": "PREPARE_READ_ONLY",
    "NO_OP": "NO_OP",
}
PROHIBITED_ACTIONS = {
    "RESTART_PROJECT", "STOP_PROJECT", "KILL_PROCESS", "MODIFY_STRATEGY",
    "CHANGE_PARAMETERS", "WRITE_TO_ORACLE", "WRITE_TO_MICRO", "DELETE_DATA",
    "RESET_GIT", "CHECKOUT_PROJECT_BRANCH", "ENABLE_REAL_MONEY", "SEND_ORDER",
    "EXECUTE_TRADE", "MODIFY_CREDENTIALS", "MUTATE", "TARGET_MUTATION",
    "DESTRUCTIVE", "EXECUTE_RECOVERY",
}


class ProvenanceVerifier(Protocol):
    def __call__(self, payload: DirectivePayload, envelope: DirectiveEnvelope,
                 directive_file_path: Path | None = None) -> tuple[object, str, bool, dict[str, Any]]: ...


@dataclass(frozen=True)
class IngestResult:
    task_id: str
    directive_id: str
    created: bool
    state: str


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def deterministic_task_id(directive_id: str, idempotency_key: str) -> str:
    manifest = f"AF04_TASK_V1\n{directive_id}\n{idempotency_key}\n".encode()
    return "af04-" + _sha(manifest)


class DirectiveTaskIngestor:
    """Consumes queue bytes read-only; verifier authority must be injected explicitly."""

    def __init__(self, store: AutonomyStore, queue_path: Path | str, *,
                 verifier: ProvenanceVerifier | None,
                 supported_targets: Iterable[str], clock: Callable[[], float]):
        self.store = store
        self.queue_path = Path(queue_path)
        self.verifier = verifier
        self.supported_targets = frozenset(clean(item) for item in supported_targets)
        self.clock = clock
        self._init_schema()

    def _init_schema(self) -> None:
        self.store.db.executescript("""
CREATE TABLE IF NOT EXISTS autonomy_provenance(
 task_id TEXT PRIMARY KEY,directive_id TEXT NOT NULL UNIQUE,idempotency_key TEXT NOT NULL,
 source_commit_sha TEXT NOT NULL,blob_sha TEXT NOT NULL,payload_sha256 TEXT NOT NULL,
 source_path TEXT NOT NULL,signer_identity TEXT NOT NULL,target_project TEXT NOT NULL,action_type TEXT NOT NULL,
 capability TEXT NOT NULL,ingested_at REAL NOT NULL);
CREATE TABLE IF NOT EXISTS runtime_queue_records(
 sequence INTEGER PRIMARY KEY,line_sha256 TEXT NOT NULL,directive_id TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS runtime_ingest_state(
 singleton INTEGER PRIMARY KEY CHECK(singleton=1),source_path TEXT NOT NULL,
 source_state TEXT NOT NULL,last_sequence INTEGER NOT NULL,last_error TEXT,
 last_directive_id TEXT,last_task_id TEXT);
INSERT OR IGNORE INTO runtime_ingest_state VALUES(1,'','UNKNOWN',0,NULL,NULL,NULL);
""")

    @staticmethod
    def _identifier(value: object, label: str) -> str:
        if not isinstance(value, str) or not _IDENTIFIER.fullmatch(value):
            raise BlockedError(f"invalid {label}")
        return value

    def _block_source(self, reason: str) -> None:
        self.store.db.execute("UPDATE runtime_ingest_state SET source_state='INTEGRITY_BLOCKED',last_error=? WHERE singleton=1", (clean(reason),))

    def read_records(self) -> list[tuple[dict[str, Any], str]]:
        if not self.queue_path.exists() or not self.queue_path.is_file() or self.queue_path.is_symlink():
            self._block_source("QUEUE_UNAVAILABLE")
            raise IntegrityBlockedError("queue unavailable")
        raw = self.queue_path.read_bytes()
        if len(raw) > MAX_QUEUE_BYTES:
            self._block_source("QUEUE_OVERSIZED")
            raise IntegrityBlockedError("queue oversized")
        lines = raw.splitlines(keepends=True)
        if len(lines) > MAX_RECORDS:
            self._block_source("TOO_MANY_RECORDS")
            raise IntegrityBlockedError("too many queue records")
        records: list[tuple[dict[str, Any], str]] = []
        for index, line in enumerate(lines, 1):
            content = line.rstrip(b"\r\n")
            if not content.strip():
                continue
            if len(line) > MAX_RECORD_BYTES:
                self._block_source("RECORD_OVERSIZED")
                raise IntegrityBlockedError("queue record oversized")
            try:
                value = json.loads(content.decode("utf-8"))
            except (UnicodeError, json.JSONDecodeError) as exc:
                self._block_source("MALFORMED_QUEUE")
                raise IntegrityBlockedError("malformed queue") from exc
            if not isinstance(value, dict):
                self._block_source("INVALID_RECORD_SHAPE")
                raise IntegrityBlockedError("invalid queue record")
            records.append((value, _sha(line)))
        source = self.store.db.execute("SELECT source_path FROM runtime_ingest_state WHERE singleton=1").fetchone()
        resolved_source = str(self.queue_path.resolve(strict=True))
        if source and source[0] and source[0] != resolved_source:
            self._block_source("QUEUE_SOURCE_REBOUND")
            raise IntegrityBlockedError("queue source changed")
        persisted = list(self.store.db.execute("SELECT sequence,line_sha256,directive_id FROM runtime_queue_records ORDER BY sequence"))
        if len(records) < len(persisted):
            self._block_source("QUEUE_TRUNCATED")
            raise IntegrityBlockedError("queue truncated")
        for row, (record, line_sha) in zip(persisted, records):
            if row[1] != line_sha or row[2] != record.get("directive_id"):
                self._block_source("QUEUE_REWRITE_OR_REORDER")
                raise IntegrityBlockedError("queue history changed")
        return records

    @staticmethod
    def _source_path(value: object) -> str:
        if not isinstance(value, str) or "\\" in value or any(ord(ch) < 32 for ch in value):
            raise BlockedError("directive source path unavailable")
        path = PurePosixPath(value)
        parts = path.parts
        if (path.is_absolute() or len(parts) != 3 or parts[:2] != ("directives", "inbox")
                or not _IDENTIFIER.fullmatch(parts[2]) or not parts[2].endswith(".json")):
            raise BlockedError("invalid directive source path")
        return path.as_posix()

    def _validate(self, record: dict[str, Any]) -> tuple[DirectivePayload, DirectiveEnvelope, str, str, str]:
        directive_id = self._identifier(record.get("directive_id"), "directive_id")
        if record.get("queue_state") != "READY_FOR_FUTURE_EXECUTOR" or record.get("readback_verified") is not True or record.get("executed") is not False:
            raise BlockedError("queue record not execution-ready")
        commit = str(record.get("directive_source_sha", "")).lower()
        blob = str(record.get("directive_blob_sha", "")).lower()
        payload_sha = str(record.get("directive_payload_sha256", "")).lower()
        if not _HEX40.fullmatch(commit) or not _HEX40.fullmatch(blob) or not _HEX64.fullmatch(payload_sha):
            raise BlockedError("invalid provenance hashes")
        expected_key = _sha(f"{directive_id}:{commit}:{payload_sha}".encode())
        if record.get("idempotency_key") != expected_key:
            raise BlockedError("idempotency mismatch")
        source_path = self._source_path(record.get("directive_source_path"))
        target = self._identifier(record.get("target_project"), "target_project")
        if target not in self.supported_targets:
            raise BlockedError("unsupported target")
        action = self._identifier(record.get("action_type"), "action_type")
        if action in PROHIBITED_ACTIONS or action not in ACTION_CAPABILITIES:
            raise BlockedError("unknown or prohibited action")
        raw_payload = record.get("directive_payload")
        if not isinstance(raw_payload, dict):
            raise BlockedError("directive payload unavailable")
        payload = DirectivePayload.from_dict(raw_payload)
        if payload.directive_id != directive_id or payload.target_project != target or payload.action_type != action:
            raise BlockedError("payload record contradiction")
        if payload.requires_human_approval is not record.get("requires_human_approval"):
            raise BlockedError("human approval contradiction")
        envelope = DirectiveEnvelope(
            directive_id=directive_id, payload_commit_sha=commit, payload_blob_sha=blob,
            payload_sha256=payload_sha, trusted_remote="AI-CONTROL-PLANE", trusted_branch="main")
        return payload, envelope, expected_key, ACTION_CAPABILITIES[action], source_path

    def _verify(self, payload: DirectivePayload, envelope: DirectiveEnvelope,
                record: dict[str, Any], source_path: str) -> str:
        if self.verifier is None:
            raise BlockedError("provenance verifier unavailable")
        try:
            result = self.verifier(payload, envelope, Path(source_path))
            if not isinstance(result, tuple) or len(result) != 4 or not isinstance(result[3], dict):
                raise BlockedError("malformed provenance response")
            status, _, human_wait, metadata = result
        except BlockedError:
            raise
        except Exception as exc:
            raise BlockedError("provenance verifier unavailable") from exc
        status_value = status.value if isinstance(status, ValidationStatus) else str(status)
        signer = clean(metadata.get("signer_identity", ""))
        if (status_value != ValidationStatus.AUTHENTIC.value or not metadata.get("signature_valid")
                or not metadata.get("signer_allowed") or not metadata.get("remote_ancestry_verified")
                or metadata.get("payload_commit_sha") != envelope.payload_commit_sha
                or metadata.get("payload_blob_sha") != envelope.payload_blob_sha
                or metadata.get("payload_sha256") != envelope.payload_sha256
                or signer != clean(record.get("signer_identity", ""))
                or bool(human_wait) != payload.requires_human_approval):
            raise BlockedError("provenance revalidation failed")
        return signer

    def ingest(self) -> list[IngestResult]:
        records = self.read_records()
        resolved_source = str(self.queue_path.resolve(strict=True))
        results: list[IngestResult] = []
        persisted_count = self.store.db.execute("SELECT count(*) FROM runtime_queue_records").fetchone()[0]
        for sequence, (record, line_sha) in enumerate(records, 1):
            if sequence <= persisted_count:
                continue
            payload, envelope, key, capability, source_path = self._validate(record)
            signer = self._verify(payload, envelope, record, source_path)
            task_id = deterministic_task_id(payload.directive_id, key)
            n = self.store.now(self.clock())
            binding = (task_id, payload.directive_id, key, envelope.payload_commit_sha,
                       envelope.payload_blob_sha, envelope.payload_sha256, source_path, signer,
                       payload.target_project, payload.action_type, capability)
            try:
                self.store.db.execute("BEGIN IMMEDIATE")
                sequence_row = self.store.db.execute("SELECT line_sha256,directive_id FROM runtime_queue_records WHERE sequence=?", (sequence,)).fetchone()
                if sequence_row and (sequence_row[0] != line_sha or sequence_row[1] != payload.directive_id):
                    self._block_source("QUEUE_SEQUENCE_CONFLICT")
                    self.store.db.execute("COMMIT")
                    raise IntegrityBlockedError("queue sequence conflict")
                existing = self.store.db.execute("SELECT * FROM autonomy_provenance WHERE directive_id=? OR task_id=?", (payload.directive_id, task_id)).fetchone()
                if existing:
                    actual = tuple(existing[name] for name in ("task_id","directive_id","idempotency_key","source_commit_sha","blob_sha","payload_sha256","source_path","signer_identity","target_project","action_type","capability"))
                    if actual != binding:
                        self._block_source("PROVENANCE_CONFLICT")
                        self.store.db.execute("COMMIT")
                        raise IntegrityBlockedError("conflicting provenance")
                    created = False
                else:
                    state = "WAITING_HUMAN" if payload.requires_human_approval else "QUEUED"
                    self.store.db.execute("INSERT INTO tasks(task_id,directive_id,target_project,capability,state,priority,created_at,updated_at,requires_human_approval,governance_allowed,retry_budget) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                                          (task_id,payload.directive_id,payload.target_project,capability,state,0,n,n,int(payload.requires_human_approval),1,1))
                    self.store.db.execute("INSERT INTO autonomy_provenance VALUES(?,?,?,?,?,?,?,?,?,?,?,?)", (*binding,n))
                    self.store.audit(task_id,"DIRECTIVE_INGESTED",n,f"directive={payload.directive_id};action={payload.action_type}")
                    created = True
                if sequence_row is None:
                    self.store.db.execute("INSERT INTO runtime_queue_records VALUES(?,?,?)", (sequence,line_sha,payload.directive_id))
                self.store.db.execute("UPDATE runtime_ingest_state SET source_path=?,source_state='VERIFIED',last_sequence=?,last_error=NULL,last_directive_id=?,last_task_id=? WHERE singleton=1",
                                      (resolved_source,sequence,payload.directive_id,task_id))
                self.store.db.execute("COMMIT")
                if created:
                    results.append(IngestResult(task_id,payload.directive_id,True,self.store.task(task_id)["state"]))
            except (BlockedError, IntegrityBlockedError):
                if self.store.db.in_transaction:
                    self.store.db.execute("ROLLBACK")
                raise
            except sqlite3.OperationalError as exc:
                if self.store.db.in_transaction:
                    self.store.db.execute("ROLLBACK")
                if "locked" in str(exc).lower() or "busy" in str(exc).lower():
                    raise BlockedError("store busy") from exc
                raise
        return results

    def projection(self) -> dict[str, Any]:
        row = self.store.db.execute("SELECT source_state,last_sequence,last_error,last_directive_id,last_task_id FROM runtime_ingest_state WHERE singleton=1").fetchone()
        return dict(row) if row else {"source_state": "UNKNOWN", "last_error": "INTEGRITY_BLOCKED"}
