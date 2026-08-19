"""
Directive Watcher Module

Integrated single-instance watcher scanning directives/inbox/ and executing real Git validation,
cryptographic signature verification, TOCTOU revalidation, durable queueing with read-back verification,
human approval gating, acknowledgement generation, and status reconstruction from durable truth.

Guarantees MUTATING_DIRECTIVES_EXECUTED = 0.
"""

import json
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Any, Set
from config import settings
from src.directive.contracts import (
    DirectivePayload, DirectiveEnvelope, DirectiveAck, DirectiveState,
    ValidationStatus, DirectiveChannelStatus
)
from src.directive.schema_validator import DirectiveSchemaValidator
from src.directive.replay_ledger import ReplayLedger
from src.directive.durable_queue import DurableExecutionQueue, QueuePersistenceError
from src.directive.authenticator import DirectiveAuthenticator
from src.directive.executor import PreExecutionRevalidator


def get_git_commit_sha(repo_dir: Path) -> str:
    try:
        res = subprocess.run(
            ["git", "-C", str(repo_dir), "rev-parse", "HEAD"],
            capture_output=True,
            text=True,
            timeout=5.0
        )
        if res.returncode == 0:
            return res.stdout.strip()
    except Exception:
        pass
    return "UNKNOWN_SHA"


class DirectiveWatcher:
    def __init__(
        self,
        directives_root: Optional[Path] = None,
        schema_validator: Optional[DirectiveSchemaValidator] = None,
        replay_ledger: Optional[ReplayLedger] = None,
        durable_queue: Optional[DurableExecutionQueue] = None,
        authenticator: Optional[DirectiveAuthenticator] = None
    ):
        self.root = directives_root or (settings.CONTROL_PLANE_ROOT / "directives")
        self.inbox_dir = self.root / "inbox"
        self.accepted_dir = self.root / "accepted"
        self.rejected_dir = self.root / "rejected"
        self.waiting_human_dir = self.root / "waiting_human"
        self.completed_dir = self.root / "completed"
        self.ack_dir = self.root / "ack"
        self.runtime_dir = self.root / "runtime"

        for d in [self.inbox_dir, self.accepted_dir, self.rejected_dir, self.waiting_human_dir, self.completed_dir, self.ack_dir, self.runtime_dir]:
            d.mkdir(parents=True, exist_ok=True)

        self.schema_validator = schema_validator or DirectiveSchemaValidator()
        self.replay_ledger = replay_ledger or ReplayLedger(self.runtime_dir / "consumed_directives.jsonl")
        self.durable_queue = durable_queue or DurableExecutionQueue(self.runtime_dir / "execution_queue.jsonl")
        self.authenticator = authenticator or DirectiveAuthenticator(repo_root=self.root.parent)
        self.revalidator = PreExecutionRevalidator(self.authenticator)

        self.status = DirectiveChannelStatus()
        self.reconstruct_channel_status()

    def reconstruct_channel_status(self):
        """
        Reconstructs state/directive_channel_status.json counters from durable truth.
        """
        accepted_files = list(self.accepted_dir.glob("*.json"))
        rejected_files = list(self.rejected_dir.glob("*.json"))
        waiting_files = list(self.waiting_human_dir.glob("*.json"))

        self.status.accepted_count = len(accepted_files)
        self.status.rejected_count = len(rejected_files)
        self.status.waiting_human_count = len(waiting_files)
        self.status.queued_count = len(self.durable_queue.get_items())

        replay_count = 0
        auth_count = 0
        schema_count = 0
        state_conflicts = 0

        ledger_file = self.runtime_dir / "consumed_directives.jsonl"
        if ledger_file.exists():
            try:
                with open(ledger_file, "r", encoding="utf-8") as f:
                    for line in f:
                        line_str = line.strip()
                        if line_str:
                            try:
                                data = json.loads(line_str)
                                reason = data.get("decision_reason", "")
                                if "REPLAY_DETECTED" in reason:
                                    replay_count += 1
                                if "INVALID_SOURCE" in reason or "NOT_IN_APPROVED_BRANCH" in reason or "COMMIT_NOT_FOUND" in reason or "SIGNATURE" in reason or "REACHABLE" in reason:
                                    auth_count += 1
                                if "SCHEMA_INVALID" in reason:
                                    schema_count += 1
                                if "STATE_CONFLICT" in reason:
                                    state_conflicts += 1
                            except Exception:
                                pass
            except Exception:
                pass

        self.status.replay_rejections = replay_count
        self.status.auth_rejections = auth_count
        self.status.schema_rejections = schema_count
        self.status.state_conflicts = state_conflicts

        all_ack_files = sorted(list(self.ack_dir.glob("*.json")), key=lambda p: p.stat().st_mtime if p.exists() else 0)
        if all_ack_files:
            last_ack = all_ack_files[-1]
            try:
                ack_data = json.loads(last_ack.read_text(encoding="utf-8"))
                self.status.last_directive_id = ack_data.get("directive_id")
                self.status.last_directive_seen = f"{self.status.last_directive_id}.json"
            except Exception:
                pass

        self.update_channel_status()

    def update_channel_status(self):
        self.status.last_poll = datetime.now(timezone.utc).isoformat()
        status_file = settings.CONTROL_PLANE_ROOT / "state" / "directive_channel_status.json"
        status_file.parent.mkdir(parents=True, exist_ok=True)
        with open(status_file, "w", encoding="utf-8") as f:
            json.dump(self.status.to_dict(), f, indent=2)

    def write_ack(
        self,
        directive_id: str,
        source_commit_sha: str,
        val_status: str,
        decision: str,
        decision_reason: str,
        human_req: bool,
        queued: bool,
        executed: bool = False,
        readback_verified: bool = True
    ) -> DirectiveAck:
        cp_commit = get_git_commit_sha(settings.CONTROL_PLANE_ROOT)
        ack = DirectiveAck(
            directive_id=directive_id,
            received_at=datetime.now(timezone.utc).isoformat(),
            source_commit_sha=source_commit_sha,
            validation_status=val_status,
            decision=decision,
            decision_reason=decision_reason,
            human_required=human_req,
            queued=queued,
            executed=executed,
            control_plane_commit_sha=cp_commit,
            readback_verified=readback_verified
        )
        ack_file = self.ack_dir / f"{directive_id}.json"
        try:
            with open(ack_file, "w", encoding="utf-8") as f:
                json.dump(ack.to_dict(), f, indent=2)
        except Exception:
            pass
        return ack

    def poll_inbox(self) -> List[DirectiveAck]:
        acks = []
        now_iso = datetime.now(timezone.utc).isoformat()
        self.status.last_poll = now_iso

        if not self.inbox_dir.exists():
            self.update_channel_status()
            return acks

        inbox_files = sorted(list(self.inbox_dir.glob("*.json")))

        for file_path in inbox_files:
            self.status.last_directive_seen = file_path.name
            raw_text = ""
            try:
                raw_text = file_path.read_text(encoding="utf-8")
                raw_json = json.loads(raw_text)
            except Exception as e:
                d_id = file_path.stem
                self.status.schema_rejections += 1
                self.status.rejected_count += 1
                self.status.last_error = f"Malformed JSON: {str(e)}"
                ack = self.write_ack(
                    directive_id=d_id,
                    source_commit_sha="UNKNOWN_SHA",
                    val_status=ValidationStatus.SCHEMA_INVALID.value,
                    decision="REJECTED",
                    decision_reason=f"SCHEMA_INVALID: Malformed JSON syntax: {str(e)}",
                    human_req=False,
                    queued=False,
                    executed=False
                )
                acks.append(ack)
                shutil.move(str(file_path), str(self.rejected_dir / file_path.name))
                continue

            # Step 1: Schema Validation
            valid_schema, schema_msg = self.schema_validator.validate(raw_json)
            if not valid_schema:
                d_id = raw_json.get("directive_id", file_path.stem) if isinstance(raw_json, dict) else file_path.stem
                self.status.schema_rejections += 1
                self.status.rejected_count += 1
                self.status.last_error = schema_msg
                ack = self.write_ack(
                    directive_id=d_id,
                    source_commit_sha=raw_json.get("source_commit_sha", raw_json.get("payload_commit_sha", "UNKNOWN_SHA")) if isinstance(raw_json, dict) else "UNKNOWN_SHA",
                    val_status=ValidationStatus.SCHEMA_INVALID.value,
                    decision="REJECTED",
                    decision_reason=schema_msg,
                    human_req=False,
                    queued=False,
                    executed=False
                )
                acks.append(ack)
                shutil.move(str(file_path), str(self.rejected_dir / file_path.name))
                continue

            # Parse DirectivePayload and DirectiveEnvelope
            payload_data = raw_json.get("payload_object", raw_json)
            envelope_data = raw_json.get("envelope", raw_json)

            payload = DirectivePayload.from_dict(payload_data)
            envelope = DirectiveEnvelope.from_dict(envelope_data)
            d_id = payload.directive_id
            self.status.last_directive_id = d_id

            # Step 2: State Conflict & Idempotency / Replay Check
            if self.replay_ledger.is_consumed(d_id):
                existing_rec = self.replay_ledger.get_consumed_record(d_id)
                self.status.replay_rejections += 1
                self.status.rejected_count += 1
                self.status.last_error = f"Replay detected for directive_id {d_id}"

                val_stat = ValidationStatus.REPLAY_DETECTED
                reason_msg = f"REPLAY_DETECTED: Directive {d_id} has already been processed"

                if existing_rec and existing_rec.source_commit_sha != envelope.payload_commit_sha:
                    val_stat = ValidationStatus.STATE_CONFLICT
                    self.status.state_conflicts += 1
                    reason_msg = f"STATE_CONFLICT: directive_id {d_id} resubmitted with different payload commit {envelope.payload_commit_sha[:7]}"

                ack = self.write_ack(
                    directive_id=d_id,
                    source_commit_sha=envelope.payload_commit_sha,
                    val_status=val_stat.value,
                    decision="REJECTED",
                    decision_reason=reason_msg,
                    human_req=False,
                    queued=False,
                    executed=False
                )
                acks.append(ack)
                shutil.move(str(file_path), str(self.rejected_dir / file_path.name))
                continue

            # Step 3: Source Authenticity, Cryptographic Signatures & Remote Reachability
            val_status, val_reason, requires_human_wait, auth_meta = self.authenticator.authenticate(payload, envelope, file_path)

            if val_status != ValidationStatus.AUTHENTIC:
                if val_status in (ValidationStatus.INVALID_SOURCE, ValidationStatus.NOT_IN_APPROVED_BRANCH, ValidationStatus.COMMIT_NOT_FOUND, ValidationStatus.COMMIT_EXISTS_BUT_DIRECTIVE_ABSENT, ValidationStatus.COMMIT_SIGNATURE_MISSING, ValidationStatus.COMMIT_SIGNATURE_INVALID, ValidationStatus.UNTRUSTED_COMMIT_SIGNER, ValidationStatus.PAYLOAD_COMMIT_NOT_REACHABLE):
                    self.status.auth_rejections += 1
                else:
                    self.status.schema_rejections += 1

                self.status.rejected_count += 1
                self.status.last_error = val_reason

                self.replay_ledger.record_consumption(
                    directive_id=d_id,
                    source_commit_sha=envelope.payload_commit_sha,
                    first_seen_at=now_iso,
                    decision="REJECTED",
                    decision_reason=val_reason
                )

                ack = self.write_ack(
                    directive_id=d_id,
                    source_commit_sha=envelope.payload_commit_sha,
                    val_status=val_status.value,
                    decision="REJECTED",
                    decision_reason=val_reason,
                    human_req=False,
                    queued=False,
                    executed=False
                )
                acks.append(ack)
                shutil.move(str(file_path), str(self.rejected_dir / file_path.name))
                continue

            # Step 4: Human Approval Gate
            if requires_human_wait:
                self.status.waiting_human_count = len(list(self.waiting_human_dir.glob("*.json"))) + 1
                ack = self.write_ack(
                    directive_id=d_id,
                    source_commit_sha=envelope.payload_commit_sha,
                    val_status=val_status.value,
                    decision="WAITING_HUMAN",
                    decision_reason=val_reason,
                    human_req=True,
                    queued=False,
                    executed=False
                )
                acks.append(ack)

                dest_waiting = self.waiting_human_dir / file_path.name
                shutil.move(str(file_path), str(dest_waiting))
                continue

            # Step 5: Durable Execution Queueing with Mandatory Read-Back Verification
            try:
                queued_item = self.durable_queue.enqueue_payload(
                    payload=payload,
                    envelope=envelope,
                    auth_metadata=auth_meta,
                    accepted_at=now_iso
                )
            except QueuePersistenceError as qe:
                self.status.rejected_count += 1
                self.status.last_error = str(qe)
                ack = self.write_ack(
                    directive_id=d_id,
                    source_commit_sha=envelope.payload_commit_sha,
                    val_status=ValidationStatus.QUEUE_PERSISTENCE_FAILURE.value,
                    decision="REJECTED",
                    decision_reason=str(qe),
                    human_req=False,
                    queued=False,
                    executed=False,
                    readback_verified=False
                )
                acks.append(ack)
                shutil.move(str(file_path), str(self.rejected_dir / file_path.name))
                continue

            # Step 6: Append-Only Ledger Record Verification & ACK
            self.status.accepted_count = len(list(self.accepted_dir.glob("*.json"))) + 1
            self.status.queued_count = len(self.durable_queue.get_items())

            self.replay_ledger.record_consumption(
                directive_id=d_id,
                source_commit_sha=envelope.payload_commit_sha,
                first_seen_at=now_iso,
                decision="ACCEPTED",
                decision_reason=val_reason
            )

            ack = self.write_ack(
                directive_id=d_id,
                source_commit_sha=envelope.payload_commit_sha,
                val_status=val_status.value,
                decision="ACCEPTED",
                decision_reason=val_reason,
                human_req=False,
                queued=True,
                executed=False,  # MUTATING_DIRECTIVES_EXECUTED = 0
                readback_verified=queued_item.readback_verified
            )
            acks.append(ack)

            dest_file = self.accepted_dir / file_path.name
            shutil.move(str(file_path), str(dest_file))

        self.update_channel_status()
        return acks
