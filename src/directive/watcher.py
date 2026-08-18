"""
Directive Watcher Module

Integrated single-instance watcher scanning directives/inbox/ and executing validation,
replay protection, human approval gating, acknowledgement generation, and safe queuing.
Guarantees MUTATING_DIRECTIVES_EXECUTED = 0.
"""

import json
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Any
from config import settings
from src.directive.contracts import (
    Directive, DirectiveAck, DirectiveState, ValidationStatus, DirectiveChannelStatus
)
from src.directive.schema_validator import DirectiveSchemaValidator
from src.directive.replay_ledger import ReplayLedger
from src.directive.authenticator import DirectiveAuthenticator


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
        authenticator: Optional[DirectiveAuthenticator] = None
    ):
        self.root = directives_root or (settings.CONTROL_PLANE_ROOT / "directives")
        self.inbox_dir = self.root / "inbox"
        self.accepted_dir = self.root / "accepted"
        self.rejected_dir = self.root / "rejected"
        self.completed_dir = self.root / "completed"
        self.ack_dir = self.root / "ack"
        self.runtime_dir = self.root / "runtime"

        for d in [self.inbox_dir, self.accepted_dir, self.rejected_dir, self.completed_dir, self.ack_dir, self.runtime_dir]:
            d.mkdir(parents=True, exist_ok=True)

        self.schema_validator = schema_validator or DirectiveSchemaValidator()
        self.replay_ledger = replay_ledger or ReplayLedger(self.runtime_dir / "consumed_directives.jsonl")
        self.authenticator = authenticator or DirectiveAuthenticator()

        self.status = DirectiveChannelStatus()
        self.queued_directives: List[Dict[str, Any]] = []

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
        executed: bool = False
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
            control_plane_commit_sha=cp_commit
        )
        ack_file = self.ack_dir / f"{directive_id}.json"
        with open(ack_file, "w", encoding="utf-8") as f:
            json.dump(ack.to_dict(), f, indent=2)
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
                # Malformed JSON -> REJECT
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
                    source_commit_sha=raw_json.get("source_commit_sha", "UNKNOWN_SHA") if isinstance(raw_json, dict) else "UNKNOWN_SHA",
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

            directive = Directive.from_dict(raw_json)
            d_id = directive.directive_id
            self.status.last_directive_id = d_id

            # Step 2: Replay Protection
            if self.replay_ledger.is_consumed(d_id):
                self.status.replay_rejections += 1
                self.status.rejected_count += 1
                self.status.last_error = f"Replay detected for directive_id {d_id}"
                ack = self.write_ack(
                    directive_id=d_id,
                    source_commit_sha=directive.source_commit_sha,
                    val_status=ValidationStatus.REPLAY_DETECTED.value,
                    decision="REJECTED",
                    decision_reason=f"REPLAY_DETECTED: Directive {d_id} has already been processed",
                    human_req=False,
                    queued=False,
                    executed=False
                )
                acks.append(ack)
                shutil.move(str(file_path), str(self.rejected_dir / file_path.name))
                continue

            # Step 3: Source Authenticity, Expiration & Permission Validation
            val_status, val_reason, requires_human_wait = self.authenticator.authenticate(directive, file_path)

            if val_status != ValidationStatus.AUTHENTIC:
                if val_status == ValidationStatus.INVALID_SOURCE or val_status == ValidationStatus.NOT_IN_APPROVED_BRANCH or val_status == ValidationStatus.COMMIT_NOT_FOUND:
                    self.status.auth_rejections += 1
                else:
                    self.status.schema_rejections += 1

                self.status.rejected_count += 1
                self.status.last_error = val_reason

                self.replay_ledger.record_consumption(
                    directive_id=d_id,
                    source_commit_sha=directive.source_commit_sha,
                    first_seen_at=now_iso,
                    decision="REJECTED",
                    decision_reason=val_reason
                )

                ack = self.write_ack(
                    directive_id=d_id,
                    source_commit_sha=directive.source_commit_sha,
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
                self.status.waiting_human_count += 1
                self.replay_ledger.record_consumption(
                    directive_id=d_id,
                    source_commit_sha=directive.source_commit_sha,
                    first_seen_at=now_iso,
                    decision="WAITING_HUMAN",
                    decision_reason=val_reason
                )
                ack = self.write_ack(
                    directive_id=d_id,
                    source_commit_sha=directive.source_commit_sha,
                    val_status=val_status.value,
                    decision="WAITING_HUMAN",
                    decision_reason=val_reason,
                    human_req=True,
                    queued=False,
                    executed=False
                )
                acks.append(ack)
                # Leaves directive file in inbox for human review
                continue

            # Step 5: Accepted -> Queued for execution (READY_FOR_FUTURE_EXECUTOR)
            self.status.accepted_count += 1
            self.status.queued_count += 1

            self.replay_ledger.record_consumption(
                directive_id=d_id,
                source_commit_sha=directive.source_commit_sha,
                first_seen_at=now_iso,
                decision="ACCEPTED",
                decision_reason=val_reason
            )

            queue_entry = {
                "directive": directive.to_dict(),
                "status": "READY_FOR_FUTURE_EXECUTOR",
                "accepted_at": now_iso
            }
            self.queued_directives.append(queue_entry)

            ack = self.write_ack(
                directive_id=d_id,
                source_commit_sha=directive.source_commit_sha,
                val_status=val_status.value,
                decision="ACCEPTED",
                decision_reason=val_reason,
                human_req=False,
                queued=True,
                executed=False  # MUTATING_DIRECTIVES_EXECUTED = 0
            )
            acks.append(ack)

            # Move directive file to accepted/
            dest_file = self.accepted_dir / file_path.name
            shutil.move(str(file_path), str(dest_file))

        self.update_channel_status()
        return acks
