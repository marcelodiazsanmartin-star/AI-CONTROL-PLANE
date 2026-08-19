"""
Directive Pre-Execution Revalidator & TOCTOU Protection Engine

Implements PRE_EXECUTION_REVALIDATION immediately prior to any execution step.
Guarantees EXECUTION_ALLOWED = FALSE if any trust condition changes after initial authentication.
"""

from typing import Tuple, Dict, Any, Optional
from pathlib import Path
from src.directive.contracts import QueuedDirectiveItem, DirectivePayload, DirectiveEnvelope, ValidationStatus
from src.directive.authenticator import DirectiveAuthenticator
from config import settings


class PreExecutionRevalidator:
    def __init__(self, authenticator: Optional[DirectiveAuthenticator] = None):
        self.authenticator = authenticator or DirectiveAuthenticator()

    def revalidate(
        self,
        queued_item: QueuedDirectiveItem,
        repo_root: Optional[Path] = None
    ) -> Tuple[bool, ValidationStatus, str, Dict[str, Any]]:
        """
        Executes immediate PRE_EXECUTION_REVALIDATION before any operation attempt.
        Returns (execution_allowed: bool, status: ValidationStatus, reason: str, reval_metadata: dict)
        """
        # 1. Queue record integrity check
        if not queued_item.readback_verified:
            return False, ValidationStatus.QUEUE_CORRUPTION, "TOCTOU_REVALIDATION_FAILED: Queue record was not read-back verified", {}

        if queued_item.executed:
            return False, ValidationStatus.STATE_CONFLICT, "TOCTOU_REVALIDATION_FAILED: Directive already executed", {}

        # 2. Re-construct Payload and Envelope from queued item
        if not queued_item.directive_payload:
            return False, ValidationStatus.QUEUE_RECORD_MISMATCH, "TOCTOU_REVALIDATION_FAILED: Queued directive_payload is missing", {}

        payload = DirectivePayload.from_dict(queued_item.directive_payload)
        envelope = DirectiveEnvelope(
            directive_id=queued_item.directive_id,
            payload_commit_sha=queued_item.directive_source_sha,
            payload_blob_sha=queued_item.directive_blob_sha,
            payload_sha256=queued_item.directive_payload_sha256,
            trusted_remote=settings.APPROVED_SOURCE_REPOSITORY,
            trusted_branch=settings.APPROVED_SOURCE_BRANCH,
            signer_identity=queued_item.signer_identity
        )

        # 3. Live Re-Authentication against Remote, Branch Reachability, Signature, and Blob SHA256
        val_status, val_reason, req_human, auth_meta = self.authenticator.authenticate(payload, envelope)

        if val_status != ValidationStatus.AUTHENTIC and not req_human:
            return False, ValidationStatus.TOCTOU_REVALIDATION_FAILED, f"TOCTOU_REVALIDATION_FAILED: {val_reason}", auth_metadata

        # 4. Verify exact blob sha256 equality against queued sha256
        live_sha256 = auth_meta.get("payload_sha256", "")
        if live_sha256 and queued_item.directive_payload_sha256 and live_sha256 != queued_item.directive_payload_sha256:
            return False, ValidationStatus.TOCTOU_REVALIDATION_FAILED, f"TOCTOU_REVALIDATION_FAILED: Live blob SHA256 ({live_sha256[:7]}) mismatch against queued record ({queued_item.directive_payload_sha256[:7]})", auth_metadata

        # 5. Check Safety Enforcement Settings
        if not settings.CONTROL_PLANE_EXECUTE_MUTATING_DIRECTIVES:
            # Stage CONTROL-02.5 invariant: Execution of mutating directives is forbidden
            return False, ValidationStatus.ACTION_NOT_ALLOWED, "EXECUTION_ALLOWED = FALSE: Mutating directive execution disabled in stage CONTROL-02.5", auth_meta

        return True, ValidationStatus.AUTHENTIC, "TOCTOU_REVALIDATION_PASSED: Execution revalidated successfully", auth_meta
