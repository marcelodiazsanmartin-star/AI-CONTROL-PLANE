"""Public-only ORACLE transport. No import of the service or cloud adapters."""

import base64
import json
from dataclasses import replace
from .authority import CheckpointProposal, TrustAnchorError, AuthorityUnavailableError
from .witness import DeploymentIdentity, WitnessRecord


class ProposalClient:
    """ORACLE-side interface: HTTPS RPC only, no signer, witness, or ADMIN methods."""

    def __init__(self, identity: DeploymentIdentity, session, token_provider):
        identity.validate()
        audience = identity.audience
        if not audience.startswith("https://") or audience.endswith("/"):
            raise TrustAnchorError("SERVICE_ENDPOINT_INVALID")
        self._audience = audience
        self._identity = identity
        self._session = session
        self._token_provider = token_provider

    def _call(self, operation: str, request: dict) -> dict:
        try:
            result = self._session.post(self._audience + "/oracle/" + operation, json=request,
                headers={"Authorization": "Bearer " + self._token_provider(self._audience)},
                timeout=20, allow_redirects=False)
            if result.status_code != 200:
                raise AuthorityUnavailableError("TRUST_ANCHOR_SERVICE_REJECTED")
            value = result.json()
            if value == {"status": "NO_ACCEPTED_HEAD", "run_id": request["run_id"]} and operation == "get_head":
                return value
            record = WitnessRecord(**value)
            record.verify(self._identity)
            expected_type = "AUTHORIZATION_EPOCH" if operation == "get_authorization" else "CHECKPOINT_HEAD"
            if record.run_id != request["run_id"] or record.record_type != expected_type:
                raise TrustAnchorError("SERVICE_RESPONSE_BINDING_MISMATCH")
            if operation == "propose_checkpoint":
                payload = json.loads(record.payload_json)
                for key in ("checkpoint_sequence", "checkpoint_hash", "manifest_hash", "previous_accepted_hash", "authorization_record_hash"):
                    if payload[key] != request[key]:
                        raise TrustAnchorError("SERVICE_RESPONSE_BINDING_MISMATCH")
                if record.anchor_namespace_id != request["anchor_namespace_id"] or record.code_under_test_sha != request["code_under_test_sha"]:
                    raise TrustAnchorError("SERVICE_RESPONSE_BINDING_MISMATCH")
            return value
        except TrustAnchorError:
            raise
        except Exception as exc:
            raise AuthorityUnavailableError("TRUST_ANCHOR_SERVICE_UNAVAILABLE") from exc

    def get_authorization(self, run_id: str) -> dict:
        return self._call("get_authorization", {"run_id": run_id})

    def get_head(self, run_id: str) -> dict:
        return self._call("get_head", {"run_id": run_id})

    def propose_checkpoint(self, authorization_record_hash: str, proposal: CheckpointProposal) -> dict:
        # Take a second frozen snapshot at the transport boundary.
        frozen = replace(proposal)
        request = {key: getattr(frozen, key) for key in ("run_id", "anchor_namespace_id", "checkpoint_sequence",
            "checkpoint_hash", "manifest_hash", "previous_accepted_hash", "code_under_test_sha")}
        request.update(authorization_record_hash=authorization_record_hash,
            checkpoint_b64=base64.b64encode(frozen.checkpoint_bytes).decode("ascii"),
            manifest_b64=base64.b64encode(frozen.manifest_bytes).decode("ascii"))
        return self._call("propose_checkpoint", request)
