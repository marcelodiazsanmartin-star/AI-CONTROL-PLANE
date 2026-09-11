"""Production-only composition root; no provisioning or test-mode switch."""

from __future__ import annotations

import json
import os
from pathlib import Path

from .authority import AuthorityUnavailableError, TrustAnchorError
from .google_cloud import GoogleCloudKMSSigner, GoogleCloudMonotonicWitness, GoogleRestTransport
from .service import GoogleOIDCAuthenticator, LocalState, TrustAnchorService
from .witness import DeploymentIdentity


RELEASE_IDENTITY = Path(__file__).with_name("deployment_identity.json")
LOCAL_CACHE = Path("/var/lib/trust-anchor/head.json")


def load_release_identity() -> DeploymentIdentity:
    """Governance installs this public manifest in the immutable service image."""
    try:
        identity = DeploymentIdentity(**json.loads(RELEASE_IDENTITY.read_bytes()))
        identity.validate()
        return identity
    except Exception as exc:
        raise TrustAnchorError("PINNED_DEPLOYMENT_IDENTITY_REQUIRED") from exc


def attest_workload(identity: DeploymentIdentity, request) -> None:
    """A copied disk cannot mint this Google-signed attached-service identity."""
    try:
        from google.auth import compute_engine
        from google.oauth2.id_token import verify_oauth2_token
        if (os.environ.get("GOOGLE_APPLICATION_CREDENTIALS")
                or os.environ.get("STORAGE_EMULATOR_HOST")
                or os.environ.get("GCE_METADATA_HOST")
                or os.environ.get("GCE_METADATA_IP")
                or os.environ.get("GCE_METADATA_ROOT")
                or os.environ.get("K_REVISION") != identity.service_revision):
            raise TrustAnchorError("WORKLOAD_IDENTITY_MISMATCH")
        credential = compute_engine.IDTokenCredentials(request, target_audience=identity.audience,
                                                       use_metadata_identity_endpoint=True)
        credential.refresh(request)
        claims = verify_oauth2_token(credential.token, request, audience=identity.audience)
        if (claims.get("sub") != identity.service_subject
                or claims.get("email") != identity.service_email
                or claims.get("email_verified") is not True
                or claims.get("aud") != identity.audience
                or claims.get("iss") not in ("accounts.google.com", "https://accounts.google.com")):
            raise TrustAnchorError("WORKLOAD_IDENTITY_MISMATCH")
    except TrustAnchorError:
        raise
    except Exception as exc:
        raise AuthorityUnavailableError("ATTACHED_WORKLOAD_IDENTITY_REQUIRED") from exc


def build_production_service(configuration: dict | None = None) -> TrustAnchorService:
    identity = load_release_identity()
    if configuration is not None:
        identity.check_configuration(configuration)
    try:
        from google.auth import compute_engine
        from google.auth.transport.requests import AuthorizedSession, Request
        request = Request()
        attest_workload(identity, request)
        credentials = compute_engine.Credentials(service_account_email=identity.service_email,
            scopes=["https://www.googleapis.com/auth/cloud-platform"])
        transport = GoogleRestTransport(AuthorizedSession(credentials))
        signer = GoogleCloudKMSSigner(identity, transport)
        signer.attest()
        witness = GoogleCloudMonotonicWitness(identity, transport)
        return TrustAnchorService(identity, witness, signer, GoogleOIDCAuthenticator(identity, request), LocalState(LOCAL_CACHE))
    except TrustAnchorError:
        raise
    except Exception as exc:
        raise AuthorityUnavailableError("PRODUCTION_DEPENDENCY_UNAVAILABLE") from exc
