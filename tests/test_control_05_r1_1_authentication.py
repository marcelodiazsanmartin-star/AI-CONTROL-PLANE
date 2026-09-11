"""Real Google JWT verification with local RSA signatures and offline certs."""

import json
import time
from dataclasses import asdict
from types import SimpleNamespace

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from google.auth import crypt, jwt

from src.trust_anchor.authority import TrustAnchorError
from src.trust_anchor.client import ProposalClient
from src.trust_anchor import runtime
from src.trust_anchor.service import GoogleOIDCAuthenticator
from tests.control05_support import create_run, rig


@pytest.fixture
def tokens():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    public = key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    signer = crypt.RSASigner.from_string(private, key_id="offline-google-fixture")
    def request(url, method="GET", **kwargs):
        assert url == "https://www.googleapis.com/oauth2/v1/certs"
        return SimpleNamespace(status=200, data=json.dumps({"offline-google-fixture": public}).encode())
    def mint(identity, **changes):
        now = int(time.time())
        claims = {"iss": "https://accounts.google.com", "aud": identity.audience,
                  "iat": now - 30, "exp": now + 300, "sub": identity.oracle_subject,
                  "email": "oracle@test-project.iam.gserviceaccount.com", "email_verified": True}
        claims.update(changes)
        return jwt.encode(signer, claims).decode()
    return request, mint


def test_real_token_roles(tmp_path, tokens):
    r = rig(tmp_path)
    request, mint = tokens
    auth = GoogleOIDCAuthenticator(r.identity, request)
    assert auth.authenticate(mint(r.identity)) == "ORACLE"
    assert auth.authenticate(mint(r.identity, sub=r.identity.admin_subject)) == "ADMIN"


@pytest.mark.parametrize("changes", [{"aud": "https://attacker.example"}, {"iss": "https://attacker.example"},
    {"sub": "999"}, {"sub": "103"}, {"exp": 1}, {"iat": 9999999999}, {"email_verified": False},
    {"email_verified": "true"}, {"exp": None}])
def test_real_invalid_token_rejected(tmp_path, tokens, changes):
    r = rig(tmp_path)
    request, mint = tokens
    auth = GoogleOIDCAuthenticator(r.identity, request)
    with pytest.raises(TrustAnchorError, match="AUTHENTICATION_REJECTED"):
        auth.authenticate(mint(r.identity, **changes))


def test_token_signature_forgery_rejected(tmp_path, tokens):
    r = rig(tmp_path)
    request, mint = tokens
    token = mint(r.identity)
    header, payload, signature = token.split(".")
    forged = header + "." + payload + "." + ("A" if signature[0] != "A" else "B") + signature[1:]
    with pytest.raises(TrustAnchorError, match="AUTHENTICATION_REJECTED"):
        GoogleOIDCAuthenticator(r.identity, request).authenticate(forged)


def test_copied_disk_cannot_supply_attached_identity(tmp_path, tokens, monkeypatch):
    r = rig(tmp_path)
    request, mint = tokens
    from google.auth import compute_engine
    monkeypatch.setenv("K_REVISION", r.identity.service_revision)
    class CopiedDiskCredential:
        def __init__(self, *args, **kwargs):
            self.token = mint(r.identity)
        def refresh(self, request):
            return None
    monkeypatch.setattr(compute_engine, "IDTokenCredentials", CopiedDiskCredential)
    with pytest.raises(TrustAnchorError, match="WORKLOAD_IDENTITY_MISMATCH"):
        runtime.attest_workload(r.identity, request)


@pytest.mark.parametrize("variable", ["GOOGLE_APPLICATION_CREDENTIALS", "GCE_METADATA_HOST", "GCE_METADATA_IP",
                                       "GCE_METADATA_ROOT", "STORAGE_EMULATOR_HOST", "K_REVISION"])
def test_no_credentials_or_endpoint_override(tmp_path, tokens, monkeypatch, variable):
    r = rig(tmp_path)
    monkeypatch.setenv("K_REVISION", r.identity.service_revision)
    monkeypatch.setenv(variable, "attacker-controlled")
    with pytest.raises(TrustAnchorError, match="WORKLOAD_IDENTITY_MISMATCH"):
        runtime.attest_workload(r.identity, tokens[0])


def test_no_identity_manifest_no_autoprovisioning(tmp_path, monkeypatch):
    missing = tmp_path / "not-provisioned.json"
    monkeypatch.setattr(runtime, "RELEASE_IDENTITY", missing)
    with pytest.raises(TrustAnchorError, match="PINNED_DEPLOYMENT_IDENTITY_REQUIRED"):
        runtime.build_production_service()
    assert not missing.exists()


def test_factory_rejects_test_witness_configuration(tmp_path, monkeypatch):
    r = rig(tmp_path)
    monkeypatch.setattr(runtime, "load_release_identity", lambda: r.identity)
    with pytest.raises(TrustAnchorError, match="PRODUCTION_WITNESS_TYPE_REQUIRED"):
        runtime.build_production_service({**asdict(r.identity), "witness_type": "TEST_MEMORY"})
    with pytest.raises(TypeError):
        runtime.build_production_service(signer=r.key)


def test_proposal_client_has_only_public_transport_and_rejects_forgery(tmp_path):
    r = rig(tmp_path)
    authorization = create_run(r)
    class Session:
        forged = False
        def post(self, url, **kwargs):
            assert url == r.identity.audience + "/oracle/get_authorization"
            assert kwargs["allow_redirects"] is False
            value = json.loads(authorization.encode())
            if self.forged:
                value["deployment_identity"] = "clone"
            return SimpleNamespace(status_code=200, json=lambda: value)
    session = Session()
    client = ProposalClient(r.identity, session, lambda audience: "oracle-token")
    for capability in ("create_run", "renew_authorization", "_signer", "_witness", "_private_key", "redirect_witness"):
        assert not hasattr(client, capability)
    assert client.get_authorization("run-1") == json.loads(authorization.encode())
    session.forged = True
    with pytest.raises(TrustAnchorError):
        client.get_authorization("run-1")
