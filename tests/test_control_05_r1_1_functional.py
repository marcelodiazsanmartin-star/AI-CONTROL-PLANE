import io
import json

import pytest

from src.trust_anchor.http_api import TrustAnchorWSGI
from src.trust_anchor.service import TrustAnchorService
from src.trust_anchor.witness import canonical
from tests.control05_support import RUN_REQUEST, append_checkpoint, checkpoint, create_run, rig


def test_provisioned_service_authorization_and_restart(tmp_path):
    r = rig(tmp_path)
    authorization = create_run(r)
    first = append_checkpoint(r, authorization)
    second = append_checkpoint(r, authorization, sequence=1, previous=json.loads(first.payload_json)["checkpoint_hash"], data=b"second")
    restarted = TrustAnchorService(r.identity, r.witness, r.signer, r.auth, r.local)
    assert restarted.handle("oracle-token", "get_head", {"run_id": "run-1"}) == json.loads(second.encode())
    assert len(r.witness.verify_continuity(r.identity)) == 4
    assert r.local.path.read_bytes() == r.local.snapshot(r.identity, r.witness.read_current_state())


def test_startup_performs_no_create_or_sign(tmp_path):
    r = rig(tmp_path)
    assert all(method == "GET" for method, _, _ in r.cloud.calls)
    assert len(r.cloud.objects) == 1


def test_create_only_upload_and_generation_pinned_reads(tmp_path):
    r = rig(tmp_path)
    create_run(r)
    uploads = [kwargs for method, url, kwargs in r.cloud.calls if "/upload/" in url]
    assert len(uploads) == 1
    assert uploads[0]["params"]["ifGenerationMatch"] == 0
    assert uploads[0]["params"]["name"].endswith("00000000000000000001.json")
    downloads = [kwargs for _, url, kwargs in r.cloud.calls if "/o/" in url]
    assert downloads and all(d["params"]["generation"] == d["params"]["ifGenerationMatch"] for d in downloads)


def test_kms_signs_raw_data_and_has_no_private_key(tmp_path):
    r = rig(tmp_path)
    auth = create_run(r)
    auth.verify(r.identity)
    assert not hasattr(r.signer, "_private_key")
    calls = [kwargs for _, url, kwargs in r.cloud.calls if url.endswith(":asymmetricSign")]
    assert len(calls) == 1 and set(calls[0]["json"]) == {"data"}


def test_authorization_rotation_is_external(tmp_path):
    r = rig(tmp_path)
    old = create_run(r)
    renewed = r.service.handle("admin-token", "renew_authorization", {"run_id": "run-1"})
    assert json.loads(renewed["payload_json"])["epoch"] == 2
    assert renewed != json.loads(old.encode())
    assert r.service.handle("oracle-token", "get_authorization", {"run_id": "run-1"}) == renewed


def rpc(app, path, token, request):
    status = []
    data = canonical(request)
    body = app({"REQUEST_METHOD": "POST", "PATH_INFO": path, "HTTP_AUTHORIZATION": "Bearer " + token,
        "CONTENT_TYPE": "application/json", "CONTENT_LENGTH": str(len(data)), "wsgi.input": io.BytesIO(data)},
        lambda code, headers: status.append(code))
    return status[0], json.loads(b"".join(body))


def test_separate_api_paths_end_to_end(tmp_path):
    r = rig(tmp_path)
    app = TrustAnchorWSGI(r.service)
    assert rpc(app, "/admin/create_run", "admin-token", RUN_REQUEST)[0] == "200 OK"
    assert rpc(app, "/oracle/get_head", "oracle-token", {"run_id": "run-1"}) == (
        "200 OK", {"status": "NO_ACCEPTED_HEAD", "run_id": "run-1"})
    authorization = create_authorization_from_rpc(r)
    assert rpc(app, "/oracle/propose_checkpoint", "oracle-token", checkpoint(authorization))[0] == "200 OK"


def create_authorization_from_rpc(r):
    from src.trust_anchor.witness import WitnessRecord
    return WitnessRecord(**r.service.handle("oracle-token", "get_authorization", {"run_id": "run-1"}))
