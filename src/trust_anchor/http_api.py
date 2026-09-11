"""WSGI boundary for the dedicated authenticated Trust Anchor deployment."""

import json

from .authority import AuthorityUnavailableError, TrustAnchorError
from .witness import canonical

MAX_REQUEST_BYTES = 1_048_576


class TrustAnchorWSGI:
    def __init__(self, service):
        self._service = service

    def __call__(self, environ, start_response):
        try:
            if environ.get("REQUEST_METHOD") != "POST":
                raise TrustAnchorError("METHOD_REJECTED")
            routes = {"/admin/create_run": ("ADMIN", "create_run"),
                      "/admin/renew_authorization": ("ADMIN", "renew_authorization"),
                      "/oracle/get_authorization": ("ORACLE", "get_authorization"),
                      "/oracle/get_head": ("ORACLE", "get_head"),
                      "/oracle/propose_checkpoint": ("ORACLE", "propose_checkpoint")}
            role, operation = routes[environ.get("PATH_INFO", "")]
            header = environ.get("HTTP_AUTHORIZATION", "")
            if not header.startswith("Bearer ") or not header[7:]:
                raise TrustAnchorError("CALLER_AUTHENTICATION_REQUIRED")
            token = header[7:]
            if self._service._authenticator.authenticate(token) != role:
                raise TrustAnchorError("CAPABILITY_DENIED")
            if environ.get("CONTENT_TYPE", "").split(";")[0] != "application/json":
                raise TrustAnchorError("CONTENT_TYPE_REJECTED")
            size = int(environ.get("CONTENT_LENGTH", "0"))
            if size < 1 or size > MAX_REQUEST_BYTES:
                raise TrustAnchorError("REQUEST_SIZE_REJECTED")
            data = environ["wsgi.input"].read(size)
            if len(data) != size:
                raise TrustAnchorError("REQUEST_TRUNCATED")
            request = json.loads(data)
            if not isinstance(request, dict):
                raise TrustAnchorError("REQUEST_INVALID")
            result = self._service.handle(token, operation, request)
            status = "200 OK"
        except AuthorityUnavailableError as exc:
            status, result = "503 Service Unavailable", {"error": str(exc)}
        except (TrustAnchorError, ValueError, KeyError, TypeError):
            status, result = "403 Forbidden", {"error": "REQUEST_REJECTED"}
        except Exception:
            status, result = "503 Service Unavailable", {"error": "AUTHORITY_UNAVAILABLE"}
        body = canonical(result)
        start_response(status, [("Content-Type", "application/json"), ("Cache-Control", "no-store"),
                                ("Content-Length", str(len(body)))])
        return [body]


def create_application():
    from .runtime import build_production_service
    return TrustAnchorWSGI(build_production_service())
