"""CSRF protection, part 1: the Origin check (section 6).

Every unsafe request (POST, PUT, PATCH, DELETE) must carry an `Origin` header
equal to FRONTEND_ORIGIN, otherwise it is rejected before routing. This also
covers /auth/login and /auth/mfa, which have no session yet (login CSRF). A
missing `Origin` is rejected too: browsers always send it on cross-origin
requests, and the frontend is on another origin than the API.

Part 2, the `X-CSRF-Token` check against the session, is in
app.auth.dependencies.current_session.

Outside production the API's own origin is accepted too (`allow_same_origin`):
Swagger UI at /api/v1/docs is served by the API and sends its requests from
there. A cross-site page still cannot pass, because its Origin is its own.
Production accepts FRONTEND_ORIGIN only.
"""

from starlette.requests import Request
from starlette.types import ASGIApp, Receive, Scope, Send

from app.core.errors import ErrorCode, error_response
from app.core.logging import get_logger

UNSAFE_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})

logger = get_logger(__name__)


class OriginCheckMiddleware:
    def __init__(
        self, app: ASGIApp, *, allowed_origin: str | None, allow_same_origin: bool = False
    ) -> None:
        self.app = app
        # None: no frontend configured, so no unsafe request is accepted at all.
        self._allowed = allowed_origin.encode("latin-1") if allowed_origin else None
        self._allow_same_origin = allow_same_origin

    def _accepted(self, scope: Scope, origin: bytes | None) -> bool:
        if origin is None:
            return False
        if self._allowed is not None and origin == self._allowed:
            return True
        if not self._allow_same_origin:
            return False
        host = next((v for k, v in scope.get("headers", ()) if k == b"host"), None)
        return host is not None and origin == scope.get("scheme", "http").encode() + b"://" + host

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] == "http" and scope["method"] in UNSAFE_METHODS:
            origin = next((v for k, v in scope.get("headers", ()) if k == b"origin"), None)
            if not self._accepted(scope, origin):
                logger.warning("csrf_origin_rejected", path=scope.get("path"))
                response = error_response(Request(scope), ErrorCode.CSRF_FAILED)
                await response(scope, receive, send)
                return
        await self.app(scope, receive, send)
