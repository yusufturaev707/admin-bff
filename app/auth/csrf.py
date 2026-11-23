"""CSRF protection, part 1: the Origin check (section 6).

Every unsafe request (POST, PUT, PATCH, DELETE) must carry an `Origin` header
equal to FRONTEND_ORIGIN, otherwise it is rejected before routing. This also
covers /auth/login and /auth/mfa, which have no session yet (login CSRF). A
missing `Origin` is rejected too: browsers always send it on cross-origin
requests, and the frontend is on another origin than the API.

Part 2, the `X-CSRF-Token` check against the session, is in
app.auth.dependencies.current_session.
"""

from starlette.requests import Request
from starlette.types import ASGIApp, Receive, Scope, Send

from app.core.errors import ErrorCode, error_response
from app.core.logging import get_logger

UNSAFE_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})

logger = get_logger(__name__)


class OriginCheckMiddleware:
    def __init__(self, app: ASGIApp, *, allowed_origin: str | None) -> None:
        self.app = app
        # None: no frontend configured, so no unsafe request is accepted at all.
        self._allowed = allowed_origin.encode("latin-1") if allowed_origin else None

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] == "http" and scope["method"] in UNSAFE_METHODS:
            origin = next((v for k, v in scope.get("headers", ()) if k == b"origin"), None)
            if self._allowed is None or origin != self._allowed:
                logger.warning("csrf_origin_rejected", path=scope.get("path"))
                response = error_response(Request(scope), ErrorCode.CSRF_FAILED)
                await response(scope, receive, send)
                return
        await self.app(scope, receive, send)
