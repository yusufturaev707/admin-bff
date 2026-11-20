"""Request ID and access log middleware (section 11).

* An incoming `X-Request-ID` is accepted only if it is a UUID (normalised to
  the canonical form); otherwise a new UUID4 is generated.
* The ID is bound to the structlog context, stored in `request.state` (so the
  error handlers can put it into the error body) and returned in the response.
* One access log line per request: method, path (without the query string, it
  may contain personal data), status, duration. `/health` is not logged.

Written as a pure ASGI middleware (not `BaseHTTPMiddleware`) so the handler runs
in the same task and context variables propagate correctly.
"""

import time
import uuid

import structlog
from starlette.datastructures import MutableHeaders
from starlette.requests import HTTPConnection
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from app.core.logging import get_logger

REQUEST_ID_HEADER = "X-Request-ID"
_REQUEST_ID_HEADER_RAW = REQUEST_ID_HEADER.lower().encode("latin-1")
_MAX_INCOMING_LENGTH = 64
_NOT_LOGGED_PATHS = frozenset({"/health"})

access_logger = get_logger("app.access")


def parse_request_id(raw: str | None) -> str | None:
    """Returns the canonical UUID string, or None if `raw` is not a UUID."""
    if not raw or len(raw) > _MAX_INCOMING_LENGTH:
        return None
    try:
        return str(uuid.UUID(raw))
    except ValueError:
        return None


def get_request_id(conn: HTTPConnection) -> str | None:
    value = conn.scope.get("state", {}).get("request_id")
    return value if isinstance(value, str) else None


class RequestContextMiddleware:
    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        incoming: str | None = None
        for name, value in scope.get("headers", ()):
            if name == _REQUEST_ID_HEADER_RAW:
                incoming = value.decode("latin-1")
                break
        request_id = parse_request_id(incoming) or str(uuid.uuid4())
        scope.setdefault("state", {})["request_id"] = request_id

        structlog.contextvars.clear_contextvars()
        structlog.contextvars.bind_contextvars(request_id=request_id)

        status_code = 500
        started = time.perf_counter()

        async def send_with_request_id(message: Message) -> None:
            nonlocal status_code
            if message["type"] == "http.response.start":
                status_code = message["status"]
                headers = MutableHeaders(scope=message)
                headers[REQUEST_ID_HEADER] = request_id
            await send(message)

        try:
            await self.app(scope, receive, send_with_request_id)
        finally:
            path: str = scope.get("path", "")
            if path not in _NOT_LOGGED_PATHS:
                access_logger.info(
                    "request",
                    method=scope.get("method"),
                    path=path,
                    status=status_code,
                    duration_ms=round((time.perf_counter() - started) * 1000, 2),
                )
            # The context is intentionally not cleared here: an unhandled
            # exception is logged by ServerErrorMiddleware (outside this
            # middleware) and must still carry the request_id. Each request
            # runs in its own task, so nothing leaks between requests.
