"""Request body limit (section 11), answered in the unified error format.

Nginx refuses larger bodies first (`client_max_body_size 1m`); the app enforces
the limit as well, so a large body never reaches a handler in full.

* A declared `Content-Length` over the limit is answered at once with a 413,
  without reading the body.
* A body without one (chunked) is counted as it arrives. When it passes the
  limit, reading it raises an HTTPException(413) inside the handler, which the
  error handlers turn into the unified format. (It must be an HTTPException:
  FastAPI turns any other error raised while it reads the body into a 400.)

Starlette's own limit (FastAPI `max_body_size`) is not used: it answers a
declared oversize body with a plain-text 413, replacing the unified error.
"""

from starlette.exceptions import HTTPException
from starlette.requests import Request
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from app.core.errors import BODY_TOO_LARGE, ErrorCode, error_response

TOO_LARGE_STATUS = 413


def _declared_length(scope: Scope) -> int | None:
    for name, value in scope.get("headers", ()):
        if name == b"content-length":
            try:
                return int(value)
            except ValueError:
                return None  # counted while it is read instead
    return None


class BodySizeLimitMiddleware:
    def __init__(self, app: ASGIApp, *, max_bytes: int) -> None:
        self.app = app
        self.max_bytes = max_bytes

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        declared = _declared_length(scope)
        if declared is not None and declared > self.max_bytes:
            response = error_response(
                Request(scope),
                ErrorCode.VALIDATION_ERROR,
                status_code=TOO_LARGE_STATUS,
                message=BODY_TOO_LARGE,
            )
            await response(scope, receive, send)
            return

        received = 0

        async def limited_receive() -> Message:
            nonlocal received
            message = await receive()
            if message["type"] == "http.request":
                received += len(message.get("body", b""))
                if received > self.max_bytes:
                    raise HTTPException(status_code=TOO_LARGE_STATUS)
            return message

        await self.app(scope, limited_receive, send)
