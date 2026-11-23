"""Request-level audit (section 9): every POST, PUT, PATCH and DELETE request
and every 403 leaves an audit record, even where no service wrote one.

Services write the meaningful events themselves (`admin.user.create`,
`auth.login`, `rbac.denied`, ...). When a request ends without any audit event
(a validation error, a CSRF rejection, a missing object, a write route that
forgot to audit), this middleware writes `http.request` with the method, the
path (without the query string), the status and, if known, the admin.

The record is written when the response starts, before the client sees it.
A failure to write it is logged, not raised: the response is already decided.

Not recorded: 404/405 of requests without a session (scanners probing paths;
the access log has them).
"""

from starlette.types import ASGIApp, Message, Receive, Scope, Send

from app.audit.context import RequestAudit, end_request, start_request
from app.audit.sink import AuditEvent, AuditOutcome, AuditSink
from app.auth.csrf import UNSAFE_METHODS
from app.core.logging import get_logger

_MAX_PATH = 512
_MAX_USER_AGENT = 256

logger = get_logger(__name__)


def outcome_for_status(status: int) -> AuditOutcome:
    if status < 400:
        return AuditOutcome.SUCCESS
    if status in (401, 403, 429):
        return AuditOutcome.DENIED
    return AuditOutcome.ERROR


def system_for_path(path: str) -> str | None:
    """`/api/v1/admin/users` -> `admin`; `/api/v1/systems/faceid/...` -> `faceid`."""
    parts = path.strip("/").split("/")
    if len(parts) < 3 or parts[:2] != ["api", "v1"] or not parts[2]:
        return None
    if parts[2] == "systems":
        return parts[3] if len(parts) > 3 and parts[3] else None
    return parts[2]


def needs_record(method: str, status: int, state: RequestAudit) -> bool:
    if state.written or (method not in UNSAFE_METHODS and status != 403):
        return False
    return not (state.actor_id is None and status in (404, 405))


class AuditRequestMiddleware:
    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        state, token = start_request()
        started = False

        async def send_and_audit(message: Message) -> None:
            nonlocal started
            if message["type"] == "http.response.start" and not started:
                started = True
                await self._record(scope, state, int(message["status"]))
            await send(message)

        try:
            await self.app(scope, receive, send_and_audit)
        except Exception:
            # The 500 response is sent outside this middleware.
            if not started:
                await self._record(scope, state, 500)
            raise
        finally:
            end_request(token)

    async def _record(self, scope: Scope, state: RequestAudit, status: int) -> None:
        method = str(scope.get("method", ""))
        if not needs_record(method, status, state):
            return
        sink: AuditSink | None = getattr(scope["app"].state, "audit_sink", None)
        if sink is None:  # pragma: no cover - set in lifespan
            return
        path = str(scope.get("path", ""))[:_MAX_PATH]
        client = scope.get("client")
        headers = dict(scope.get("headers", ()))
        user_agent = headers.get(b"user-agent", b"").decode("latin-1")[:_MAX_USER_AGENT]
        request_id = scope.get("state", {}).get("request_id")
        try:
            await sink.write(
                AuditEvent(
                    action="http.request",
                    outcome=outcome_for_status(status),
                    actor_id=state.actor_id,
                    actor_username=state.actor_username,
                    actor_ip=client[0] if client else None,
                    user_agent=user_agent,
                    session_hash=state.session_hash,
                    request_id=request_id if isinstance(request_id, str) else None,
                    system_id=system_for_path(path),
                    status_code=status,
                    details={"method": method, "path": path},
                )
            )
        except Exception:
            logger.exception("audit_request_record_failed", method=method, status=status)
