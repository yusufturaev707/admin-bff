"""FastAPI dependencies of the auth module.

* `current_session`: a valid session (setup sessions included) + CSRF token;
* `require_authenticated`: a fully set-up session (TOTP enrolled, password changed);
* `require_recent_mfa(max_age_s)`: TOTP entered recently (step-up, section 7).

Phase 2 builds `require("perm")` on top of `require_authenticated`.
"""

import hmac
from collections.abc import Awaitable, Callable
from datetime import timedelta
from typing import Annotated

import structlog
from fastapi import Depends, Request, Response

from app.audit.context import set_actor as set_audit_actor
from app.auth.csrf import UNSAFE_METHODS
from app.auth.service import AuthService, RequestMeta
from app.auth.sessions import SessionData
from app.core.errors import AppError, ErrorCode
from app.core.guards import mark_guard
from app.core.request_id import get_request_id
from app.core.time import Clock

# `__Host-`: the browser accepts it only with Secure, Path=/ and no Domain,
# so the cookie stays on the API host and cannot be set by a subdomain.
SESSION_COOKIE = "__Host-admin_session"
CSRF_HEADER = "X-CSRF-Token"
_USER_AGENT_MAX = 256


# Plain lookups are `async def` on purpose: FastAPI runs sync dependencies in a
# thread pool, which would cost a thread hop on every request.
async def get_auth_service(request: Request) -> AuthService:
    service = request.app.state.auth_service
    if not isinstance(service, AuthService):  # pragma: no cover - set in lifespan
        raise RuntimeError("auth service is not initialised")
    return service


AuthServiceDep = Annotated[AuthService, Depends(get_auth_service)]


async def get_clock(request: Request) -> Clock:
    clock: Clock = request.app.state.clock
    return clock


async def request_meta(request: Request) -> RequestMeta:
    # Behind Nginx the client address comes from X-Forwarded-For, which Nginx
    # overwrites with $remote_addr (deploy/nginx/admin-api.conf).
    return RequestMeta(
        ip=request.client.host if request.client else "unknown",
        user_agent=request.headers.get("user-agent", "")[:_USER_AGENT_MAX],
        request_id=get_request_id(request),
    )


RequestMetaDep = Annotated[RequestMeta, Depends(request_meta)]


def set_session_cookie(response: Response, session_id: str) -> None:
    response.set_cookie(
        SESSION_COOKIE, session_id, path="/", secure=True, httponly=True, samesite="strict"
    )


def clear_session_cookie(response: Response) -> None:
    response.delete_cookie(SESSION_COOKIE, path="/", secure=True, httponly=True, samesite="strict")


_CLEAR_SESSION_COOKIE = f"{SESSION_COOKIE}=; Max-Age=0; Path=/; Secure; HttpOnly; SameSite=strict"


async def current_session(request: Request, service: AuthServiceDep) -> SessionData:
    session_id = request.cookies.get(SESSION_COOKIE)
    if not session_id:
        raise AppError(ErrorCode.NOT_AUTHENTICATED)
    session = await service.sessions.load(session_id)
    if session is None:
        raise AppError(ErrorCode.SESSION_EXPIRED, headers={"Set-Cookie": _CLEAR_SESSION_COOKIE})
    # Known before the CSRF check: a rejected request is audited with its admin.
    set_audit_actor(session.user_id, session.username, session.key)
    if request.method in UNSAFE_METHODS:
        token = request.headers.get(CSRF_HEADER, "")
        # Header values are latin-1 strings; bytes keep compare_digest total.
        if not hmac.compare_digest(token.encode("latin-1"), session.csrf_token.encode()):
            raise AppError(ErrorCode.CSRF_FAILED)
    structlog.contextvars.bind_contextvars(user_id=str(session.user_id))
    return session


mark_guard(current_session)
CurrentSession = Annotated[SessionData, Depends(current_session)]


async def require_authenticated(session: CurrentSession) -> SessionData:
    if session.pending:
        raise AppError(
            ErrorCode.FORBIDDEN,
            "Avval hisobingizni sozlashni yakunlang",
            details={"pending": [step.value for step in session.pending]},
        )
    return session


mark_guard(require_authenticated)
AuthenticatedSession = Annotated[SessionData, Depends(require_authenticated)]


def require_recent_mfa(max_age_s: int = 300) -> Callable[..., Awaitable[SessionData]]:
    """401 `step_up_required` unless TOTP was entered within `max_age_s` seconds."""

    async def dependency(
        session: AuthenticatedSession, clock: Annotated[Clock, Depends(get_clock)]
    ) -> SessionData:
        if session.mfa_at is None or clock() - session.mfa_at > timedelta(seconds=max_age_s):
            raise AppError(ErrorCode.STEP_UP_REQUIRED)
        return session

    return mark_guard(dependency)
