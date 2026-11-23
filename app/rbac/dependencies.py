"""Authorization dependencies (section 7).

    @router.get(..., dependencies=[Depends(require("admin:users:read"))])
    async def handler(principal: Annotated[Principal, Depends(require("..."))]): ...

* `require(perm)` / `require_any(*perms)`: 403 `forbidden` without the permission;
  every denial is audited.
* `get_principal`: any fully set-up session (e.g. `/me`).
* `require_recent_mfa(max_age_s)` (step-up) lives in app.auth.dependencies.

The permissions named here are checked against the registry at startup
(app.rbac.route_check), so a typo stops the service instead of locking a route.
"""

from collections.abc import Awaitable, Callable
from typing import Annotated

from fastapi import Depends, Request

from app.audit.sink import AuditEvent, AuditOutcome, AuditSink
from app.auth.dependencies import AuthenticatedSession, request_meta, require_recent_mfa
from app.core.errors import AppError, ErrorCode
from app.core.guards import mark_guard
from app.rbac.permissions import PERMISSION_RE
from app.rbac.principal import Principal, PrincipalLoader

__all__ = ["PrincipalDep", "get_principal", "require", "require_any", "require_recent_mfa"]


async def get_principal(request: Request, session: AuthenticatedSession) -> Principal:
    loader = request.app.state.principal_loader
    if not isinstance(loader, PrincipalLoader):  # pragma: no cover - set in lifespan
        raise RuntimeError("principal loader is not initialised")
    principal = await loader.load(session)
    if principal is None:
        # Blocked or removed meanwhile (its sessions are revoked as well).
        raise AppError(ErrorCode.SESSION_EXPIRED)
    return principal


mark_guard(get_principal)
PrincipalDep = Annotated[Principal, Depends(get_principal)]


async def _audit_denied(request: Request, principal: Principal, required: list[str]) -> None:
    sink: AuditSink = request.app.state.audit_sink
    meta = await request_meta(request)
    # The system the request was for: the first segment of the permission.
    systems = {permission.split(":", 1)[0] for permission in required}
    await sink.write(
        AuditEvent(
            action="rbac.denied",
            outcome=AuditOutcome.DENIED,
            actor_id=principal.user_id,
            actor_username=principal.username,
            actor_ip=meta.ip,
            user_agent=meta.user_agent,
            session_hash=principal.session_key,
            request_id=meta.request_id,
            system_id=systems.pop() if len(systems) == 1 else None,
            status_code=403,
            details={"method": request.method, "path": request.url.path, "required": required},
        )
    )


def _checked(permissions: tuple[str, ...]) -> tuple[str, ...]:
    if not permissions:
        raise ValueError("at least one permission is required")
    for permission in permissions:
        if not PERMISSION_RE.fullmatch(permission):
            # Wildcards are for grants only; a route always names one exact permission.
            raise ValueError(f"route permission {permission!r} must be an exact 'a:b:c'")
    return permissions


def require(permission: str) -> Callable[..., Awaitable[Principal]]:
    (checked,) = _checked((permission,))

    async def dependency(request: Request, principal: PrincipalDep) -> Principal:
        if not principal.has(checked):
            await _audit_denied(request, principal, [checked])
            raise AppError(ErrorCode.FORBIDDEN)
        return principal

    dependency.__name__ = f"require[{checked}]"
    return mark_guard(dependency, [checked])


def require_any(*permissions: str) -> Callable[..., Awaitable[Principal]]:
    checked = _checked(permissions)

    async def dependency(request: Request, principal: PrincipalDep) -> Principal:
        if not any(principal.has(p) for p in checked):
            await _audit_denied(request, principal, list(checked))
            raise AppError(ErrorCode.FORBIDDEN)
        return principal

    dependency.__name__ = f"require_any[{','.join(checked)}]"
    return mark_guard(dependency, checked)


def ensure_in_scope(principal: Principal, scope_type: str, value: str | None) -> None:
    """Row-level check for detail endpoints (BOLA): an object outside the admin's
    scope is reported as missing (404), so its existence is not disclosed."""
    if not principal.in_scope(scope_type, value):
        raise AppError(ErrorCode.NOT_FOUND)
