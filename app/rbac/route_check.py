"""Deny-by-default at startup (section 7).

Every API route must either be on the public list or depend on a guard
(`require(...)`, `require_any(...)`, `get_principal`, `require_authenticated`,
`current_session`). Every permission a guard names must
be declared in the registry. Otherwise `RuntimeError` stops the startup.
"""

from fastapi import FastAPI
from fastapi.dependencies.models import Dependant
from fastapi.routing import APIRoute, iter_route_contexts

from app.core.guards import guard_permissions
from app.rbac.registry import PermissionRegistry

PUBLIC_PATHS = frozenset(
    {
        "/api/v1/auth/login",
        "/api/v1/auth/oneid/start",
        "/api/v1/auth/oneid/callback",
        "/health",
        "/ready",
    }
)


def _guards(dependant: Dependant) -> list[frozenset[str]]:
    found: list[frozenset[str]] = []
    for sub in dependant.dependencies:
        permissions = guard_permissions(sub.call)
        if permissions is not None:
            found.append(permissions)
        found.extend(_guards(sub))
    return found


def validate_access(
    app: FastAPI, registry: PermissionRegistry, *, extra_public: frozenset[str] = frozenset()
) -> None:
    public = PUBLIC_PATHS | extra_public
    for context in iter_route_contexts(app.routes):
        if not isinstance(context.original_route, APIRoute):
            continue
        path = context.path or ""
        where = f"{sorted(context.methods or ())} {path}"
        guards = _guards(context.dependant)
        if not guards and path not in public:
            raise RuntimeError(
                f"route {where} is not protected: add require(...) or another guard, "
                "or list it in PUBLIC_PATHS"
            )
        for permissions in guards:
            for permission in sorted(permissions):
                if permission not in registry:
                    raise RuntimeError(
                        f"route {where} requires {permission!r}, which is not declared "
                        "in the permission registry"
                    )
