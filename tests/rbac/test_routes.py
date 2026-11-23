"""Deny-by-default: the startup refuses unprotected routes and unknown permissions."""

import httpx
import pytest
from fastapi import APIRouter, Depends, FastAPI

from app.rbac.dependencies import require, require_any
from app.rbac.route_check import PUBLIC_PATHS
from app.settings import Settings
from tests.conftest import FakeClock
from tests.helpers.auth import create_admin, login
from tests.helpers.client import app_client
from tests.helpers.rbac import make_admin_with


def _router(path: str, *dependencies: object) -> APIRouter:
    router = APIRouter(dependencies=list(dependencies))  # type: ignore[arg-type]

    @router.get(path, operation_id="test_route_get")
    async def handler() -> dict[str, str]:
        return {"ok": "yes"}

    return router


async def _start(app: FastAPI) -> None:
    async with app.router.lifespan_context(app):
        pass


async def test_unprotected_route_stops_startup(app: FastAPI) -> None:
    app.include_router(_router("/api/v1/open"))
    with pytest.raises(RuntimeError, match="is not protected"):
        await _start(app)


async def test_undeclared_permission_stops_startup(app: FastAPI) -> None:
    app.include_router(_router("/api/v1/typo", Depends(require("admin:users:raed"))))
    with pytest.raises(RuntimeError, match="not declared in the permission registry"):
        await _start(app)


async def test_guard_on_the_router_level_counts(app: FastAPI) -> None:
    app.include_router(_router("/api/v1/guarded", Depends(require("admin:users:read"))))
    await _start(app)


def test_route_permissions_must_be_exact() -> None:
    with pytest.raises(ValueError, match="exact"):
        require("admin:*:read")


def test_public_list_is_the_spec() -> None:
    assert {
        "/api/v1/auth/login",
        "/api/v1/auth/oneid/start",
        "/api/v1/auth/oneid/callback",
        "/health",
        "/ready",
    } == PUBLIC_PATHS


async def test_admin_without_roles_is_forbidden_everywhere(
    client: httpx.AsyncClient, settings: Settings, clock: FakeClock
) -> None:
    await login(client, await create_admin(settings, clock), clock)
    for path in ("/api/v1/admin/users", "/api/v1/admin/roles", "/api/v1/admin/permissions"):
        response = await client.get(path)
        assert response.status_code == 403, path
        assert response.json()["error"]["code"] == "forbidden"
    assert (await client.get("/api/v1/me")).status_code == 200


async def test_require_any(app: FastAPI, settings: Settings, clock: FakeClock) -> None:
    router = APIRouter()

    @router.get(
        "/api/v1/_test/either",
        operation_id="test_either_get",
        dependencies=[Depends(require_any("admin:users:read", "admin:roles:read"))],
    )
    async def either() -> dict[str, str]:
        return {"ok": "yes"}

    app.include_router(router)
    roles_reader = await make_admin_with(settings, clock, ["admin:roles:read"])
    nobody = await make_admin_with(settings, clock, [])
    async with app_client(app) as client:
        await login(client, roles_reader, clock)
        assert (await client.get("/api/v1/_test/either")).status_code == 200
        await login(client, nobody, clock)
        assert (await client.get("/api/v1/_test/either")).status_code == 403
    with pytest.raises(ValueError, match="at least one"):
        require_any()
