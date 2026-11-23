"""Swagger UI and the OpenAPI schema for the frontend developer (section 10)."""

from collections.abc import AsyncIterator

import httpx
import pytest
from fastapi import FastAPI

from app import main
from app.api.docs import DOCS_URL, OPENAPI_URL, STATIC_URL
from app.main import create_app
from app.settings import Settings
from tests.auth_helpers import AUTH, login, totp_code
from tests.conftest import FakeClock, Services
from tests.helpers import app_client, extra_client
from tests.rbac_helpers import make_admin_with, make_superadmin


async def test_docs_are_open_outside_production(client: httpx.AsyncClient) -> None:
    page = await client.get(DOCS_URL)
    assert page.status_code == 200
    assert f'src="{STATIC_URL}/swagger-ui-bundle.js"' in page.text
    assert "<script>" not in page.text  # no inline script (CSP)
    assert "cdn" not in page.text.lower()
    init = await client.get(f"{DOCS_URL}/init.js")
    assert init.headers["content-type"].startswith("text/javascript")
    assert 'url: API + "/openapi.json"' in init.text
    schema = await client.get(OPENAPI_URL)
    assert schema.status_code == 200
    assert "/api/v1/audit" in schema.json()["paths"]
    assert DOCS_URL not in schema.json()["paths"]  # the docs are not part of the API
    for asset in ("swagger-ui-bundle.js", "swagger-ui.css", "favicon-32x32.png"):
        assert (await client.get(f"{STATIC_URL}/{asset}")).status_code == 200


@pytest.fixture
async def production(
    settings: Settings, clock: FakeClock, services: Services, monkeypatch: pytest.MonkeyPatch
) -> AsyncIterator[httpx.AsyncClient]:
    # The test DB has a single role; the privilege check has its own tests.
    async def no_check(*args: object) -> None:
        return None

    monkeypatch.setattr(main, "check_database", no_check)
    strong = {"app_env": "production", "argon2_time_cost": 2, "argon2_memory_cost_kib": 19456}
    async with app_client(create_app(settings.model_copy(update=strong), clock=clock)) as c:
        yield c
    await services.reset()


@pytest.mark.parametrize("path", [DOCS_URL, f"{DOCS_URL}/init.js", OPENAPI_URL])
async def test_docs_need_a_session_in_production(production: httpx.AsyncClient, path: str) -> None:
    response = await production.get(path)
    assert response.status_code == 401
    assert response.json()["error"]["code"] == "not_authenticated"


async def test_docs_need_the_permission_in_production(
    production: httpx.AsyncClient, settings: Settings, clock: FakeClock
) -> None:
    viewer = await make_admin_with(settings, clock, ["admin:users:read"])
    await login(production, viewer, clock)
    assert (await production.get(DOCS_URL)).status_code == 403
    assert (await production.get(OPENAPI_URL)).status_code == 403

    developer = await make_admin_with(settings, clock, ["admin:api:docs"])
    await login(production, developer, clock)
    assert (await production.get(DOCS_URL)).status_code == 200
    assert (await production.get(OPENAPI_URL)).json()["info"]["title"] == "UZBMB Admin"


@pytest.mark.parametrize("path", ["/openapi.json", "/docs", "/redoc"])
async def test_fastapi_default_docs_are_off(client: httpx.AsyncClient, path: str) -> None:
    assert (await client.get(path)).status_code == 404


SWAGGER_ORIGIN = "https://testserver"  # the API's own origin in these tests


async def test_swagger_signs_in_and_writes_outside_production(
    app: FastAPI, client: httpx.AsyncClient, settings: Settings, clock: FakeClock
) -> None:
    """What the docs page does: requests from the API's own origin, the CSRF
    token taken from the sign-in response."""
    superadmin = await make_superadmin(settings, clock)
    async with extra_client(app, origin=SWAGGER_ORIGIN) as swagger:
        clock.advance(30)
        start = await swagger.post(
            f"{AUTH}/login",
            json={"username": superadmin.username, "password": superadmin.password},
        )
        assert start.status_code == 200, start.text
        mfa = await swagger.post(
            f"{AUTH}/mfa",
            json={"mfa_token": start.json()["mfa_token"], "code": totp_code(superadmin, clock)},
        )
        assert mfa.status_code == 200
        csrf = mfa.json()["csrf_token"]
        created = await swagger.post(
            "/api/v1/admin/roles",
            json={"name": "from_swagger", "permissions": []},
            headers={"X-CSRF-Token": csrf},
        )
        assert created.status_code == 201, created.text
        # The CSRF token is still required.
        assert (await swagger.post(f"{AUTH}/logout")).status_code == 403
    async with extra_client(app, origin="https://evil.example") as other:
        rejected = await other.post(f"{AUTH}/login", json={"username": "x", "password": "y"})
    assert rejected.json()["error"]["code"] == "csrf_failed"


async def test_swagger_is_read_only_in_production(production: httpx.AsyncClient) -> None:
    response = await production.post(
        f"{AUTH}/login",
        json={"username": "x", "password": "y"},
        headers={"Origin": SWAGGER_ORIGIN},
    )
    assert response.status_code == 403
    assert response.json()["error"]["code"] == "csrf_failed"


async def test_sign_in_bar_is_on_outside_production(client: httpx.AsyncClient) -> None:
    init = (await client.get(f"{DOCS_URL}/init.js")).text
    assert "const SIGN_IN = true;" in init
    assert "X-CSRF-Token" in init
    page = (await client.get(DOCS_URL)).text
    assert 'id="bff-bar"' in page
    assert "style=" not in page
    css = await client.get(f"{DOCS_URL}/docs.css")
    assert css.headers["content-type"].startswith("text/css")


async def test_sign_in_bar_is_off_in_production(
    production: httpx.AsyncClient, settings: Settings, clock: FakeClock
) -> None:
    developer = await make_admin_with(settings, clock, ["admin:api:docs"])
    await login(production, developer, clock)
    assert "const SIGN_IN = false;" in (await production.get(f"{DOCS_URL}/init.js")).text


async def test_schema_states_the_access_of_every_operation(client: httpx.AsyncClient) -> None:
    schema = (await client.get(OPENAPI_URL)).json()
    assert set(schema["components"]["securitySchemes"]) == {"session", "csrf"}
    paths = schema["paths"]
    for operations in paths.values():
        for operation in operations.values():
            assert "security" in operation
    assert paths[f"{AUTH}/login"]["post"]["security"] == []
    users = paths["/api/v1/admin/users"]
    assert users["get"]["security"] == [{"session": []}]
    assert users["get"]["x-permissions"] == ["admin:users:read"]
    assert "x-step-up" not in users["get"]
    assert users["post"]["security"] == [{"session": [], "csrf": []}]
    assert users["post"]["x-step-up"] is True
    assert "`admin:users:write`" in users["post"]["description"]
