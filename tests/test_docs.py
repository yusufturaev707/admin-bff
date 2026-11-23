"""Swagger UI and the OpenAPI schema for the frontend developer (section 10)."""

from collections.abc import AsyncIterator

import httpx
import pytest

from app import main
from app.api.docs import DOCS_URL, OPENAPI_URL, STATIC_URL
from app.main import create_app
from app.settings import Settings
from tests.auth_helpers import login
from tests.conftest import FakeClock, Services
from tests.helpers import app_client
from tests.rbac_helpers import make_admin_with


async def test_docs_are_open_outside_production(client: httpx.AsyncClient) -> None:
    page = await client.get(DOCS_URL)
    assert page.status_code == 200
    assert f'src="{STATIC_URL}/swagger-ui-bundle.js"' in page.text
    assert "<script>" not in page.text  # no inline script (CSP)
    assert "cdn" not in page.text.lower()
    init = await client.get(f"{DOCS_URL}/init.js")
    assert init.headers["content-type"].startswith("text/javascript")
    assert OPENAPI_URL in init.text
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

    monkeypatch.setattr(main, "check_audit_privileges", no_check)
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
    assert (await production.get(OPENAPI_URL)).json()["info"]["title"] == "UZBMB Admin BFF"


@pytest.mark.parametrize("path", ["/openapi.json", "/docs", "/redoc"])
async def test_fastapi_default_docs_are_off(client: httpx.AsyncClient, path: str) -> None:
    assert (await client.get(path)).status_code == 404
