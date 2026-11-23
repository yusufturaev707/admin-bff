import httpx
import pytest

from app.main import create_app
from app.settings import Settings
from tests.helpers import FRONTEND_ORIGIN, app_client


def _preflight_headers(origin: str) -> dict[str, str]:
    return {
        "Origin": origin,
        "Access-Control-Request-Method": "POST",
        "Access-Control-Request-Headers": "X-CSRF-Token",
    }


async def test_preflight_from_frontend_origin(client: httpx.AsyncClient) -> None:
    response = await client.options("/health", headers=_preflight_headers(FRONTEND_ORIGIN))
    assert response.status_code == 200
    assert response.headers["Access-Control-Allow-Origin"] == FRONTEND_ORIGIN
    assert response.headers["Access-Control-Allow-Credentials"] == "true"
    assert "X-Request-ID" in response.headers


async def test_other_origin_is_not_allowed(client: httpx.AsyncClient) -> None:
    response = await client.options(
        "/health", headers=_preflight_headers("https://evil.example.com")
    )
    assert "Access-Control-Allow-Origin" not in response.headers

    response = await client.get("/health", headers={"Origin": "https://evil.example.com"})
    assert "Access-Control-Allow-Origin" not in response.headers


async def test_simple_request_exposes_request_id(client: httpx.AsyncClient) -> None:
    response = await client.get("/health", headers={"Origin": FRONTEND_ORIGIN})
    assert response.headers["Access-Control-Allow-Origin"] == FRONTEND_ORIGIN
    assert "X-Request-ID" in response.headers["Access-Control-Expose-Headers"]


async def test_no_cors_without_frontend_origin(settings: Settings) -> None:
    app = create_app(settings.model_copy(update={"frontend_origin": None}))
    async with app_client(app) as client:
        response = await client.get("/health", headers={"Origin": FRONTEND_ORIGIN})
    assert "Access-Control-Allow-Origin" not in response.headers


@pytest.mark.parametrize("origin", ["null", "https://admin.test.uz.evil.com"])
async def test_lookalike_origins_are_rejected(client: httpx.AsyncClient, origin: str) -> None:
    response = await client.get("/health", headers={"Origin": origin})
    assert "Access-Control-Allow-Origin" not in response.headers
