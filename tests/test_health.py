import asyncio
from collections.abc import Mapping

import httpx
from fastapi import FastAPI

from app.api.health import ReadinessCheck, get_readiness_checks
from tests.helpers import app_client


async def _ok() -> None:
    return None


async def _fail() -> None:
    raise ConnectionRefusedError("connection to 10.0.0.5 refused")


async def _hang() -> None:
    await asyncio.sleep(60)


def _override(app: FastAPI, checks: Mapping[str, ReadinessCheck]) -> None:
    app.dependency_overrides[get_readiness_checks] = lambda: checks


async def test_health(client: httpx.AsyncClient) -> None:
    response = await client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


async def test_lifespan_registers_db_and_redis_checks(app: FastAPI) -> None:
    async with app_client(app):
        assert set(app.state.readiness_checks) == {"db", "redis"}


async def test_ready_ok(app: FastAPI) -> None:
    _override(app, {"db": _ok, "redis": _ok})
    async with app_client(app) as client:
        response = await client.get("/ready")
    assert response.status_code == 200
    assert response.json() == {"status": "ok", "checks": {"db": "ok", "redis": "ok"}}


async def test_ready_reports_failed_dependency(app: FastAPI) -> None:
    _override(app, {"db": _ok, "redis": _fail})
    async with app_client(app) as client:
        response = await client.get("/ready")
    assert response.status_code == 503
    assert response.json() == {"status": "unavailable", "checks": {"db": "ok", "redis": "error"}}
    assert "10.0.0.5" not in response.text


async def test_ready_times_out(app: FastAPI) -> None:
    app.state.settings = app.state.settings.model_copy(update={"ready_timeout_s": 0.05})
    _override(app, {"db": _hang, "redis": _ok})
    async with app_client(app) as client:
        response = await client.get("/ready")
    assert response.status_code == 503
    assert response.json()["checks"] == {"db": "error", "redis": "ok"}
