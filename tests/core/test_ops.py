"""Metrics, the per-session rate limit and the Gunicorn config (section 11)."""

import runpy
import uuid
from collections.abc import AsyncIterator
from pathlib import Path
from types import SimpleNamespace

import httpx
import pytest
from prometheus_client import REGISTRY

from app.main import create_app
from app.settings import Settings
from tests.conftest import FakeClock, Services
from tests.helpers.auth import AUTH, create_admin, login
from tests.helpers.client import app_client
from tests.helpers.rbac import make_admin_with

ROOT = Path(__file__).resolve().parents[2]


def _value(name: str, **labels: str) -> float:
    return REGISTRY.get_sample_value(name, labels) or 0.0


async def test_metrics_count_requests_by_route_template(
    client: httpx.AsyncClient, settings: Settings, clock: FakeClock
) -> None:
    admin = await make_admin_with(settings, clock, ["admin:users:read"])
    await login(client, admin, clock)
    route = "/api/v1/admin/users/{user_id}"
    before = _value("admin_bff_http_requests_total", method="GET", route=route, status="404")
    missing = uuid.uuid4()
    assert (await client.get(f"/api/v1/admin/users/{missing}")).status_code == 404

    response = await client.get("/metrics")
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/plain")
    text = response.text
    assert "admin_bff_http_request_duration_seconds_bucket" in text
    assert str(missing) not in text  # raw paths never become labels
    assert (
        _value("admin_bff_http_requests_total", method="GET", route=route, status="404")
        == before + 1
    )
    assert "/metrics" not in (await client.get("/api/v1/openapi.json")).json()["paths"]


async def test_failed_sign_ins_and_lockouts_are_counted(
    client: httpx.AsyncClient, settings: Settings, clock: FakeClock
) -> None:
    admin = await create_admin(settings, clock)
    failures = _value("admin_bff_login_failures_total", step="password")
    lockouts = _value("admin_bff_login_lockouts_total", rule="user")
    for _ in range(5):
        await client.post(f"{AUTH}/login", json={"username": admin.username, "password": "x" * 16})
    assert _value("admin_bff_login_failures_total", step="password") == failures + 5
    assert _value("admin_bff_login_lockouts_total", rule="user") == lockouts + 1


@pytest.fixture
async def limited_client(
    settings: Settings, clock: FakeClock, services: Services
) -> AsyncIterator[httpx.AsyncClient]:
    app = create_app(settings.model_copy(update={"session_requests_per_minute": 10}), clock=clock)
    async with app_client(app) as client:
        yield client
    await services.reset()


async def test_requests_per_session_are_limited(
    limited_client: httpx.AsyncClient, settings: Settings, clock: FakeClock
) -> None:
    admin = await make_admin_with(settings, clock, ["admin:users:read"])
    await login(limited_client, admin, clock)
    limited = _value("admin_bff_rate_limited_total", limit="session")
    for _ in range(10):
        assert (await limited_client.get("/api/v1/me")).status_code == 200
    response = await limited_client.get("/api/v1/me")
    assert response.status_code == 429
    assert response.json()["error"]["code"] == "rate_limited"
    assert 0 < int(response.headers["Retry-After"]) <= 60
    assert _value("admin_bff_rate_limited_total", limit="session") == limited + 1
    # Sign-in itself is limited by the lockout rules, not by this.
    assert (await limited_client.get("/health")).status_code == 200


def test_gunicorn_uses_uvicorn_worker_and_cleans_metric_files(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config = runpy.run_path(str(ROOT / "deploy" / "gunicorn.conf.py"))
    assert config["worker_class"] == "uvicorn_worker.UvicornWorker"
    assert config["bind"] == "unix:/run/admin-bff/bff.sock"

    directory = tmp_path / "prometheus"
    directory.mkdir()
    (directory / "counter_123.db").write_bytes(b"stale")
    monkeypatch.setenv("PROMETHEUS_MULTIPROC_DIR", str(directory))
    config["on_starting"](None)
    assert directory.is_dir()
    assert list(directory.iterdir()) == []
    config["child_exit"](None, SimpleNamespace(pid=123))  # no files left: no error
