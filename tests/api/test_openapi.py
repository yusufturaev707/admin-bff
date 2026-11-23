import json
import os
import tomllib
from pathlib import Path

import pytest
from fastapi import APIRouter, FastAPI

from app import __version__
from app.core.routes import OPERATION_ID_RE, iter_api_routes, validate_routes
from app.main import OPENAPI_URL, create_app
from app.settings import Settings
from tests.helpers.client import app_client

ROOT = Path(__file__).resolve().parents[2]
SNAPSHOT_PATH = ROOT / "openapi" / "v1.json"
# `UPDATE_OPENAPI_SNAPSHOT=1 uv run pytest tests/api/test_openapi.py` rewrites the snapshot.
UPDATE_ENV = "UPDATE_OPENAPI_SNAPSHOT"


def build_openapi_document() -> str:
    """Renders the OpenAPI schema deterministically (independent of the environment)."""
    settings = Settings(_env_file=None, app_env="test", log_level="WARNING")
    schema = create_app(settings).openapi()
    return json.dumps(schema, indent=2, ensure_ascii=False, sort_keys=False) + "\n"


def test_operation_ids_are_explicit_unique_and_well_formed(app: FastAPI) -> None:
    routes = list(iter_api_routes(app))
    assert {r.path for r in routes} >= {"/health", "/ready"}
    ids = [r.operation_id for r in routes]
    assert all(isinstance(i, str) and OPERATION_ID_RE.match(i) for i in ids), ids
    assert len(ids) == len(set(ids))
    validate_routes(app)


def _router_with(path: str, operation_id: str | None) -> APIRouter:
    router = APIRouter()

    @router.get(path, operation_id=operation_id)
    async def endpoint() -> None:
        return None

    return router


@pytest.mark.parametrize(
    ("router", "message"),
    [
        (_router_with("/implicit", None), "no explicit operation_id"),
        (_router_with("/bad", "BadName"), "does not match"),
        (_router_with("/dup", "core_health_get"), "duplicate operation_id"),
    ],
)
async def test_bad_route_table_stops_startup(app: FastAPI, router: APIRouter, message: str) -> None:
    app.include_router(router, prefix="/api/v1")
    with pytest.raises(RuntimeError, match=message):
        async with app.router.lifespan_context(app):
            pass


def test_openapi_snapshot_is_up_to_date() -> None:
    document = build_openapi_document()
    if os.environ.get(UPDATE_ENV) == "1":
        SNAPSHOT_PATH.write_text(document, encoding="utf-8", newline="\n")
    snapshot = SNAPSHOT_PATH.read_text(encoding="utf-8")
    assert document == snapshot, (
        "OpenAPI changed: review the contract change, then run "
        f"`{UPDATE_ENV}=1 uv run pytest tests/api/test_openapi.py`"
    )


async def test_openapi_is_served_outside_production(app: FastAPI) -> None:
    async with app_client(app) as client:
        response = await client.get(OPENAPI_URL)
    assert response.status_code == 200
    assert response.json()["info"]["version"] == __version__


def test_version_matches_pyproject() -> None:
    pyproject = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    assert pyproject["project"]["version"] == __version__
