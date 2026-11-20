import tomllib
from pathlib import Path

import pytest
from fastapi import APIRouter, FastAPI

from app import __version__
from app.cli import DEFAULT_OPENAPI_PATH, build_openapi_document, main
from app.core.routes import OPERATION_ID_RE, iter_api_routes, validate_routes
from app.main import OPENAPI_URL, create_app
from app.settings import Settings
from tests.helpers import app_client

ROOT = Path(__file__).resolve().parent.parent


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
    snapshot = (ROOT / DEFAULT_OPENAPI_PATH).read_text(encoding="utf-8")
    assert build_openapi_document() == snapshot, (
        "OpenAPI changed: review the contract change, then run "
        "`uv run python -m app.cli export-openapi`"
    )


def test_cli_check_detects_outdated_snapshot(tmp_path: Path) -> None:
    target = tmp_path / "v1.json"
    assert main(["export-openapi", "--output", str(target), "--check"]) == 1
    assert main(["export-openapi", "--output", str(target)]) == 0
    assert main(["export-openapi", "--output", str(target), "--check"]) == 0


async def test_openapi_is_served_outside_production(app: FastAPI) -> None:
    async with app_client(app) as client:
        response = await client.get(OPENAPI_URL)
    assert response.status_code == 200
    assert response.json()["info"]["version"] == __version__


@pytest.mark.parametrize("path", [OPENAPI_URL, "/openapi.json", "/docs", "/redoc"])
async def test_docs_are_closed_in_production(settings: Settings, path: str) -> None:
    app = create_app(settings.model_copy(update={"app_env": "production"}))
    async with app_client(app) as client:
        response = await client.get(path)
    assert response.status_code == 404


def test_version_matches_pyproject() -> None:
    pyproject = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    assert pyproject["project"]["version"] == __version__
