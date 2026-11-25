"""The database checks at startup (app.main.check_database)."""

import secrets

import pytest

from app.main import create_app
from app.settings import Settings
from tests.conftest import FakeClock
from tests.helpers.client import app_client


def _production(settings: Settings, **changes: object) -> Settings:
    return settings.model_copy(
        update={
            "app_env": "production",
            "argon2_time_cost": 2,
            "argon2_memory_cost_kib": 19456,
            **changes,
        }
    )


async def test_production_starts_with_one_db_user(settings: Settings, clock: FakeClock) -> None:
    # Owner's decision (2026-11-24): the migrations and the service share one DB user.
    async with app_client(create_app(_production(settings), clock=clock)) as client:
        assert (await client.get("/ready")).status_code == 200


async def test_production_refuses_to_start_without_the_database(settings: Settings) -> None:
    app = create_app(_production(settings, db_name=f"missing_{secrets.token_hex(4)}"))
    with pytest.raises(RuntimeError, match="cannot check the database"):
        async with app.router.lifespan_context(app):
            pass


async def test_development_only_warns_without_the_database(settings: Settings) -> None:
    app = create_app(settings.model_copy(update={"db_name": f"missing_{secrets.token_hex(4)}"}))
    async with app.router.lifespan_context(app):
        pass
