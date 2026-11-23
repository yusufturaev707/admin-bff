"""The `permissions` table follows the registry in code (app.rbac.catalogue)."""

import pytest

from app import main
from app.core.db import create_engine, create_sessionmaker
from app.rbac.catalogue import CatalogueChanges, sync_permission_table
from app.rbac.registry import build_registry
from app.settings import Settings
from tests.conftest import Services
from tests.helpers.client import app_client
from tests.helpers.rbac import make_role


async def _table(services: Services) -> list[tuple[str, str, str]]:
    conn = await services.pg_connect()
    try:
        rows = await conn.fetch(
            "SELECT code, system_id, description FROM permissions ORDER BY code"
        )
    finally:
        await conn.close()
    return [(r["code"], r["system_id"], r["description"]) for r in rows]


def _registry_rows() -> list[tuple[str, str, str]]:
    return [(s.code, s.system_id, s.description) for s in build_registry()]


@pytest.mark.usefixtures("client")  # runs the app lifespan
async def test_startup_copies_the_registry(services: Services) -> None:
    assert await _table(services) == _registry_rows()


async def test_sync_fixes_drift_and_keeps_role_grants(
    settings: Settings, services: Services
) -> None:
    engine = create_engine(settings)
    db = create_sessionmaker(engine)
    try:
        await sync_permission_table(db, build_registry())
        # An old description and a permission that the code no longer declares,
        # still granted by a role.
        role_id = await make_role(settings, ["old:thing:read"])
        conn = await services.pg_connect()
        try:
            await conn.execute(
                "UPDATE permissions SET description = 'eski' WHERE code = 'admin:users:write'"
            )
            await conn.execute(
                "INSERT INTO permissions (code, system_id, description) "
                "VALUES ('old:thing:read', 'old', 'eski')"
            )
        finally:
            await conn.close()

        changes = await sync_permission_table(db, build_registry())
        assert (changes.added, changes.updated, changes.removed) == (
            [],
            ["admin:users:write"],
            ["old:thing:read"],
        )
        assert await _table(services) == _registry_rows()
        conn = await services.pg_connect()
        try:
            grants = await conn.fetch(
                "SELECT permission FROM role_permissions WHERE role_id = $1", role_id
            )
        finally:
            await conn.close()
        assert [g["permission"] for g in grants] == ["old:thing:read"]
        # Nothing left to change.
        assert not await sync_permission_table(db, build_registry())
    finally:
        await engine.dispose()
        await services.reset()


async def test_an_empty_table_is_filled(settings: Settings, services: Services) -> None:
    engine = create_engine(settings)
    try:
        conn = await services.pg_connect()
        try:
            await conn.execute("TRUNCATE permissions")
        finally:
            await conn.close()
        changes = await sync_permission_table(create_sessionmaker(engine), build_registry())
        assert changes.added == [code for code, _, _ in _registry_rows()]
        assert await _table(services) == _registry_rows()
    finally:
        await engine.dispose()
        await services.reset()


async def test_a_failed_sync_does_not_stop_the_service(
    settings: Settings,
    services: Services,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    # Nothing reads the copy at runtime, so a failed sync only warns.
    async def broken(*args: object) -> CatalogueChanges:
        raise ConnectionError

    monkeypatch.setattr(main, "sync_permission_table", broken)
    try:
        async with app_client(main.create_app(settings)) as client:
            assert (await client.get("/health")).status_code == 200
        assert "permission_catalogue_not_synced" in capsys.readouterr().out
    finally:
        await services.reset()
