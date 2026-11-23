"""CLI: sync-permissions and create-superadmin with the superadmin role (section 7)."""

import asyncio
import getpass
import secrets
from typing import Any

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy.pool import NullPool

from app import cli
from app.core.db import create_sessionmaker, database_url
from app.rbac.models import Permission, Role, RolePermission, UserRole, UserScope
from app.rbac.registry import build_registry
from app.settings import Settings
from tests.auth_helpers import create_admin
from tests.conftest import FakeClock
from tests.rbac_helpers import make_role


async def _query(settings: Settings, statement: Any) -> list[Any]:
    engine = create_async_engine(database_url(settings), poolclass=NullPool)
    try:
        async with create_sessionmaker(engine)() as db:
            return list((await db.execute(statement)).all())
    finally:
        await engine.dispose()


def test_sync_permissions(cli_env: Settings) -> None:
    obsolete_role = asyncio.run(make_role(cli_env, ["admin:users:read"]))
    asyncio.run(_seed_obsolete(cli_env, obsolete_role))

    assert cli.main(["sync-permissions"]) == 0
    assert cli.main(["sync-permissions"]) == 0  # idempotent

    stored = {row[0] for row in asyncio.run(_query(cli_env, select(Permission.code)))}
    assert stored == {spec.code for spec in build_registry()}
    grants = {
        row[0]
        for row in asyncio.run(
            _query(
                cli_env,
                select(RolePermission.permission).where(RolePermission.role_id == obsolete_role),
            )
        )
    }
    assert grants == {"admin:users:read"}  # the removed code is gone, the rest stays
    superadmin = asyncio.run(
        _query(cli_env, select(Role.is_system).where(Role.name == "superadmin"))
    )
    assert superadmin == [(True,)]


async def _seed_obsolete(settings: Settings, role_id: object) -> None:
    engine = create_async_engine(database_url(settings), poolclass=NullPool)
    try:
        async with create_sessionmaker(engine)() as db, db.begin():
            db.add(Permission(code="old:thing:read", system_id="old", description="eski"))
            db.add(RolePermission(role_id=role_id, permission="old:thing:read"))
    finally:
        await engine.dispose()


def test_create_superadmin_gets_the_role_and_every_scope(
    cli_env: Settings, clean_env: pytest.MonkeyPatch
) -> None:
    password = secrets.token_urlsafe(18)
    replies = iter([password, password])
    clean_env.setattr(getpass, "getpass", lambda prompt="": next(replies))

    assert cli.main(["create-superadmin", "--username", "chief"]) == 0
    roles = asyncio.run(
        _query(
            cli_env,
            select(Role.name, RolePermission.permission)
            .join(UserRole, UserRole.role_id == Role.id)
            .join(RolePermission, RolePermission.role_id == Role.id),
        )
    )
    assert roles == [("superadmin", "*:*:*")]
    scopes = asyncio.run(_query(cli_env, select(UserScope.scope_type, UserScope.scope_value)))
    assert sorted(scopes) == [("branch", "*"), ("region", "*"), ("zone", "*")]


def test_promote_an_existing_admin(cli_env: Settings, clock: FakeClock) -> None:
    admin = asyncio.run(create_admin(cli_env, clock))
    assert cli.main(["create-superadmin", "--username", admin.username]) == 1  # exists
    assert cli.main(["create-superadmin", "--username", "nobody_here", "--existing"]) == 1
    assert cli.main(["create-superadmin", "--username", admin.username, "--existing"]) == 0
    assert cli.main(["create-superadmin", "--username", admin.username, "--existing"]) == 0
    members = asyncio.run(
        _query(
            cli_env,
            select(UserRole.user_id)
            .join(Role, Role.id == UserRole.role_id)
            .where(Role.name == "superadmin"),
        )
    )
    assert members == [(admin.id,)]
