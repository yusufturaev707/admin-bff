"""RBAC test helpers: roles and grants written straight to the test DB."""

import secrets
import uuid
from collections.abc import Sequence

from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy.pool import NullPool

from app.core.db import create_sessionmaker, database_url
from app.rbac.models import SUPERADMIN_ROLE, Role, RolePermission, UserRole, UserScope
from app.settings import Settings
from tests.auth_helpers import Admin, create_admin
from tests.conftest import FakeClock

ALL_SCOPES: tuple[tuple[str, str], ...] = (("region", "*"), ("zone", "*"), ("branch", "*"))


async def _write(settings: Settings, *objects: object) -> None:
    engine = create_async_engine(database_url(settings), poolclass=NullPool)
    try:
        async with create_sessionmaker(engine)() as db, db.begin():
            for obj in objects:
                db.add(obj)
                await db.flush()
    finally:
        await engine.dispose()


async def make_role(
    settings: Settings, permissions: Sequence[str], *, name: str | None = None, system: bool = False
) -> uuid.UUID:
    role = Role(
        id=uuid.uuid4(),
        name=name or f"role_{secrets.token_hex(3)}",
        description="test",
        is_system=system,
    )
    await _write(
        settings, role, *(RolePermission(role_id=role.id, permission=p) for p in permissions)
    )
    return role.id


async def grant(
    settings: Settings,
    user_id: uuid.UUID,
    role_ids: Sequence[uuid.UUID],
    scopes: Sequence[tuple[str, str]] = ALL_SCOPES,
) -> None:
    await _write(
        settings,
        *(UserRole(user_id=user_id, role_id=r) for r in role_ids),
        *(UserScope(user_id=user_id, scope_type=t, scope_value=v) for t, v in scopes),
    )


async def make_superadmin(settings: Settings, clock: FakeClock) -> Admin:
    admin = await create_admin(settings, clock)
    role_id = await make_role(settings, ["*:*:*"], name=SUPERADMIN_ROLE, system=True)
    await grant(settings, admin.id, [role_id])
    return admin


async def make_admin_with(
    settings: Settings,
    clock: FakeClock,
    permissions: Sequence[str],
    scopes: Sequence[tuple[str, str]] = ALL_SCOPES,
) -> Admin:
    admin = await create_admin(settings, clock)
    if permissions:
        await grant(settings, admin.id, [await make_role(settings, permissions)], scopes)
    elif scopes:
        await grant(settings, admin.id, [], scopes)
    return admin
