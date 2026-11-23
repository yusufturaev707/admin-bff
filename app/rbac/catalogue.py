"""Keeps the `permissions` table equal to the registry in code (section 7).

The registry is the source of truth, and the role editor reads it directly
(`GET /api/v1/admin/permissions`). The table is its copy for SQL access, so the
service brings it up to date at every startup: it adds new permissions,
updates changed descriptions and removes codes that are no longer declared.

* An advisory lock serialises the workers starting at once; the later ones
  find nothing to change.
* Role grants (`role_permissions`) are never touched: if a system's permissions
  vanish from the code (e.g. a connector is switched off), the roles keep their
  grants and get them back when it returns.
"""

from dataclasses import dataclass

from sqlalchemy import delete, select, text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.rbac.models import Permission
from app.rbac.registry import PermissionRegistry

# int.from_bytes(b"permsync")
PERMISSION_SYNC_LOCK_KEY = 8099005319310044771
_LOCK = text("SELECT pg_advisory_xact_lock(:key)")


@dataclass(frozen=True, slots=True)
class CatalogueChanges:
    added: list[str]
    updated: list[str]
    removed: list[str]

    def __bool__(self) -> bool:
        return bool(self.added or self.updated or self.removed)


async def sync_permission_table(
    db: async_sessionmaker[AsyncSession], registry: PermissionRegistry
) -> CatalogueChanges:
    declared = {spec.code: spec for spec in registry}
    async with db() as session, session.begin():
        await session.execute(_LOCK, {"key": PERMISSION_SYNC_LOCK_KEY})
        stored = {row.code: row for row in (await session.scalars(select(Permission))).all()}
        updated: list[str] = []
        for code, spec in declared.items():
            row = stored.get(code)
            if row is None:
                session.add(
                    Permission(code=code, system_id=spec.system_id, description=spec.description)
                )
            elif (row.system_id, row.description) != (spec.system_id, spec.description):
                row.system_id, row.description = spec.system_id, spec.description
                updated.append(code)
        removed = sorted(set(stored) - set(declared))
        if removed:
            await session.execute(delete(Permission).where(Permission.code.in_(removed)))
    return CatalogueChanges(
        added=sorted(set(declared) - set(stored)), updated=sorted(updated), removed=removed
    )
