"""Principal: who the current admin is and what they may do (section 7).

Loaded from the DB once and cached in Redis under the admin's `perm_version`:
`principal:<user_id>:<perm_version>`. Changing an admin's roles or scopes, or
the permissions of a role, bumps `perm_version` in the DB (`bump`, inside the
transaction) and then in Redis (`publish`, after the commit), so the very next
request loads a fresh principal. The Redis version only ever grows: a request
that read old data concurrently cannot move it back.
"""

import json
import uuid
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field, replace

from redis.asyncio import Redis
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.auth.models import AdminUser
from app.auth.sessions import SessionData
from app.rbac.models import SCOPE_ALL, RolePermission, UserRole, UserScope
from app.rbac.permissions import any_covers, pattern_matches

PRINCIPAL_TTL_S = 5 * 60
PERM_VERSION_TTL_S = 24 * 3600

_SET_MAX_LUA = """
local current = redis.call('GET', KEYS[1])
if (not current) or tonumber(current) < tonumber(ARGV[1]) then
  redis.call('SET', KEYS[1], ARGV[1], 'EX', ARGV[2])
  return 1
end
redis.call('EXPIRE', KEYS[1], ARGV[2])
return 0
"""


@dataclass(frozen=True, slots=True)
class Principal:
    user_id: uuid.UUID
    username: str
    full_name: str | None
    permissions: frozenset[str]  # granted patterns (exact codes or wildcards)
    scopes: Mapping[str, frozenset[str]] = field(default_factory=dict)
    perm_version: int = 0
    session_key: str = ""

    def has(self, permission: str) -> bool:
        return any(pattern_matches(granted, permission) for granted in self.permissions)

    def covers(self, pattern: str) -> bool:
        """Holds everything `pattern` grants (privilege escalation check)."""
        return any_covers(self.permissions, pattern)

    def covers_all(self, patterns: Iterable[str]) -> bool:
        return all(self.covers(p) for p in patterns)

    def in_scope(self, scope_type: str, value: str | None) -> bool:
        """Row-level check. No scope of that type means nothing is visible."""
        values = self.scopes.get(scope_type, frozenset())
        return SCOPE_ALL in values or (value is not None and value in values)

    def covers_scope(self, scope_type: str, value: str) -> bool:
        """May hand out this scope to another admin."""
        values = self.scopes.get(scope_type, frozenset())
        return SCOPE_ALL in values or value in values

    def regions(self) -> list[str]:
        """The `regions` claim of the service JWT (section 8)."""
        values = self.scopes.get("region", frozenset())
        return [SCOPE_ALL] if SCOPE_ALL in values else sorted(values)

    def _cache_dump(self) -> str:
        return json.dumps(
            {
                "username": self.username,
                "full_name": self.full_name,
                "permissions": sorted(self.permissions),
                "scopes": {k: sorted(v) for k, v in self.scopes.items()},
            }
        )


class PrincipalLoader:
    def __init__(self, db: async_sessionmaker[AsyncSession], redis: Redis, *, prefix: str) -> None:
        self._db = db
        self._redis = redis
        self._prefix = prefix
        self._set_max = redis.register_script(_SET_MAX_LUA)

    def _version_key(self, user_id: uuid.UUID) -> str:
        return f"{self._prefix}perm_version:{user_id}"

    def _principal_key(self, user_id: uuid.UUID, version: int) -> str:
        return f"{self._prefix}principal:{user_id}:{version}"

    async def load(self, session: SessionData) -> Principal | None:
        """None if the admin no longer exists or is blocked."""
        version_raw = await self._redis.get(self._version_key(session.user_id))
        if version_raw is not None:
            version = int(version_raw)
            cached = await self._redis.get(self._principal_key(session.user_id, version))
            if cached is not None:
                data = json.loads(cached)
                return Principal(
                    user_id=session.user_id,
                    username=data["username"],
                    full_name=data["full_name"],
                    permissions=frozenset(data["permissions"]),
                    scopes={k: frozenset(v) for k, v in data["scopes"].items()},
                    perm_version=version,
                    session_key=session.key,
                )
        principal = await self._load_from_db(session.user_id)
        if principal is None:
            return None
        await self._redis.set(
            self._principal_key(session.user_id, principal.perm_version),
            principal._cache_dump(),
            ex=PRINCIPAL_TTL_S,
        )
        await self._publish_one(session.user_id, principal.perm_version)
        return replace(principal, session_key=session.key)

    async def _publish_one(self, user_id: uuid.UUID, version: int) -> None:
        await self._set_max(keys=[self._version_key(user_id)], args=[version, PERM_VERSION_TTL_S])

    async def _load_from_db(self, user_id: uuid.UUID) -> Principal | None:
        async with self._db() as db:
            user = await db.get(AdminUser, user_id)
            if user is None or not user.is_active:
                return None
            permissions = await db.scalars(
                select(RolePermission.permission)
                .join(UserRole, UserRole.role_id == RolePermission.role_id)
                .where(UserRole.user_id == user_id)
            )
            scope_rows = await db.execute(
                select(UserScope.scope_type, UserScope.scope_value).where(
                    UserScope.user_id == user_id
                )
            )
            scopes: dict[str, set[str]] = {}
            for scope_type, scope_value in scope_rows.all():
                scopes.setdefault(scope_type, set()).add(scope_value)
            return Principal(
                user_id=user.id,
                username=user.username,
                full_name=user.full_name,
                permissions=frozenset(permissions.all()),
                scopes={k: frozenset(v) for k, v in scopes.items()},
                perm_version=user.perm_version,
            )

    async def bump(
        self, db: AsyncSession, user_ids: Iterable[uuid.UUID]
    ) -> list[tuple[uuid.UUID, int]]:
        """Increments `perm_version` of `user_ids` inside the caller's transaction.
        Pass the result to `publish` after the commit."""
        ids = list(set(user_ids))
        if not ids:
            return []
        rows = await db.execute(
            update(AdminUser)
            .where(AdminUser.id.in_(ids))
            .values(perm_version=AdminUser.perm_version + 1)
            .returning(AdminUser.id, AdminUser.perm_version)
        )
        return [(user_id, version) for user_id, version in rows.all()]

    async def publish(self, versions: Iterable[tuple[uuid.UUID, int]]) -> None:
        for user_id, version in versions:
            await self._publish_one(user_id, version)
