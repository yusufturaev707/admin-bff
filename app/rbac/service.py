"""Admins and roles (section 7).

Rules against privilege escalation, enforced for every change:

* an admin can only grant permissions (roles) it holds itself;
* an admin cannot manage an admin who holds more than it does;
* an admin cannot change its own roles, sign-in methods or status;
* the system role `superadmin` cannot be edited or deleted, and the last active
  superadmin cannot be demoted or blocked. Those changes take an advisory lock
  first, so two superadmins cannot block each other at the same moment.

A role change takes effect on the next request (perm_version, see principal.py);
an admin whose roles change, who is blocked or whose password is reset also
loses every session (section 6).
"""

import secrets
import uuid
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from typing import Any

from sqlalchemy import delete, func, or_, select, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.audit.sink import AuditEvent, AuditOutcome, AuditSink
from app.auth.crypto import hmac_sha256_hex
from app.auth.lockout import LoginLimiter
from app.auth.models import AuthMethod, User, normalize_username
from app.auth.passwords import PasswordPolicyError, PasswordService, check_password_policy
from app.auth.service import RequestMeta
from app.auth.sessions import SessionStore
from app.core.errors import AppError, ErrorCode, field_error
from app.core.pagination import PageParams
from app.core.pii import mask_pinfl
from app.directory.models import Organization, Region
from app.rbac.models import SUPERADMIN_LOCK_KEY, SUPERADMIN_ROLE, Role, RolePermission, UserRole
from app.rbac.permissions import is_valid_pattern
from app.rbac.principal import Principal, PrincipalLoader
from app.rbac.registry import PermissionRegistry
from app.settings import Settings

FORBIDDEN_SELF = "O'z rolingiz, kirish usullaringiz va holatingizni o'zgartira olmaysiz"
FORBIDDEN_HIGHER = "Sizdan yuqori huquqli adminni boshqara olmaysiz"
FORBIDDEN_GRANT = "O'zingizda yo'q huquqni bera olmaysiz"
LAST_SUPERADMIN = "Oxirgi faol superadminni o'chirib yoki bloklab bo'lmaydi"

_SUPERADMIN_LOCK = text("SELECT pg_advisory_xact_lock(:key)")

_SORT_COLUMNS = {
    "username": User.username,
    "created_at": User.created_at,
    "last_login_at": User.last_login_at,
}


@dataclass(frozen=True, slots=True)
class UserView:
    user: User
    roles: list[Role]


@dataclass(frozen=True, slots=True)
class RoleView:
    role: Role
    permissions: list[str]
    user_count: int


@dataclass(frozen=True, slots=True)
class UserFilters:
    q: str | None = None
    is_active: bool | None = None
    role_id: uuid.UUID | None = None
    org_id: int | None = None
    region_id: int | None = None
    sort: str = "username"


class AdminService:
    def __init__(
        self,
        *,
        settings: Settings,
        db: async_sessionmaker[AsyncSession],
        registry: PermissionRegistry,
        loader: PrincipalLoader,
        sessions: SessionStore,
        limiter: LoginLimiter,
        passwords: PasswordService,
        audit: AuditSink,
    ) -> None:
        self._settings = settings
        self._db = db
        self.registry = registry
        self._loader = loader
        self._sessions = sessions
        self._limiter = limiter
        self._passwords = passwords
        self._audit_sink = audit

    # --- helpers -------------------------------------------------------------

    async def _audit(
        self,
        action: str,
        actor: Principal,
        meta: RequestMeta,
        *,
        resource: str,
        resource_id: uuid.UUID,
        before: object = None,
        after: object = None,
        **details: Any,
    ) -> None:
        await self._audit_sink.write(
            AuditEvent(
                action=action,
                outcome=AuditOutcome.SUCCESS,
                actor_id=actor.user_id,
                actor_username=actor.username,
                actor_ip=meta.ip,
                user_agent=meta.user_agent,
                session_hash=actor.session_key,
                request_id=meta.request_id,
                system_id="admin",
                resource=resource,
                resource_id=str(resource_id),
                before=before,
                after=after,
                details=details,
            )
        )

    def _new_password(self, username: str) -> str:
        """A random temporary password that satisfies the policy."""
        while True:
            candidate = secrets.token_urlsafe(12)
            try:
                check_password_policy(candidate, username=username)
            except PasswordPolicyError:
                continue
            return candidate

    def _imie(self, imie: str) -> tuple[str, str]:
        """The IMIE (PINFL) as stored: its HMAC for the OneID lookup, masked for display."""
        return hmac_sha256_hex(self._settings.pinfl_key(), imie), mask_pinfl(imie)

    @staticmethod
    async def _placement(
        db: AsyncSession,
        org_id: int | None,
        region_id: int | None,
        *,
        current: tuple[int | None, int | None] = (None, None),
    ) -> tuple[int | None, int | None]:
        """The user's organization and region, checked. Without a region the
        organization's region is taken; with both they must agree. A newly
        set organization or region must exist and be active (`status`); one the
        user already has is kept even if it was deactivated since."""
        if org_id is not None:
            org = await db.get(Organization, org_id)
            if org is None or (org_id != current[0] and not org.status):
                raise field_error(
                    ("body", "org_id"), "unknown_organization", "Bunday faol tashkilot topilmadi"
                )
            if region_id is None:
                region_id = org.region_id
            elif region_id != org.region_id:
                raise field_error(
                    ("body", "region_id"),
                    "region_mismatch",
                    "Hudud tashkilotning hududi bilan bir xil bo'lishi kerak",
                )
        if region_id is not None and region_id != current[1]:
            region = await db.get(Region, region_id)
            if region is None or not region.status:
                raise field_error(
                    ("body", "region_id"), "unknown_region", "Bunday faol hudud topilmadi"
                )
        return org_id, region_id

    async def _user_or_404(self, db: AsyncSession, user_id: uuid.UUID) -> User:
        user = await db.get(User, user_id)
        if user is None:
            raise AppError(ErrorCode.NOT_FOUND)
        return user

    async def _roles_or_422(self, db: AsyncSession, role_ids: Sequence[uuid.UUID]) -> list[Role]:
        wanted = set(role_ids)
        roles = list((await db.scalars(select(Role).where(Role.id.in_(wanted)))).all())
        if len(roles) != len(wanted):
            raise field_error(("body", "role_ids"), "unknown_role", "Bunday rol topilmadi")
        return roles

    async def _role_patterns(self, db: AsyncSession, role_ids: Iterable[uuid.UUID]) -> set[str]:
        ids = list(role_ids)
        if not ids:
            return set()
        rows = await db.scalars(
            select(RolePermission.permission).where(RolePermission.role_id.in_(ids))
        )
        return set(rows.all())

    async def _user_patterns(self, db: AsyncSession, user_id: uuid.UUID) -> set[str]:
        rows = await db.scalars(
            select(RolePermission.permission)
            .join(UserRole, UserRole.role_id == RolePermission.role_id)
            .where(UserRole.user_id == user_id)
        )
        return set(rows.all())

    @staticmethod
    async def _lock_superadmins(db: AsyncSession) -> None:
        """Taken first in a transaction that may leave fewer active superadmins,
        and held until it commits. Otherwise two such changes running at once
        would each still see the other superadmin and both go through."""
        await db.execute(_SUPERADMIN_LOCK, {"key": SUPERADMIN_LOCK_KEY})

    async def _active_superadmins(self, db: AsyncSession) -> set[uuid.UUID]:
        rows = await db.scalars(
            select(UserRole.user_id)
            .join(Role, Role.id == UserRole.role_id)
            .join(User, User.id == UserRole.user_id)
            .where(Role.is_system, Role.name == SUPERADMIN_ROLE, User.is_active)
        )
        return set(rows.all())

    def _checked_patterns(self, patterns: Iterable[str]) -> list[str]:
        """Valid format and matching at least one declared permission (catches typos)."""
        result = sorted(set(patterns))
        unknown = [p for p in result if not is_valid_pattern(p) or not self.registry.matching(p)]
        if unknown:
            raise AppError(
                ErrorCode.VALIDATION_ERROR,
                "Noma'lum permission",
                details={
                    "fields": [
                        {"loc": ["body", "permissions"], "type": "unknown_permission", "msg": p}
                        for p in unknown
                    ]
                },
            )
        return result

    @staticmethod
    def _ensure_name_free(name: str) -> None:
        if name.strip().lower() == SUPERADMIN_ROLE:
            raise AppError(ErrorCode.CONFLICT, "Bu nom tizim roli uchun band")

    @staticmethod
    def _ensure_grants(actor: Principal, patterns: Iterable[str]) -> None:
        if not actor.covers_all(patterns):
            raise AppError(ErrorCode.FORBIDDEN, FORBIDDEN_GRANT)

    async def _ensure_can_manage(self, db: AsyncSession, actor: Principal, target: User) -> None:
        if target.id == actor.user_id:
            raise AppError(ErrorCode.FORBIDDEN, FORBIDDEN_SELF)
        if not actor.covers_all(await self._user_patterns(db, target.id)):
            raise AppError(ErrorCode.FORBIDDEN, FORBIDDEN_HIGHER)

    async def _views(self, db: AsyncSession, users: Sequence[User]) -> list[UserView]:
        ids = [u.id for u in users]
        roles: dict[uuid.UUID, list[Role]] = {i: [] for i in ids}
        if ids:
            role_rows = await db.execute(
                select(UserRole.user_id, Role)
                .join(Role, Role.id == UserRole.role_id)
                .where(UserRole.user_id.in_(ids))
                .order_by(Role.name)
            )
            for user_id, role in role_rows.all():
                roles[user_id].append(role)
        return [UserView(u, roles[u.id]) for u in users]

    async def _view(self, user_id: uuid.UUID) -> UserView:
        async with self._db() as db:
            return (await self._views(db, [await self._user_or_404(db, user_id)]))[0]

    async def _after_change(
        self, versions: list[tuple[uuid.UUID, int]], *, revoke: Iterable[uuid.UUID] = ()
    ) -> None:
        await self._loader.publish(versions)
        for user_id in set(revoke):
            await self._sessions.delete_all_for_user(user_id)

    # --- admins --------------------------------------------------------------

    async def list_users(
        self, params: PageParams, filters: UserFilters
    ) -> tuple[list[UserView], int]:
        query = select(User)
        if filters.q:
            query = query.where(
                or_(
                    User.username.contains(filters.q.lower(), autoescape=True),
                    User.full_name.icontains(filters.q, autoescape=True),
                )
            )
        if filters.is_active is not None:
            query = query.where(User.is_active == filters.is_active)
        if filters.role_id is not None:
            query = query.where(
                User.id.in_(select(UserRole.user_id).where(UserRole.role_id == filters.role_id))
            )
        if filters.org_id is not None:
            query = query.where(User.org_id == filters.org_id)
        if filters.region_id is not None:
            query = query.where(User.region_id == filters.region_id)
        column = _SORT_COLUMNS[filters.sort.lstrip("-")]
        order = column.desc().nulls_last() if filters.sort.startswith("-") else column.asc()
        async with self._db() as db:
            total = await db.scalar(select(func.count()).select_from(query.subquery()))
            users = await db.scalars(
                query.order_by(order, User.id).offset(params.offset).limit(params.page_size)
            )
            return await self._views(db, users.all()), int(total or 0)

    async def get_user(self, user_id: uuid.UUID) -> UserView:
        return await self._view(user_id)

    async def create_user(
        self,
        actor: Principal,
        meta: RequestMeta,
        *,
        username: str,
        full_name: str | None,
        methods: Sequence[AuthMethod],
        imie: str | None,
        role_ids: Sequence[uuid.UUID],
        org_id: int | None = None,
        region_id: int | None = None,
    ) -> tuple[UserView, str | None]:
        normalized = normalize_username(username)
        if normalized is None:
            raise field_error(
                ("body", "username"),
                "invalid_username",
                "3-64 belgi: kichik lotin harflari, raqamlar, '.', '_' yoki '-'",
            )
        method_values = sorted({m.value for m in methods})
        if AuthMethod.ONEID.value in method_values and imie is None:
            raise field_error(("body", "imie"), "imie_required", "OneID uchun IMIE (PINFL) kerak")
        password = (
            self._new_password(normalized) if AuthMethod.PASSWORD.value in method_values else None
        )
        user = User(
            id=uuid.uuid4(),
            username=normalized,
            full_name=full_name,
            auth_methods=method_values,
            password_hash=await self._passwords.hash(password) if password else None,
            must_change_password=password is not None,
        )
        if imie is not None:
            user.oneid_imie_hash, user.imie_masked = self._imie(imie)
        try:
            async with self._db() as db, db.begin():
                user.org_id, user.region_id = await self._placement(db, org_id, region_id)
                roles = await self._roles_or_422(db, role_ids)
                self._ensure_grants(actor, await self._role_patterns(db, (r.id for r in roles)))
                db.add(user)
                await db.flush()
                db.add_all(UserRole(user_id=user.id, role_id=r.id) for r in roles)
        except IntegrityError as exc:
            raise AppError(
                ErrorCode.CONFLICT, "Bunday login yoki IMIE (PINFL) bilan admin allaqachon bor"
            ) from exc
        await self._audit(
            "admin.user.create",
            actor,
            meta,
            resource="users",
            resource_id=user.id,
            after={
                "username": normalized,
                "full_name": full_name,
                "auth_methods": method_values,
                "roles": sorted(r.name for r in roles),
                "imie_masked": user.imie_masked,
                "org_id": user.org_id,
                "region_id": user.region_id,
            },
        )
        return await self._view(user.id), password

    async def update_user(
        self, actor: Principal, meta: RequestMeta, user_id: uuid.UUID, changes: dict[str, Any]
    ) -> tuple[UserView, str | None]:
        """`changes` holds only the fields the client sent."""
        password: str | None = None
        revoke = False
        try:
            async with self._db() as db, db.begin():
                if changes.get("is_active") is False:
                    await self._lock_superadmins(db)
                user = await self._user_or_404(db, user_id)
                sensitive = set(changes) - {"full_name"}
                if user.id == actor.user_id and sensitive:
                    raise AppError(ErrorCode.FORBIDDEN, FORBIDDEN_SELF)
                if user.id != actor.user_id:
                    await self._ensure_can_manage(db, actor, user)
                before = {
                    "full_name": user.full_name,
                    "is_active": user.is_active,
                    "auth_methods": list(user.auth_methods),
                    "imie_masked": user.imie_masked,
                    "org_id": user.org_id,
                    "region_id": user.region_id,
                }
                if "full_name" in changes:
                    user.full_name = changes["full_name"]
                if "org_id" in changes or "region_id" in changes:
                    org_id = changes.get("org_id", user.org_id)
                    if "region_id" in changes:
                        region_id = changes["region_id"]
                    else:
                        # A new organization brings its region; none keeps the region.
                        region_id = None if org_id is not None else user.region_id
                    user.org_id, user.region_id = await self._placement(
                        db, org_id, region_id, current=(user.org_id, user.region_id)
                    )
                if "imie" in changes:
                    if changes["imie"] is None:
                        user.oneid_imie_hash = user.imie_masked = None
                    else:
                        user.oneid_imie_hash, user.imie_masked = self._imie(changes["imie"])
                    revoke = True
                if changes.get("auth_methods") is not None:
                    methods = sorted({AuthMethod(m).value for m in changes["auth_methods"]})
                    if AuthMethod.PASSWORD.value in methods and user.password_hash is None:
                        password = self._new_password(user.username)
                        user.password_hash = await self._passwords.hash(password)
                        user.must_change_password = True
                    user.auth_methods = methods
                    revoke = True
                if AuthMethod.ONEID.value in user.auth_methods and user.oneid_imie_hash is None:
                    raise field_error(
                        ("body", "imie"), "imie_required", "OneID uchun IMIE (PINFL) kerak"
                    )
                if changes.get("is_active") is not None and changes["is_active"] != user.is_active:
                    if not changes["is_active"]:
                        superadmins = await self._active_superadmins(db)
                        if superadmins == {user.id}:
                            raise AppError(ErrorCode.CONFLICT, LAST_SUPERADMIN)
                    user.is_active = changes["is_active"]
                    revoke = True
                versions = await self._loader.bump(db, [user.id]) if revoke else []
        except IntegrityError as exc:
            raise AppError(
                ErrorCode.CONFLICT, "Bu IMIE (PINFL) boshqa adminga biriktirilgan"
            ) from exc
        await self._after_change(versions, revoke=[user_id] if revoke else [])
        view = await self._view(user_id)
        await self._audit(
            "admin.user.update",
            actor,
            meta,
            resource="users",
            resource_id=user_id,
            before=before,
            after={
                "full_name": view.user.full_name,
                "is_active": view.user.is_active,
                "auth_methods": list(view.user.auth_methods),
                "imie_masked": view.user.imie_masked,
                "org_id": view.user.org_id,
                "region_id": view.user.region_id,
            },
        )
        return view, password

    async def set_roles(
        self, actor: Principal, meta: RequestMeta, user_id: uuid.UUID, role_ids: Sequence[uuid.UUID]
    ) -> UserView:
        async with self._db() as db, db.begin():
            await self._lock_superadmins(db)
            user = await self._user_or_404(db, user_id)
            await self._ensure_can_manage(db, actor, user)
            roles = await self._roles_or_422(db, role_ids)
            self._ensure_grants(actor, await self._role_patterns(db, (r.id for r in roles)))
            is_super = any(r.is_system and r.name == SUPERADMIN_ROLE for r in roles)
            if not is_super and (await self._active_superadmins(db)) == {user.id}:
                raise AppError(ErrorCode.CONFLICT, LAST_SUPERADMIN)
            before = sorted(
                (
                    await db.scalars(
                        select(Role.name)
                        .join(UserRole, UserRole.role_id == Role.id)
                        .where(UserRole.user_id == user.id)
                    )
                ).all()
            )
            await db.execute(delete(UserRole).where(UserRole.user_id == user.id))
            db.add_all(UserRole(user_id=user.id, role_id=r.id) for r in roles)
            versions = await self._loader.bump(db, [user.id])
        # Section 6: a role change ends all sessions of that admin.
        await self._after_change(versions, revoke=[user_id])
        await self._audit(
            "admin.user.roles",
            actor,
            meta,
            resource="users",
            resource_id=user_id,
            before=before,
            after=sorted(r.name for r in roles),
        )
        return await self._view(user_id)

    async def reset_password(self, actor: Principal, meta: RequestMeta, user_id: uuid.UUID) -> str:
        async with self._db() as db, db.begin():
            user = await self._user_or_404(db, user_id)
            await self._ensure_can_manage(db, actor, user)
            if not user.allows(AuthMethod.PASSWORD):
                raise AppError(ErrorCode.CONFLICT, "Bu admin parol bilan kirmaydi")
            password = self._new_password(user.username)
            user.password_hash = await self._passwords.hash(password)
            user.must_change_password = True
        await self._after_change([], revoke=[user_id])
        await self._audit(
            "admin.user.password_reset", actor, meta, resource="users", resource_id=user_id
        )
        return password

    async def unlock(self, actor: Principal, meta: RequestMeta, user_id: uuid.UUID) -> None:
        async with self._db() as db:
            user = await self._user_or_404(db, user_id)
        removed = await self._limiter.unlock(username=user.username)
        await self._audit(
            "auth.unlock",
            actor,
            meta,
            resource="users",
            resource_id=user_id,
            removed_keys=removed,
        )

    # --- roles ---------------------------------------------------------------

    async def _role_views(self, db: AsyncSession, roles: Sequence[Role]) -> list[RoleView]:
        ids = [r.id for r in roles]
        permissions: dict[uuid.UUID, list[str]] = {i: [] for i in ids}
        counts: dict[uuid.UUID, int] = dict.fromkeys(ids, 0)
        if ids:
            for role_id, permission in (
                await db.execute(
                    select(RolePermission.role_id, RolePermission.permission)
                    .where(RolePermission.role_id.in_(ids))
                    .order_by(RolePermission.permission)
                )
            ).all():
                permissions[role_id].append(permission)
            for role_id, count in (
                await db.execute(
                    select(UserRole.role_id, func.count())
                    .where(UserRole.role_id.in_(ids))
                    .group_by(UserRole.role_id)
                )
            ).all():
                counts[role_id] = int(count)
        return [RoleView(r, permissions[r.id], counts[r.id]) for r in roles]

    async def _role_or_404(self, db: AsyncSession, role_id: uuid.UUID) -> Role:
        role = await db.get(Role, role_id)
        if role is None:
            raise AppError(ErrorCode.NOT_FOUND)
        return role

    async def list_roles(self) -> list[RoleView]:
        async with self._db() as db:
            roles = await db.scalars(select(Role).order_by(Role.name))
            return await self._role_views(db, roles.all())

    async def get_role(self, role_id: uuid.UUID) -> RoleView:
        async with self._db() as db:
            return (await self._role_views(db, [await self._role_or_404(db, role_id)]))[0]

    async def create_role(
        self,
        actor: Principal,
        meta: RequestMeta,
        *,
        name: str,
        description: str,
        permissions: Sequence[str],
    ) -> RoleView:
        self._ensure_name_free(name)
        patterns = self._checked_patterns(permissions)
        self._ensure_grants(actor, patterns)
        role = Role(id=uuid.uuid4(), name=name.strip(), description=description, is_system=False)
        try:
            async with self._db() as db, db.begin():
                db.add(role)
                await db.flush()
                db.add_all(RolePermission(role_id=role.id, permission=p) for p in patterns)
        except IntegrityError as exc:
            raise AppError(ErrorCode.CONFLICT, "Bunday nomli rol allaqachon bor") from exc
        await self._audit(
            "admin.role.create",
            actor,
            meta,
            resource="roles",
            resource_id=role.id,
            after={"name": role.name, "description": description, "permissions": patterns},
        )
        return await self.get_role(role.id)

    async def update_role(
        self,
        actor: Principal,
        meta: RequestMeta,
        role_id: uuid.UUID,
        *,
        name: str | None,
        description: str | None,
        permissions: Sequence[str] | None,
    ) -> RoleView:
        if name is not None:
            self._ensure_name_free(name)
        patterns = self._checked_patterns(permissions) if permissions is not None else None
        try:
            async with self._db() as db, db.begin():
                role = await self._role_or_404(db, role_id)
                if role.is_system:
                    raise AppError(ErrorCode.CONFLICT, "Tizim rolini o'zgartirib bo'lmaydi")
                members = set(
                    (
                        await db.scalars(
                            select(UserRole.user_id).where(UserRole.role_id == role.id)
                        )
                    ).all()
                )
                if actor.user_id in members:
                    raise AppError(ErrorCode.FORBIDDEN, FORBIDDEN_SELF)
                current = sorted(await self._role_patterns(db, [role.id]))
                self._ensure_grants(actor, current)  # cannot edit a stronger role
                before = {
                    "name": role.name,
                    "description": role.description,
                    "permissions": current,
                }
                if name is not None:
                    role.name = name.strip()
                if description is not None:
                    role.description = description
                versions: list[tuple[uuid.UUID, int]] = []
                if patterns is not None:
                    self._ensure_grants(actor, patterns)
                    await db.execute(
                        delete(RolePermission).where(RolePermission.role_id == role.id)
                    )
                    db.add_all(RolePermission(role_id=role.id, permission=p) for p in patterns)
                    # Effective on the members' next request, sessions stay.
                    versions = await self._loader.bump(db, members)
        except IntegrityError as exc:
            raise AppError(ErrorCode.CONFLICT, "Bunday nomli rol allaqachon bor") from exc
        await self._after_change(versions)
        view = await self.get_role(role_id)
        await self._audit(
            "admin.role.update",
            actor,
            meta,
            resource="roles",
            resource_id=role_id,
            before=before,
            after={
                "name": view.role.name,
                "description": view.role.description,
                "permissions": view.permissions,
            },
        )
        return view

    async def delete_role(self, actor: Principal, meta: RequestMeta, role_id: uuid.UUID) -> None:
        async with self._db() as db, db.begin():
            role = await self._role_or_404(db, role_id)
            if role.is_system:
                raise AppError(ErrorCode.CONFLICT, "Tizim rolini o'chirib bo'lmaydi")
            assigned = await db.scalar(
                select(func.count()).select_from(UserRole).where(UserRole.role_id == role.id)
            )
            if assigned:
                raise AppError(
                    ErrorCode.CONFLICT,
                    "Rol adminlarga biriktirilgan: avval uni adminlardan olib tashlang",
                )
            permissions = sorted(await self._role_patterns(db, [role.id]))
            self._ensure_grants(actor, permissions)
            await db.delete(role)
        await self._audit(
            "admin.role.delete",
            actor,
            meta,
            resource="roles",
            resource_id=role_id,
            before={
                "name": role.name,
                "description": role.description,
                "permissions": permissions,
            },
        )
