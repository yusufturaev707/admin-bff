"""Admins, roles and scopes (section 7).

Rules against privilege escalation, enforced for every change:

* an admin can only grant permissions (roles) and scopes it holds itself;
* an admin cannot manage an admin who holds more than it does;
* an admin cannot change its own roles, scopes, sign-in methods or status;
* the system role `superadmin` cannot be edited or deleted, and the last active
  superadmin cannot be demoted or blocked.

A role change takes effect on the next request (perm_version, see principal.py);
an admin whose roles change, who is blocked or whose credentials are reset also
loses every session (section 6).
"""

import secrets
import uuid
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from typing import Any

from sqlalchemy import delete, func, or_, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.audit.sink import AuditEvent, AuditOutcome, AuditSink
from app.auth.crypto import hmac_sha256_hex
from app.auth.lockout import LoginLimiter
from app.auth.models import AdminUser, AuthMethod, RecoveryCode, normalize_username
from app.auth.passwords import PasswordPolicyError, PasswordService, check_password_policy
from app.auth.service import RequestMeta
from app.auth.sessions import SessionStore
from app.core.errors import AppError, ErrorCode, field_error
from app.core.pagination import PageParams
from app.core.pii import mask_pinfl
from app.rbac.models import SUPERADMIN_ROLE, Role, RolePermission, UserRole, UserScope
from app.rbac.permissions import is_valid_pattern
from app.rbac.principal import Principal, PrincipalLoader
from app.rbac.registry import PermissionRegistry
from app.settings import Settings

FORBIDDEN_SELF = (
    "O'z rolingiz, hududlaringiz, kirish usullaringiz va holatingizni o'zgartira olmaysiz"
)
FORBIDDEN_HIGHER = "Sizdan yuqori huquqli adminni boshqara olmaysiz"
FORBIDDEN_GRANT = "O'zingizda yo'q huquq yoki hududni bera olmaysiz"
LAST_SUPERADMIN = "Oxirgi faol superadminni o'chirib yoki bloklab bo'lmaydi"

_SORT_COLUMNS = {
    "username": AdminUser.username,
    "created_at": AdminUser.created_at,
    "last_login_at": AdminUser.last_login_at,
}


@dataclass(frozen=True, slots=True)
class UserView:
    user: AdminUser
    roles: list[Role]
    scopes: list[tuple[str, str]]


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
        self, action: str, actor: Principal, meta: RequestMeta, **details: Any
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

    def _pinfl(self, pinfl: str) -> tuple[str, str]:
        return hmac_sha256_hex(self._settings.pinfl_key(), pinfl), mask_pinfl(pinfl)

    async def _user_or_404(self, db: AsyncSession, user_id: uuid.UUID) -> AdminUser:
        user = await db.get(AdminUser, user_id)
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

    async def _user_scopes(self, db: AsyncSession, user_id: uuid.UUID) -> list[tuple[str, str]]:
        rows = await db.execute(
            select(UserScope.scope_type, UserScope.scope_value)
            .where(UserScope.user_id == user_id)
            .order_by(UserScope.scope_type, UserScope.scope_value)
        )
        return [(t, v) for t, v in rows.all()]

    async def _active_superadmins(self, db: AsyncSession) -> set[uuid.UUID]:
        rows = await db.scalars(
            select(UserRole.user_id)
            .join(Role, Role.id == UserRole.role_id)
            .join(AdminUser, AdminUser.id == UserRole.user_id)
            .where(Role.is_system, Role.name == SUPERADMIN_ROLE, AdminUser.is_active)
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

    @staticmethod
    def _ensure_scopes(actor: Principal, scopes: Iterable[tuple[str, str]]) -> None:
        if not all(actor.covers_scope(t, v) for t, v in scopes):
            raise AppError(ErrorCode.FORBIDDEN, FORBIDDEN_GRANT)

    async def _ensure_can_manage(
        self, db: AsyncSession, actor: Principal, target: AdminUser
    ) -> None:
        if target.id == actor.user_id:
            raise AppError(ErrorCode.FORBIDDEN, FORBIDDEN_SELF)
        if not actor.covers_all(await self._user_patterns(db, target.id)):
            raise AppError(ErrorCode.FORBIDDEN, FORBIDDEN_HIGHER)
        if not all(actor.covers_scope(t, v) for t, v in await self._user_scopes(db, target.id)):
            raise AppError(ErrorCode.FORBIDDEN, FORBIDDEN_HIGHER)

    async def _views(self, db: AsyncSession, users: Sequence[AdminUser]) -> list[UserView]:
        ids = [u.id for u in users]
        roles: dict[uuid.UUID, list[Role]] = {i: [] for i in ids}
        scopes: dict[uuid.UUID, list[tuple[str, str]]] = {i: [] for i in ids}
        if ids:
            role_rows = await db.execute(
                select(UserRole.user_id, Role)
                .join(Role, Role.id == UserRole.role_id)
                .where(UserRole.user_id.in_(ids))
                .order_by(Role.name)
            )
            for user_id, role in role_rows.all():
                roles[user_id].append(role)
            scope_rows = await db.execute(
                select(UserScope.user_id, UserScope.scope_type, UserScope.scope_value)
                .where(UserScope.user_id.in_(ids))
                .order_by(UserScope.scope_type, UserScope.scope_value)
            )
            for user_id, scope_type, scope_value in scope_rows.all():
                scopes[user_id].append((scope_type, scope_value))
        return [UserView(u, roles[u.id], scopes[u.id]) for u in users]

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
        query = select(AdminUser)
        if filters.q:
            query = query.where(
                or_(
                    AdminUser.username.contains(filters.q.lower(), autoescape=True),
                    AdminUser.full_name.icontains(filters.q, autoescape=True),
                )
            )
        if filters.is_active is not None:
            query = query.where(AdminUser.is_active == filters.is_active)
        if filters.role_id is not None:
            query = query.where(
                AdminUser.id.in_(
                    select(UserRole.user_id).where(UserRole.role_id == filters.role_id)
                )
            )
        column = _SORT_COLUMNS[filters.sort.lstrip("-")]
        order = column.desc().nulls_last() if filters.sort.startswith("-") else column.asc()
        async with self._db() as db:
            total = await db.scalar(select(func.count()).select_from(query.subquery()))
            users = await db.scalars(
                query.order_by(order, AdminUser.id).offset(params.offset).limit(params.page_size)
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
        pinfl: str | None,
        role_ids: Sequence[uuid.UUID],
        scopes: Sequence[tuple[str, str]],
    ) -> tuple[UserView, str | None]:
        normalized = normalize_username(username)
        if normalized is None:
            raise field_error(
                ("body", "username"),
                "invalid_username",
                "3-64 belgi: kichik lotin harflari, raqamlar, '.', '_' yoki '-'",
            )
        method_values = sorted({m.value for m in methods})
        if AuthMethod.ONEID.value in method_values and pinfl is None:
            raise field_error(("body", "pinfl"), "pinfl_required", "OneID uchun PINFL kerak")
        self._ensure_scopes(actor, scopes)
        password = (
            self._new_password(normalized) if AuthMethod.PASSWORD.value in method_values else None
        )
        user = AdminUser(
            id=uuid.uuid4(),
            username=normalized,
            full_name=full_name,
            auth_methods=method_values,
            password_hash=await self._passwords.hash(password) if password else None,
            must_change_password=password is not None,
        )
        if pinfl is not None:
            user.oneid_pinfl_hash, user.pinfl_masked = self._pinfl(pinfl)
        try:
            async with self._db() as db, db.begin():
                roles = await self._roles_or_422(db, role_ids)
                self._ensure_grants(actor, await self._role_patterns(db, (r.id for r in roles)))
                db.add(user)
                await db.flush()
                db.add_all(UserRole(user_id=user.id, role_id=r.id) for r in roles)
                db.add_all(
                    UserScope(user_id=user.id, scope_type=t, scope_value=v) for t, v in set(scopes)
                )
        except IntegrityError as exc:
            raise AppError(
                ErrorCode.CONFLICT, "Bunday login yoki PINFL bilan admin allaqachon bor"
            ) from exc
        await self._audit(
            "admin.user.create",
            actor,
            meta,
            user_id=str(user.id),
            username=normalized,
            auth_methods=method_values,
            roles=sorted(r.name for r in roles),
            scopes=sorted(f"{t}:{v}" for t, v in set(scopes)),
            pinfl_masked=user.pinfl_masked,
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
                    "pinfl_masked": user.pinfl_masked,
                }
                if "full_name" in changes:
                    user.full_name = changes["full_name"]
                if "pinfl" in changes:
                    if changes["pinfl"] is None:
                        user.oneid_pinfl_hash = user.pinfl_masked = None
                    else:
                        user.oneid_pinfl_hash, user.pinfl_masked = self._pinfl(changes["pinfl"])
                    revoke = True
                if changes.get("auth_methods") is not None:
                    methods = sorted({AuthMethod(m).value for m in changes["auth_methods"]})
                    if AuthMethod.PASSWORD.value in methods and user.password_hash is None:
                        password = self._new_password(user.username)
                        user.password_hash = await self._passwords.hash(password)
                        user.must_change_password = True
                    user.auth_methods = methods
                    revoke = True
                if AuthMethod.ONEID.value in user.auth_methods and user.oneid_pinfl_hash is None:
                    raise field_error(
                        ("body", "pinfl"), "pinfl_required", "OneID uchun PINFL kerak"
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
            raise AppError(ErrorCode.CONFLICT, "Bu PINFL boshqa adminga biriktirilgan") from exc
        await self._after_change(versions, revoke=[user_id] if revoke else [])
        view = await self._view(user_id)
        await self._audit(
            "admin.user.update",
            actor,
            meta,
            user_id=str(user_id),
            before=before,
            after={
                "full_name": view.user.full_name,
                "is_active": view.user.is_active,
                "auth_methods": list(view.user.auth_methods),
                "pinfl_masked": view.user.pinfl_masked,
            },
        )
        return view, password

    async def set_roles(
        self, actor: Principal, meta: RequestMeta, user_id: uuid.UUID, role_ids: Sequence[uuid.UUID]
    ) -> UserView:
        async with self._db() as db, db.begin():
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
            user_id=str(user_id),
            before=before,
            after=sorted(r.name for r in roles),
        )
        return await self._view(user_id)

    async def set_scopes(
        self,
        actor: Principal,
        meta: RequestMeta,
        user_id: uuid.UUID,
        scopes: Sequence[tuple[str, str]],
    ) -> UserView:
        wanted = sorted(set(scopes))
        self._ensure_scopes(actor, wanted)
        async with self._db() as db, db.begin():
            user = await self._user_or_404(db, user_id)
            await self._ensure_can_manage(db, actor, user)
            before = await self._user_scopes(db, user.id)
            await db.execute(delete(UserScope).where(UserScope.user_id == user.id))
            db.add_all(UserScope(user_id=user.id, scope_type=t, scope_value=v) for t, v in wanted)
            versions = await self._loader.bump(db, [user.id])
        await self._after_change(versions)
        await self._audit(
            "admin.user.scopes",
            actor,
            meta,
            user_id=str(user_id),
            before=[f"{t}:{v}" for t, v in before],
            after=[f"{t}:{v}" for t, v in wanted],
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
        await self._audit("admin.user.password_reset", actor, meta, user_id=str(user_id))
        return password

    async def reset_totp(self, actor: Principal, meta: RequestMeta, user_id: uuid.UUID) -> None:
        async with self._db() as db, db.begin():
            user = await self._user_or_404(db, user_id)
            await self._ensure_can_manage(db, actor, user)
            user.totp_secret_enc = None
            user.totp_confirmed_at = None
            user.totp_last_timecode = None
            await db.execute(delete(RecoveryCode).where(RecoveryCode.user_id == user.id))
        await self._after_change([], revoke=[user_id])
        await self._audit("admin.user.totp_reset", actor, meta, user_id=str(user_id))

    async def unlock(self, actor: Principal, meta: RequestMeta, user_id: uuid.UUID) -> None:
        async with self._db() as db:
            user = await self._user_or_404(db, user_id)
        removed = await self._limiter.unlock(username=user.username)
        await self._audit("auth.unlock", actor, meta, user_id=str(user_id), removed_keys=removed)

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
            role_id=str(role.id),
            name=role.name,
            permissions=patterns,
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
            role_id=str(role_id),
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
            role_id=str(role_id),
            name=role.name,
            permissions=permissions,
        )
