"""Regions and organizations: list, read and change them (owner's decision,
2026-11-24).

Every change is audited with its before/after state (section 9). A region or
an organization that something still refers to cannot be deleted: it is
deactivated (`status: false`) instead. A new organization, or one moved to
another region, must go to an active region.
"""

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any

from sqlalchemy import Select, func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.audit.sink import AuditEvent, AuditOutcome, AuditSink
from app.auth.models import User
from app.auth.service import RequestMeta
from app.core.errors import AppError, ErrorCode, field_error
from app.core.pagination import PageParams
from app.directory.models import Organization, Region
from app.rbac.principal import Principal

REGION_TAKEN = "Bunday nomli yoki dtm_id'li hudud allaqachon bor"
REGION_IN_USE = (
    "Hududga tashkilotlar yoki foydalanuvchilar biriktirilgan: uni o'chirish o'rniga nofaol qiling"
)
ORGANIZATION_TAKEN = "Bu hududda bunday nomli tashkilot allaqachon bor"
ORGANIZATION_IN_USE = (
    "Tashkilotga foydalanuvchilar biriktirilgan: uni o'chirish o'rniga nofaol qiling"
)


@dataclass(frozen=True, slots=True)
class DirectoryFilters:
    q: str | None = None
    status: bool | None = None
    region_id: int | None = None  # organizations only


def _region_state(region: Region) -> dict[str, Any]:
    return {
        "name": region.name,
        "dtm_id": region.dtm_id,
        "p_code": region.p_code,
        "status": region.status,
    }


def _organization_state(org: Organization) -> dict[str, Any]:
    return {"name": org.name, "region_id": org.region_id, "status": org.status}


def _not_null(changes: dict[str, Any], *fields: str) -> None:
    for name in fields:
        if name in changes and changes[name] is None:
            raise field_error(("body", name), "null_not_allowed", "Bo'sh qoldirib bo'lmaydi")


class DirectoryService:
    def __init__(self, db: async_sessionmaker[AsyncSession], audit: AuditSink) -> None:
        self._db = db
        self._audit_sink = audit

    async def _audit(
        self,
        action: str,
        actor: Principal,
        meta: RequestMeta,
        *,
        resource: str,
        resource_id: int,
        before: object = None,
        after: object = None,
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
            )
        )

    @staticmethod
    async def _page[T](
        db: AsyncSession, query: Select[T], order: Sequence[Any], params: PageParams
    ) -> tuple[list[T], int]:
        total = await db.scalar(select(func.count()).select_from(query.subquery()))
        rows = await db.scalars(
            query.order_by(*order).offset(params.offset).limit(params.page_size)
        )
        return list(rows.all()), int(total or 0)

    @staticmethod
    async def _region_or_404(db: AsyncSession, region_id: int) -> Region:
        region = await db.get(Region, region_id)
        if region is None:
            raise AppError(ErrorCode.NOT_FOUND)
        return region

    @staticmethod
    async def _organization_or_404(db: AsyncSession, org_id: int) -> Organization:
        org = await db.get(Organization, org_id)
        if org is None:
            raise AppError(ErrorCode.NOT_FOUND)
        return org

    @staticmethod
    async def _active_region_or_422(db: AsyncSession, region_id: int) -> None:
        region = await db.get(Region, region_id)
        if region is None or not region.status:
            raise field_error(
                ("body", "region_id"), "unknown_region", "Bunday faol hudud topilmadi"
            )

    # --- regions ---------------------------------------------------------------

    async def list_regions(
        self, params: PageParams, filters: DirectoryFilters
    ) -> tuple[list[Region], int]:
        query = select(Region)
        if filters.q:
            query = query.where(Region.name.icontains(filters.q, autoescape=True))
        if filters.status is not None:
            query = query.where(Region.status == filters.status)
        async with self._db() as db:
            return await self._page(db, query, (Region.name, Region.id), params)

    async def get_region(self, region_id: int) -> Region:
        async with self._db() as db:
            return await self._region_or_404(db, region_id)

    async def create_region(
        self,
        actor: Principal,
        meta: RequestMeta,
        *,
        name: str,
        dtm_id: int | None,
        p_code: str | None,
        status: bool,
    ) -> Region:
        region = Region(name=name.strip(), dtm_id=dtm_id, p_code=p_code, status=status)
        try:
            async with self._db() as db, db.begin():
                db.add(region)
                await db.flush()
                await db.refresh(region)
        except IntegrityError as exc:
            raise AppError(ErrorCode.CONFLICT, REGION_TAKEN) from exc
        await self._audit(
            "admin.region.create",
            actor,
            meta,
            resource="regions",
            resource_id=region.id,
            after=_region_state(region),
        )
        return region

    async def update_region(
        self, actor: Principal, meta: RequestMeta, region_id: int, changes: dict[str, Any]
    ) -> Region:
        """`changes` holds only the fields the client sent."""
        _not_null(changes, "name", "status")
        try:
            async with self._db() as db, db.begin():
                region = await self._region_or_404(db, region_id)
                before = _region_state(region)
                if "name" in changes:
                    region.name = changes["name"].strip()
                for field in ("dtm_id", "p_code", "status"):
                    if field in changes:
                        setattr(region, field, changes[field])
                await db.flush()
                await db.refresh(region)
        except IntegrityError as exc:
            raise AppError(ErrorCode.CONFLICT, REGION_TAKEN) from exc
        await self._audit(
            "admin.region.update",
            actor,
            meta,
            resource="regions",
            resource_id=region_id,
            before=before,
            after=_region_state(region),
        )
        return region

    async def delete_region(self, actor: Principal, meta: RequestMeta, region_id: int) -> None:
        try:
            async with self._db() as db, db.begin():
                region = await self._region_or_404(db, region_id)
                used = await db.scalar(
                    select(func.count())
                    .select_from(Organization)
                    .where(Organization.region_id == region_id)
                ) or await db.scalar(
                    select(func.count()).select_from(User).where(User.region_id == region_id)
                )
                if used:
                    raise AppError(ErrorCode.CONFLICT, REGION_IN_USE)
                before = _region_state(region)
                await db.delete(region)
        except IntegrityError as exc:  # referred to in the meantime (RESTRICT)
            raise AppError(ErrorCode.CONFLICT, REGION_IN_USE) from exc
        await self._audit(
            "admin.region.delete",
            actor,
            meta,
            resource="regions",
            resource_id=region_id,
            before=before,
        )

    # --- organizations ---------------------------------------------------------

    async def list_organizations(
        self, params: PageParams, filters: DirectoryFilters
    ) -> tuple[list[Organization], int]:
        query = select(Organization)
        if filters.q:
            query = query.where(Organization.name.icontains(filters.q, autoescape=True))
        if filters.status is not None:
            query = query.where(Organization.status == filters.status)
        if filters.region_id is not None:
            query = query.where(Organization.region_id == filters.region_id)
        async with self._db() as db:
            return await self._page(db, query, (Organization.name, Organization.id), params)

    async def get_organization(self, org_id: int) -> Organization:
        async with self._db() as db:
            return await self._organization_or_404(db, org_id)

    async def create_organization(
        self, actor: Principal, meta: RequestMeta, *, name: str, region_id: int, status: bool
    ) -> Organization:
        org = Organization(name=name.strip(), region_id=region_id, status=status)
        try:
            async with self._db() as db, db.begin():
                await self._active_region_or_422(db, region_id)
                db.add(org)
                await db.flush()
                await db.refresh(org)
        except IntegrityError as exc:
            raise AppError(ErrorCode.CONFLICT, ORGANIZATION_TAKEN) from exc
        await self._audit(
            "admin.organization.create",
            actor,
            meta,
            resource="organizations",
            resource_id=org.id,
            after=_organization_state(org),
        )
        return org

    async def update_organization(
        self, actor: Principal, meta: RequestMeta, org_id: int, changes: dict[str, Any]
    ) -> Organization:
        """`changes` holds only the fields the client sent. Moving an
        organization does not move its users: their region stays as it was."""
        _not_null(changes, "name", "region_id", "status")
        try:
            async with self._db() as db, db.begin():
                org = await self._organization_or_404(db, org_id)
                before = _organization_state(org)
                if "region_id" in changes and changes["region_id"] != org.region_id:
                    await self._active_region_or_422(db, changes["region_id"])
                    org.region_id = changes["region_id"]
                if "name" in changes:
                    org.name = changes["name"].strip()
                if "status" in changes:
                    org.status = changes["status"]
                await db.flush()
                await db.refresh(org)
        except IntegrityError as exc:
            raise AppError(ErrorCode.CONFLICT, ORGANIZATION_TAKEN) from exc
        await self._audit(
            "admin.organization.update",
            actor,
            meta,
            resource="organizations",
            resource_id=org_id,
            before=before,
            after=_organization_state(org),
        )
        return org

    async def delete_organization(self, actor: Principal, meta: RequestMeta, org_id: int) -> None:
        try:
            async with self._db() as db, db.begin():
                org = await self._organization_or_404(db, org_id)
                used = await db.scalar(
                    select(func.count()).select_from(User).where(User.org_id == org_id)
                )
                if used:
                    raise AppError(ErrorCode.CONFLICT, ORGANIZATION_IN_USE)
                before = _organization_state(org)
                await db.delete(org)
        except IntegrityError as exc:  # referred to in the meantime (RESTRICT)
            raise AppError(ErrorCode.CONFLICT, ORGANIZATION_IN_USE) from exc
        await self._audit(
            "admin.organization.delete",
            actor,
            meta,
            resource="organizations",
            resource_id=org_id,
            before=before,
        )
