"""/api/v1/admin/regions and /api/v1/admin/organizations: reference data
(owner's decision, 2026-11-24).

Every change is audited with its before/after state (section 9).
"""

from typing import Annotated, Any

from fastapi import APIRouter, Depends, Query, Request, Response

from app.auth.dependencies import RequestMetaDep
from app.core.errors import ErrorResponse
from app.core.pagination import Page, PageParamsDep, known_query_params
from app.directory.schemas import (
    OrganizationCreate,
    OrganizationOut,
    OrganizationUpdate,
    RegionCreate,
    RegionOut,
    RegionUpdate,
)
from app.directory.service import DirectoryFilters, DirectoryService
from app.rbac.dependencies import require
from app.rbac.principal import Principal


async def _no_store(response: Response) -> None:
    response.headers["Cache-Control"] = "no-store"


async def get_directory_service(request: Request) -> DirectoryService:
    service = request.app.state.directory_service
    if not isinstance(service, DirectoryService):  # pragma: no cover - set in lifespan
        raise RuntimeError("directory service is not initialised")
    return service


DirectoryServiceDep = Annotated[DirectoryService, Depends(get_directory_service)]
RegionsRead = Annotated[Principal, Depends(require("admin:regions:read"))]
RegionsWrite = Annotated[Principal, Depends(require("admin:regions:write"))]
OrganizationsRead = Annotated[Principal, Depends(require("admin:organizations:read"))]
OrganizationsWrite = Annotated[Principal, Depends(require("admin:organizations:write"))]
Search = Annotated[str | None, Query(min_length=1, max_length=64)]

router = APIRouter(prefix="/api/v1/admin", tags=["admin"], dependencies=[Depends(_no_store)])


def _errors(*statuses: int) -> dict[int | str, dict[str, Any]]:
    return {status: {"model": ErrorResponse} for status in statuses}


# --- regions -------------------------------------------------------------------


@router.get(
    "/regions",
    operation_id="admin_regions_list",
    summary="Hududlar ro'yxati",
    dependencies=[Depends(known_query_params("page", "page_size", "q", "status"))],
    responses=_errors(401, 403, 422),
)
async def list_regions(
    _: RegionsRead,
    service: DirectoryServiceDep,
    paging: PageParamsDep,
    q: Search = None,
    status: bool | None = None,
) -> Page[RegionOut]:
    regions, total = await service.list_regions(paging, DirectoryFilters(q=q, status=status))
    return Page[RegionOut](
        items=[RegionOut.model_validate(r, from_attributes=True) for r in regions],
        page=paging.page,
        page_size=paging.page_size,
        total=total,
    )


@router.post(
    "/regions",
    status_code=201,
    operation_id="admin_regions_create",
    summary="Hudud qo'shish",
    responses=_errors(401, 403, 409, 422),
)
async def create_region(
    body: RegionCreate, actor: RegionsWrite, service: DirectoryServiceDep, meta: RequestMetaDep
) -> RegionOut:
    region = await service.create_region(
        actor, meta, name=body.name, dtm_id=body.dtm_id, p_code=body.p_code, status=body.status
    )
    return RegionOut.model_validate(region, from_attributes=True)


@router.get(
    "/regions/{region_id}",
    operation_id="admin_regions_get",
    summary="Hudud ma'lumotlari",
    responses=_errors(401, 403, 404),
)
async def get_region(region_id: int, _: RegionsRead, service: DirectoryServiceDep) -> RegionOut:
    return RegionOut.model_validate(await service.get_region(region_id), from_attributes=True)


@router.patch(
    "/regions/{region_id}",
    operation_id="admin_regions_update",
    summary="Hududni tahrirlash yoki nofaol qilish",
    responses=_errors(401, 403, 404, 409, 422),
)
async def update_region(
    region_id: int,
    body: RegionUpdate,
    actor: RegionsWrite,
    service: DirectoryServiceDep,
    meta: RequestMetaDep,
) -> RegionOut:
    changes = body.model_dump(include=body.model_fields_set)
    region = await service.update_region(actor, meta, region_id, changes)
    return RegionOut.model_validate(region, from_attributes=True)


@router.delete(
    "/regions/{region_id}",
    status_code=204,
    operation_id="admin_regions_delete",
    summary="Hududni o'chirish (tashkilot va foydalanuvchilar biriktirilmagan bo'lsa)",
    responses=_errors(401, 403, 404, 409),
)
async def delete_region(
    region_id: int, actor: RegionsWrite, service: DirectoryServiceDep, meta: RequestMetaDep
) -> None:
    await service.delete_region(actor, meta, region_id)


# --- organizations -------------------------------------------------------------


@router.get(
    "/organizations",
    operation_id="admin_organizations_list",
    summary="Tashkilotlar ro'yxati",
    dependencies=[Depends(known_query_params("page", "page_size", "q", "status", "region_id"))],
    responses=_errors(401, 403, 422),
)
async def list_organizations(
    _: OrganizationsRead,
    service: DirectoryServiceDep,
    paging: PageParamsDep,
    q: Search = None,
    status: bool | None = None,
    region_id: Annotated[int | None, Query(ge=1)] = None,
) -> Page[OrganizationOut]:
    filters = DirectoryFilters(q=q, status=status, region_id=region_id)
    orgs, total = await service.list_organizations(paging, filters)
    return Page[OrganizationOut](
        items=[OrganizationOut.model_validate(o, from_attributes=True) for o in orgs],
        page=paging.page,
        page_size=paging.page_size,
        total=total,
    )


@router.post(
    "/organizations",
    status_code=201,
    operation_id="admin_organizations_create",
    summary="Tashkilot qo'shish",
    responses=_errors(401, 403, 409, 422),
)
async def create_organization(
    body: OrganizationCreate,
    actor: OrganizationsWrite,
    service: DirectoryServiceDep,
    meta: RequestMetaDep,
) -> OrganizationOut:
    org = await service.create_organization(
        actor, meta, name=body.name, region_id=body.region_id, status=body.status
    )
    return OrganizationOut.model_validate(org, from_attributes=True)


@router.get(
    "/organizations/{org_id}",
    operation_id="admin_organizations_get",
    summary="Tashkilot ma'lumotlari",
    responses=_errors(401, 403, 404),
)
async def get_organization(
    org_id: int, _: OrganizationsRead, service: DirectoryServiceDep
) -> OrganizationOut:
    org = await service.get_organization(org_id)
    return OrganizationOut.model_validate(org, from_attributes=True)


@router.patch(
    "/organizations/{org_id}",
    operation_id="admin_organizations_update",
    summary="Tashkilotni tahrirlash yoki nofaol qilish",
    responses=_errors(401, 403, 404, 409, 422),
)
async def update_organization(
    org_id: int,
    body: OrganizationUpdate,
    actor: OrganizationsWrite,
    service: DirectoryServiceDep,
    meta: RequestMetaDep,
) -> OrganizationOut:
    changes = body.model_dump(include=body.model_fields_set)
    org = await service.update_organization(actor, meta, org_id, changes)
    return OrganizationOut.model_validate(org, from_attributes=True)


@router.delete(
    "/organizations/{org_id}",
    status_code=204,
    operation_id="admin_organizations_delete",
    summary="Tashkilotni o'chirish (foydalanuvchilar biriktirilmagan bo'lsa)",
    responses=_errors(401, 403, 404, 409),
)
async def delete_organization(
    org_id: int, actor: OrganizationsWrite, service: DirectoryServiceDep, meta: RequestMetaDep
) -> None:
    await service.delete_organization(actor, meta, org_id)
