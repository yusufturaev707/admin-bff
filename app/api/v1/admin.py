"""/api/v1/admin: admins, roles, permissions (section 7).

Every change additionally needs a recent TOTP (step-up, 5 minutes): these
endpoints decide who may do what in every connected system.
"""

import uuid
from typing import Annotated, Any

from fastapi import APIRouter, Depends, Query, Request, Response

from app.auth.dependencies import RequestMetaDep
from app.core.errors import ErrorResponse
from app.core.pagination import Page, PageParamsDep, known_query_params
from app.rbac.dependencies import require, require_recent_mfa
from app.rbac.principal import Principal
from app.rbac.schemas import (
    PasswordReset,
    PermissionCatalogue,
    PermissionGroup,
    PermissionItem,
    RoleCreate,
    RoleOut,
    RoleRef,
    RolesUpdate,
    RoleUpdate,
    Scope,
    ScopesUpdate,
    UserCreate,
    UserCreated,
    UserOut,
    UserSort,
    UserUpdate,
    UserUpdated,
)
from app.rbac.service import AdminService, RoleView, UserFilters, UserView

STEP_UP = Depends(require_recent_mfa(300))


async def _no_store(response: Response) -> None:
    response.headers["Cache-Control"] = "no-store"


async def get_admin_service(request: Request) -> AdminService:
    service = request.app.state.admin_service
    if not isinstance(service, AdminService):  # pragma: no cover - set in lifespan
        raise RuntimeError("admin service is not initialised")
    return service


AdminServiceDep = Annotated[AdminService, Depends(get_admin_service)]
UsersRead = Annotated[Principal, Depends(require("admin:users:read"))]
UsersWrite = Annotated[Principal, Depends(require("admin:users:write"))]
UsersSecurity = Annotated[Principal, Depends(require("admin:users:security"))]
RolesRead = Annotated[Principal, Depends(require("admin:roles:read"))]
RolesWrite = Annotated[Principal, Depends(require("admin:roles:write"))]

router = APIRouter(prefix="/api/v1/admin", tags=["admin"], dependencies=[Depends(_no_store)])


def _errors(*statuses: int) -> dict[int | str, dict[str, Any]]:
    return {status: {"model": ErrorResponse} for status in statuses}


def user_out(view: UserView) -> dict[str, Any]:
    user = view.user
    return {
        "id": user.id,
        "username": user.username,
        "full_name": user.full_name,
        "is_active": user.is_active,
        "auth_methods": list(user.auth_methods),
        "totp_enabled": user.totp_enabled,
        "must_change_password": user.must_change_password,
        "pinfl_masked": user.pinfl_masked,
        "roles": [RoleRef(id=r.id, name=r.name) for r in view.roles],
        "scopes": [Scope.model_validate({"type": t, "value": v}) for t, v in view.scopes],
        "created_at": user.created_at,
        "last_login_at": user.last_login_at,
    }


def role_out(view: RoleView) -> RoleOut:
    return RoleOut(
        id=view.role.id,
        name=view.role.name,
        description=view.role.description,
        is_system=view.role.is_system,
        permissions=view.permissions,
        user_count=view.user_count,
        created_at=view.role.created_at,
        updated_at=view.role.updated_at,
    )


def _scopes(items: list[Scope]) -> list[tuple[str, str]]:
    return [(s.type.value, s.value) for s in items]


# --- admins ------------------------------------------------------------------


@router.get(
    "/users",
    operation_id="admin_users_list",
    summary="Adminlar ro'yxati",
    dependencies=[
        Depends(known_query_params("page", "page_size", "q", "is_active", "role_id", "sort"))
    ],
    responses=_errors(401, 403, 422),
)
async def list_users(
    _: UsersRead,
    service: AdminServiceDep,
    paging: PageParamsDep,
    q: Annotated[str | None, Query(min_length=1, max_length=64)] = None,
    is_active: bool | None = None,
    role_id: uuid.UUID | None = None,
    sort: UserSort = "username",
) -> Page[UserOut]:
    views, total = await service.list_users(
        paging, UserFilters(q=q, is_active=is_active, role_id=role_id, sort=sort)
    )
    return Page[UserOut](
        items=[UserOut(**user_out(v)) for v in views],
        page=paging.page,
        page_size=paging.page_size,
        total=total,
    )


@router.post(
    "/users",
    status_code=201,
    operation_id="admin_users_create",
    summary="Admin yaratish",
    dependencies=[STEP_UP],
    responses=_errors(401, 403, 409, 422),
)
async def create_user(
    body: UserCreate, actor: UsersWrite, service: AdminServiceDep, meta: RequestMetaDep
) -> UserCreated:
    view, password = await service.create_user(
        actor,
        meta,
        username=body.username,
        full_name=body.full_name,
        methods=body.auth_methods,
        pinfl=body.pinfl,
        role_ids=body.role_ids,
        scopes=_scopes(body.scopes),
    )
    return UserCreated(**user_out(view), initial_password=password)


@router.get(
    "/users/{user_id}",
    operation_id="admin_users_get",
    summary="Admin ma'lumotlari",
    responses=_errors(401, 403, 404),
)
async def get_user(user_id: uuid.UUID, _: UsersRead, service: AdminServiceDep) -> UserOut:
    return UserOut(**user_out(await service.get_user(user_id)))


@router.patch(
    "/users/{user_id}",
    operation_id="admin_users_update",
    summary="Adminni tahrirlash yoki bloklash",
    dependencies=[STEP_UP],
    responses=_errors(401, 403, 404, 409, 422),
)
async def update_user(
    user_id: uuid.UUID,
    body: UserUpdate,
    actor: UsersWrite,
    service: AdminServiceDep,
    meta: RequestMetaDep,
) -> UserUpdated:
    changes = body.model_dump(include=body.model_fields_set)
    view, password = await service.update_user(actor, meta, user_id, changes)
    return UserUpdated(**user_out(view), initial_password=password)


@router.put(
    "/users/{user_id}/roles",
    operation_id="admin_user_roles_update",
    summary="Adminning rollarini belgilash",
    dependencies=[STEP_UP],
    responses=_errors(401, 403, 404, 409, 422),
)
async def set_roles(
    user_id: uuid.UUID,
    body: RolesUpdate,
    actor: UsersWrite,
    service: AdminServiceDep,
    meta: RequestMetaDep,
) -> UserOut:
    return UserOut(**user_out(await service.set_roles(actor, meta, user_id, body.role_ids)))


@router.put(
    "/users/{user_id}/scopes",
    operation_id="admin_user_scopes_update",
    summary="Adminning hududlarini (scope) belgilash",
    dependencies=[STEP_UP],
    responses=_errors(401, 403, 404, 422),
)
async def set_scopes(
    user_id: uuid.UUID,
    body: ScopesUpdate,
    actor: UsersWrite,
    service: AdminServiceDep,
    meta: RequestMetaDep,
) -> UserOut:
    view = await service.set_scopes(actor, meta, user_id, _scopes(body.scopes))
    return UserOut(**user_out(view))


@router.post(
    "/users/{user_id}/reset-password",
    operation_id="admin_user_password_reset",
    summary="Vaqtinchalik parol berish (barcha sessiyalari tugaydi)",
    dependencies=[STEP_UP],
    responses=_errors(401, 403, 404, 409),
)
async def reset_password(
    user_id: uuid.UUID, actor: UsersSecurity, service: AdminServiceDep, meta: RequestMetaDep
) -> PasswordReset:
    return PasswordReset(initial_password=await service.reset_password(actor, meta, user_id))


@router.post(
    "/users/{user_id}/reset-totp",
    status_code=204,
    operation_id="admin_user_totp_reset",
    summary="TOTP'ni o'chirish: admin keyingi kirishda qaytadan ulaydi",
    dependencies=[STEP_UP],
    responses=_errors(401, 403, 404),
)
async def reset_totp(
    user_id: uuid.UUID, actor: UsersSecurity, service: AdminServiceDep, meta: RequestMetaDep
) -> None:
    await service.reset_totp(actor, meta, user_id)


@router.post(
    "/users/{user_id}/unlock",
    status_code=204,
    operation_id="admin_user_login_unlock",
    summary="Login blokini muddatidan oldin ochish",
    dependencies=[STEP_UP],
    responses=_errors(401, 403, 404),
)
async def unlock(
    user_id: uuid.UUID, actor: UsersSecurity, service: AdminServiceDep, meta: RequestMetaDep
) -> None:
    await service.unlock(actor, meta, user_id)


# --- roles and permissions ----------------------------------------------------


@router.get(
    "/roles",
    operation_id="admin_roles_list",
    summary="Rollar ro'yxati",
    responses=_errors(401, 403),
)
async def list_roles(_: RolesRead, service: AdminServiceDep) -> list[RoleOut]:
    return [role_out(v) for v in await service.list_roles()]


@router.post(
    "/roles",
    status_code=201,
    operation_id="admin_roles_create",
    summary="Rol yaratish",
    dependencies=[STEP_UP],
    responses=_errors(401, 403, 409, 422),
)
async def create_role(
    body: RoleCreate, actor: RolesWrite, service: AdminServiceDep, meta: RequestMetaDep
) -> RoleOut:
    view = await service.create_role(
        actor, meta, name=body.name, description=body.description, permissions=body.permissions
    )
    return role_out(view)


@router.get(
    "/roles/{role_id}",
    operation_id="admin_roles_get",
    summary="Rol ma'lumotlari",
    responses=_errors(401, 403, 404),
)
async def get_role(role_id: uuid.UUID, _: RolesRead, service: AdminServiceDep) -> RoleOut:
    return role_out(await service.get_role(role_id))


@router.patch(
    "/roles/{role_id}",
    operation_id="admin_roles_update",
    summary="Rolni tahrirlash (keyingi so'rovdan kuchga kiradi)",
    dependencies=[STEP_UP],
    responses=_errors(401, 403, 404, 409, 422),
)
async def update_role(
    role_id: uuid.UUID,
    body: RoleUpdate,
    actor: RolesWrite,
    service: AdminServiceDep,
    meta: RequestMetaDep,
) -> RoleOut:
    view = await service.update_role(
        actor,
        meta,
        role_id,
        name=body.name,
        description=body.description,
        permissions=body.permissions,
    )
    return role_out(view)


@router.delete(
    "/roles/{role_id}",
    status_code=204,
    operation_id="admin_roles_delete",
    summary="Rolni o'chirish (adminlarga biriktirilmagan bo'lsa)",
    dependencies=[STEP_UP],
    responses=_errors(401, 403, 404, 409),
)
async def delete_role(
    role_id: uuid.UUID, actor: RolesWrite, service: AdminServiceDep, meta: RequestMetaDep
) -> None:
    await service.delete_role(actor, meta, role_id)


@router.get(
    "/permissions",
    operation_id="admin_permissions_list",
    summary="Permission'lar katalogi (rol tahrirlash oynasi uchun)",
    responses=_errors(401, 403),
)
async def list_permissions(_: RolesRead, service: AdminServiceDep) -> PermissionCatalogue:
    registry = service.registry
    return PermissionCatalogue(
        groups=[
            PermissionGroup(
                system_id=system_id,
                display_name=registry.display_name(system_id),
                permissions=[PermissionItem(code=s.code, description=s.description) for s in specs],
            )
            for system_id, specs in registry.grouped()
        ]
    )
