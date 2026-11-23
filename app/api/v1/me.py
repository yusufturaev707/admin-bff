"""GET /api/v1/me: the current admin (section 10)."""

from fastapi import APIRouter

from app.api.v1.admin import AdminServiceDep, user_out
from app.core.errors import ErrorResponse
from app.rbac.dependencies import PrincipalDep
from app.rbac.schemas import MeOut

router = APIRouter(prefix="/api/v1", tags=["me"])


@router.get(
    "/me",
    operation_id="core_me_get",
    summary="Joriy admin: ma'lumotlari, permission'lari va hududlari",
    responses={401: {"model": ErrorResponse}, 403: {"model": ErrorResponse}},
)
async def me(principal: PrincipalDep, service: AdminServiceDep) -> MeOut:
    data = user_out(await service.get_user(principal.user_id))
    return MeOut(
        id=data["id"],
        username=data["username"],
        full_name=data["full_name"],
        auth_methods=data["auth_methods"],
        must_change_password=data["must_change_password"],
        roles=data["roles"],
        permissions=sorted(principal.permissions),
        scopes=data["scopes"],
    )
