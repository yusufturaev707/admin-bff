"""/api/v1/audit: the audit log (section 9).

* `GET /api/v1/audit`: filters + cursor pagination, newest first
  (`audit:logs:read`). Not audited itself: an ordinary read.
* `POST /api/v1/audit/export`: CSV of the same filters (`audit:logs:export`,
  step-up, 5 per hour, audited). POST, so the CSRF token protects it.
"""

import uuid
from datetime import datetime
from typing import Annotated, Any

from fastapi import APIRouter, Depends, Query, Request, Response
from fastapi.responses import StreamingResponse
from pydantic import AwareDatetime

from app.audit.schemas import (
    ACTION_MAX,
    REQUEST_ID_MAX,
    RESOURCE_ID_MAX,
    RESOURCE_MAX,
    SYSTEM_MAX,
    USERNAME_MAX,
    AuditEntry,
    AuditExportRequest,
    check_query_range,
)
from app.audit.service import AuditFilters, AuditLogService
from app.audit.sink import AuditOutcome
from app.auth.dependencies import RequestMetaDep, get_clock
from app.core.errors import ErrorResponse
from app.core.pagination import (
    MAX_PAGE_SIZE,
    CursorPage,
    decode_cursor,
    encode_cursor,
    known_query_params,
)
from app.core.time import Clock
from app.rbac.dependencies import require, require_recent_mfa
from app.rbac.principal import Principal

_LIST_PARAMS = (
    "actor_id",
    "actor_username",
    "system_id",
    "action",
    "outcome",
    "resource",
    "resource_id",
    "request_id",
    "from",
    "to",
    "cursor",
    "limit",
)


async def _no_store(response: Response) -> None:
    response.headers["Cache-Control"] = "no-store"


async def get_audit_log_service(request: Request) -> AuditLogService:
    service = request.app.state.audit_log_service
    if not isinstance(service, AuditLogService):  # pragma: no cover - set in lifespan
        raise RuntimeError("audit log service is not initialised")
    return service


AuditLogServiceDep = Annotated[AuditLogService, Depends(get_audit_log_service)]
LogsRead = Annotated[Principal, Depends(require("audit:logs:read"))]
LogsExport = Annotated[Principal, Depends(require("audit:logs:export"))]

router = APIRouter(prefix="/api/v1/audit", tags=["audit"], dependencies=[Depends(_no_store)])


def _errors(*statuses: int) -> dict[int | str, dict[str, Any]]:
    return {status: {"model": ErrorResponse} for status in statuses}


@router.get(
    "",
    operation_id="audit_logs_list",
    summary="Audit log: kim, qachon, nima qildi (yangilari birinchi)",
    description=(
        "Filtrlar aniq qiymat bo'yicha. `from` kiradi, `to` kirmaydi. Keyingi sahifa uchun "
        "javobdagi `next_cursor` `cursor` sifatida yuboriladi."
    ),
    dependencies=[Depends(known_query_params(*_LIST_PARAMS))],
    responses=_errors(401, 403, 422),
)
async def list_logs(
    _: LogsRead,
    service: AuditLogServiceDep,
    actor_id: uuid.UUID | None = None,
    actor_username: Annotated[str | None, Query(min_length=1, max_length=USERNAME_MAX)] = None,
    system_id: Annotated[str | None, Query(min_length=1, max_length=SYSTEM_MAX)] = None,
    action: Annotated[str | None, Query(min_length=1, max_length=ACTION_MAX)] = None,
    outcome: AuditOutcome | None = None,
    resource: Annotated[str | None, Query(min_length=1, max_length=RESOURCE_MAX)] = None,
    resource_id: Annotated[str | None, Query(min_length=1, max_length=RESOURCE_ID_MAX)] = None,
    request_id: Annotated[str | None, Query(min_length=1, max_length=REQUEST_ID_MAX)] = None,
    since: Annotated[AwareDatetime | None, Query(alias="from")] = None,
    until: Annotated[AwareDatetime | None, Query(alias="to")] = None,
    cursor: Annotated[str | None, Query(min_length=1, max_length=64)] = None,
    limit: Annotated[int, Query(ge=1, le=MAX_PAGE_SIZE)] = 50,
) -> CursorPage[AuditEntry]:
    check_query_range(since, until)
    filters = AuditFilters(
        actor_id=actor_id,
        actor_username=actor_username.lower() if actor_username else None,
        system_id=system_id,
        action=action,
        outcome=outcome,
        resource=resource,
        resource_id=resource_id,
        request_id=request_id,
        since=since,
        until=until,
    )
    records, more = await service.list_records(
        filters, after_id=decode_cursor(cursor) if cursor else None, limit=limit
    )
    return CursorPage[AuditEntry](
        items=[AuditEntry.from_record(r) for r in records],
        next_cursor=encode_cursor(records[-1].id) if more else None,
    )


@router.post(
    "/export",
    operation_id="audit_logs_export",
    summary="Audit log'ni CSV faylga eksport qilish",
    description=(
        "TOTP so'nggi 5 daqiqada kiritilgan bo'lishi kerak (step-up). Bir soatda ko'pi bilan "
        "5 ta eksport, bitta faylda ko'pi bilan 100 000 yozuv. Fayl UTF-8 (BOM bilan), "
        "eskisi birinchi."
    ),
    dependencies=[Depends(require_recent_mfa(300))],
    response_class=StreamingResponse,
    responses={
        200: {
            "description": "CSV fayl",
            "content": {"text/csv": {"schema": {"type": "string", "format": "binary"}}},
        },
        **_errors(401, 403, 422, 429),
    },
)
async def export_logs(
    body: AuditExportRequest,
    actor: LogsExport,
    service: AuditLogServiceDep,
    meta: RequestMetaDep,
    clock: Annotated[Clock, Depends(get_clock)],
) -> StreamingResponse:
    stream = await service.start_export(actor, meta, body.filters())
    filename = f"audit-{_stamp(clock())}.csv"
    return StreamingResponse(
        stream,
        media_type="text/csv; charset=utf-8",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "Cache-Control": "no-store",
        },
    )


def _stamp(now: datetime) -> str:
    return now.strftime("%Y%m%dT%H%M%SZ")
