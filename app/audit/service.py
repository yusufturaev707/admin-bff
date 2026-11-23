"""Reading the audit log: list with filters, CSV export (section 9).

Ordinary reads are not audited (section 9); an export is, and is limited to
EXPORTS_PER_HOUR per admin (section 11).
"""

import csv
import io
import json
import uuid
from collections.abc import AsyncIterator, Sequence
from dataclasses import asdict, dataclass
from datetime import datetime
from typing import Any

from redis.asyncio import Redis
from sqlalchemy import Select, func, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.audit.models import AuditRecord
from app.audit.sink import AuditEvent, AuditOutcome, AuditSink
from app.auth.service import RequestMeta
from app.core.errors import AppError, ErrorCode, field_error
from app.core.ratelimit import FixedWindowLimiter
from app.core.time import isoformat_z
from app.rbac.principal import Principal

EXPORTS_PER_HOUR = 5
MAX_EXPORT_ROWS = 100_000
_CSV_BATCH = 500

CSV_COLUMNS: tuple[str, ...] = (
    "id",
    "ts",
    "actor_id",
    "actor_username",
    "actor_ip",
    "user_agent",
    "session_hash",
    "action",
    "system_id",
    "resource",
    "resource_id",
    "outcome",
    "status_code",
    "request_id",
    "reason",
    "before",
    "after",
    "details",
)
# A cell starting with one of these is a formula in Excel/LibreOffice
# (CSV injection); such cells get a leading apostrophe.
_FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")


@dataclass(frozen=True, slots=True)
class AuditFilters:
    actor_id: uuid.UUID | None = None
    actor_username: str | None = None
    system_id: str | None = None
    action: str | None = None
    outcome: AuditOutcome | None = None
    resource: str | None = None
    resource_id: str | None = None
    request_id: str | None = None
    since: datetime | None = None  # inclusive
    until: datetime | None = None  # exclusive

    def apply(self, query: Select[Any]) -> Select[Any]:
        exact = {
            AuditRecord.actor_id: self.actor_id,
            AuditRecord.actor_username: self.actor_username,
            AuditRecord.system_id: self.system_id,
            AuditRecord.action: self.action,
            AuditRecord.outcome: self.outcome.value if self.outcome else None,
            AuditRecord.resource: self.resource,
            AuditRecord.resource_id: self.resource_id,
            AuditRecord.request_id: self.request_id,
        }
        for column, value in exact.items():
            if value is not None:
                query = query.where(column == value)
        if self.since is not None:
            query = query.where(AuditRecord.ts >= self.since)
        if self.until is not None:
            query = query.where(AuditRecord.ts < self.until)
        return query

    def as_details(self) -> dict[str, Any]:
        return {k: v for k, v in asdict(self).items() if v is not None}


def _raise_if_limited(retry_after: int | None) -> None:
    if retry_after is not None:
        raise AppError(
            ErrorCode.RATE_LIMITED,
            f"Bir soatda ko'pi bilan {EXPORTS_PER_HOUR} ta eksport mumkin",
            headers={"Retry-After": str(retry_after)},
        )


def csv_cell(value: object) -> str:
    if value is None:
        return ""
    if isinstance(value, datetime):
        return isoformat_z(value)
    if isinstance(value, dict | list):
        cell = json.dumps(value, ensure_ascii=False, sort_keys=True)
    else:
        cell = str(value)
    return f"'{cell}" if cell.startswith(_FORMULA_PREFIXES) else cell


def csv_line(values: Sequence[object]) -> str:
    buffer = io.StringIO()
    csv.writer(buffer, lineterminator="\r\n").writerow([csv_cell(v) for v in values])
    return buffer.getvalue()


class AuditLogService:
    def __init__(
        self,
        db: async_sessionmaker[AsyncSession],
        *,
        redis: Redis,
        prefix: str,
        audit: AuditSink,
    ) -> None:
        self._db = db
        self._audit = audit
        self._exports = FixedWindowLimiter(
            redis, prefix=prefix, name="audit_export", limit=EXPORTS_PER_HOUR, window_s=3600
        )

    async def list_records(
        self, filters: AuditFilters, *, after_id: int | None, limit: int
    ) -> tuple[list[AuditRecord], bool]:
        """Newest first. Returns the page and whether more records follow."""
        query = filters.apply(select(AuditRecord))
        if after_id is not None:
            query = query.where(AuditRecord.id < after_id)
        async with self._db() as db:
            rows = list(
                (await db.scalars(query.order_by(AuditRecord.id.desc()).limit(limit + 1))).all()
            )
        return rows[:limit], len(rows) > limit

    async def count(self, filters: AuditFilters) -> int:
        async with self._db() as db:
            total = await db.scalar(filters.apply(select(func.count()).select_from(AuditRecord)))
        return int(total or 0)

    async def start_export(
        self, actor: Principal, meta: RequestMeta, filters: AuditFilters
    ) -> AsyncIterator[bytes]:
        """Checks the limits, audits the export and returns the CSV stream."""
        subject = str(actor.user_id)
        # Checked before the count, so a used-up limit costs no query; counted
        # only for exports that really start.
        _raise_if_limited(await self._exports.check(subject))
        rows = await self.count(filters)
        if rows > MAX_EXPORT_ROWS:
            raise field_error(
                ("body",),
                "too_many_rows",
                f"Eksport uchun yozuvlar juda ko'p ({rows}), ko'pi bilan {MAX_EXPORT_ROWS}. "
                "Filtrlarni toraytiring",
            )
        _raise_if_limited(await self._exports.hit(subject))
        await self._audit.write(
            AuditEvent(
                action="audit.logs.export",
                outcome=AuditOutcome.SUCCESS,
                actor_id=actor.user_id,
                actor_username=actor.username,
                actor_ip=meta.ip,
                user_agent=meta.user_agent,
                session_hash=actor.session_key,
                request_id=meta.request_id,
                resource="logs",
                details={"filters": filters.as_details(), "rows": rows, "format": "csv"},
            )
        )
        return self._csv(filters)

    async def _csv(self, filters: AuditFilters) -> AsyncIterator[bytes]:
        # The BOM makes Excel read the file as UTF-8.
        yield ("﻿" + csv_line(CSV_COLUMNS)).encode("utf-8")
        query = filters.apply(select(AuditRecord)).order_by(AuditRecord.id).limit(MAX_EXPORT_ROWS)
        async with self._db() as db, db.begin():
            result = await db.stream_scalars(query)
            async for batch in result.partitions(_CSV_BATCH):
                yield "".join(
                    csv_line([getattr(r, column) for column in CSV_COLUMNS]) for r in batch
                ).encode("utf-8")
