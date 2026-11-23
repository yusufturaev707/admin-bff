"""Audit test helpers: the test database's audit tables, read and written directly."""

import uuid
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import datetime

from sqlalchemy import select
from sqlalchemy.engine import URL
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool

from app.audit.models import AuditRecord
from app.audit.sink import AuditEvent, AuditOutcome
from app.audit.writer import DbAuditSink
from app.core.db import create_sessionmaker, database_url
from app.core.time import Clock
from app.settings import Settings


@asynccontextmanager
async def sessions(
    settings: Settings, url: URL | None = None
) -> AsyncIterator[async_sessionmaker[AsyncSession]]:
    engine = create_async_engine(url or database_url(settings), poolclass=NullPool)
    try:
        yield create_sessionmaker(engine)
    finally:
        await engine.dispose()


async def records(settings: Settings, **equals: object) -> list[AuditRecord]:
    """Audit records in chain order, optionally filtered by column values."""
    query = select(AuditRecord).order_by(AuditRecord.id)
    for name, value in equals.items():
        query = query.where(getattr(AuditRecord, name) == value)
    async with sessions(settings) as db, db() as session:
        return list((await session.scalars(query)).all())


def event(action: str = "test.thing.do", **changes: object) -> AuditEvent:
    values: dict[str, object] = {
        "action": action,
        "outcome": AuditOutcome.SUCCESS,
        "actor_id": uuid.uuid4(),
        "actor_username": "tester",
        "actor_ip": "10.20.30.40",
        "user_agent": "pytest",
        "request_id": str(uuid.uuid4()),
    }
    values.update(changes)
    return AuditEvent(**values)  # type: ignore[arg-type]


async def write_events(
    settings: Settings,
    clock: Clock,
    count: int,
    action: str = "test.thing.do",
    **changes: object,
) -> None:
    async with sessions(settings) as db:
        sink = DbAuditSink(db, clock=clock)
        for _ in range(count):
            await sink.write(event(action, **changes))


def month_partition(ts: datetime) -> str:
    return f"audit_log_y{ts.year:04d}m{ts.month:02d}"
