"""Appends audit events to the hash chain (section 9).

One append is one short transaction:

1. `pg_advisory_xact_lock` serialises appends across all workers (and against
   the retention job), so the chain has a single, well-defined order;
2. the head of the chain is read: the newest record, or, if old partitions were
   dropped and nothing newer exists, the newest anchor;
3. `ts` = max(now, head.ts): time never goes backwards along the chain, so a
   dropped month is always a prefix of it;
4. the month's partition is created if missing (SECURITY DEFINER function);
5. the record is inserted with `prev_hash` and `hash`.

Every event is also written to the `audit` logger (journald), with its id and
hash if it was stored. If the database write fails, the log copy carries the
error and the exception propagates: the request fails rather than continue
unaudited.
"""

from collections.abc import Sequence

from sqlalchemy import insert, text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.audit.chain import GENESIS_HASH, AuditRow
from app.audit.context import mark_written
from app.audit.models import AUDIT_CHAIN_LOCK_KEY, AuditRecord
from app.audit.sink import AuditEvent, AuditSink, LogAuditSink, StoredAudit
from app.core.logging import get_logger
from app.core.time import Clock

logger = get_logger(__name__)

_LOCK = text("SELECT pg_advisory_xact_lock(:key)")
_HEAD = text(
    """
    SELECT ts, hash FROM (
        (SELECT 0 AS src, ts, hash FROM audit_log ORDER BY id DESC LIMIT 1)
        UNION ALL
        (SELECT 1 AS src, last_ts, last_hash FROM audit_anchors ORDER BY last_id DESC LIMIT 1)
    ) AS head
    ORDER BY src
    LIMIT 1
    """
)
_ENSURE_PARTITION = text("SELECT audit_ensure_partition(:ts)")


class DbAuditSink:
    def __init__(
        self,
        db: async_sessionmaker[AsyncSession],
        *,
        clock: Clock,
        listeners: Sequence[AuditSink] = (),
    ) -> None:
        """`listeners` get every stored event (tests; in-app alerts later)."""
        self._db = db
        self._clock = clock
        self._log = LogAuditSink()
        self._listeners = tuple(listeners)

    async def write(self, event: AuditEvent) -> None:
        # Set first: even a failed write must not trigger the request-level
        # fallback record (app.audit.middleware), which would fail the same way.
        mark_written()
        try:
            row, stored = await self._append(event)
        except Exception as exc:
            self._log.log(
                AuditRow.from_event(event, self._clock()).canonical_fields(),
                error=type(exc).__name__,
            )
            raise
        self._log.log(row.canonical_fields(), stored=stored)
        for listener in self._listeners:
            try:
                await listener.write(event)
            except Exception:  # a listener must never fail the audited request
                logger.exception("audit_listener_failed", action=event.action)

    async def _append(self, event: AuditEvent) -> tuple[AuditRow, StoredAudit]:
        async with self._db() as db, db.begin():
            await db.execute(_LOCK, {"key": AUDIT_CHAIN_LOCK_KEY})
            head = (await db.execute(_HEAD)).first()
            now = self._clock()
            if head is None:
                prev_hash, ts = GENESIS_HASH, now
            else:
                prev_hash, ts = head.hash, max(now, head.ts)
            await db.execute(_ENSURE_PARTITION, {"ts": ts})
            row = AuditRow.from_event(event, ts)
            digest = row.chain_hash(prev_hash)
            record_id = await db.scalar(
                insert(AuditRecord)
                .values(**row.columns(), prev_hash=prev_hash, hash=digest)
                .returning(AuditRecord.id)
            )
        if record_id is None:  # pragma: no cover - RETURNING always yields the id
            raise RuntimeError("audit insert returned no id")
        return row, StoredAudit(id=record_id, ts=row.ts, hash=digest)
