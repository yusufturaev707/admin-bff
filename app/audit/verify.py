"""Chain verification of the audit log.

Verification walks the whole remaining chain in `id` order and checks, for
every record:

* `prev_hash` is the `hash` of the record before it (the first record follows
  the newest anchor, or GENESIS_HASH if no partition was ever dropped): a
  deleted or inserted record breaks this link;
* `hash` matches the record's content: a modified record breaks this;
* `ts` does not go backwards: a backdated record breaks this;
* `id` is unique (the primary key is `(id, ts)`, as partitioning requires).

It cannot see records cut off the end of the chain. scripts/verify_audit.py
(`admin-bff verify-audit`) also looks the newest record of the journald copy
up in the database (docs/security.md).
"""

from dataclasses import dataclass, field
from datetime import datetime

from sqlalchemy import select, tuple_
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.audit.chain import GENESIS_HASH, AuditRow
from app.audit.models import AuditAnchor, AuditRecord

BATCH = 1000


@dataclass(frozen=True, slots=True)
class ChainProblem:
    record_id: int
    kind: str  # "prev_hash", "hash", "ts", "duplicate_id", "missing"
    message: str  # Uzbek, printed by scripts/verify_audit.py


@dataclass(slots=True)
class VerifyResult:
    checked: int = 0
    anchor_id: int | None = None  # the anchor the chain was verified from
    first_id: int | None = None
    last_id: int | None = None
    last_hash: str | None = None
    problems: list[ChainProblem] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.problems


async def verify_chain(
    db: async_sessionmaker[AsyncSession], *, max_problems: int = 20
) -> VerifyResult:
    result = VerifyResult()
    async with db() as session:
        anchor = await session.scalar(
            select(AuditAnchor).order_by(AuditAnchor.last_id.desc()).limit(1)
        )
        prev_hash = GENESIS_HASH
        prev_ts: datetime | None = None
        after_id = 0
        if anchor is not None:
            result.anchor_id = anchor.id
            prev_hash, prev_ts, after_id = anchor.last_hash, anchor.last_ts, anchor.last_id
            # Records the retention job should have dropped with the anchor.
            stale = await session.scalar(
                select(AuditRecord.id)
                .where(AuditRecord.id <= anchor.last_id)
                .order_by(AuditRecord.id)
                .limit(1)
            )
            if stale is not None:
                result.problems.append(
                    ChainProblem(
                        stale, "prev_hash", "eng yangi anchor'dan oldingi yozuv o'chirilmagan"
                    )
                )
        query = select(AuditRecord).order_by(AuditRecord.id, AuditRecord.ts).limit(BATCH)
        batch = (await session.scalars(query.where(AuditRecord.id > after_id))).all()
        prev_id: int | None = None
        while batch and len(result.problems) < max_problems:
            for record in batch:
                if result.first_id is None:
                    result.first_id = record.id
                if record.id == prev_id:
                    result.problems.append(
                        ChainProblem(record.id, "duplicate_id", "id ikki yozuvda takrorlangan")
                    )
                if record.prev_hash != prev_hash:
                    result.problems.append(
                        ChainProblem(
                            record.id,
                            "prev_hash",
                            "oldingi yozuvga bog'lanmagan (yozuv o'chirilgan yoki qo'shilgan)",
                        )
                    )
                expected = AuditRow.from_record(record).chain_hash(record.prev_hash)
                if expected != record.hash:
                    result.problems.append(
                        ChainProblem(
                            record.id, "hash", "mazmuni hash'iga mos emas (yozuv o'zgartirilgan)"
                        )
                    )
                if prev_ts is not None and record.ts < prev_ts:
                    result.problems.append(
                        ChainProblem(record.id, "ts", "vaqti oldingi yozuvnikidan oldin")
                    )
                prev_hash, prev_ts, prev_id = record.hash, record.ts, record.id
                result.checked += 1
                result.last_id, result.last_hash = record.id, record.hash
            last = batch[-1]
            session.expunge_all()  # keeps memory flat on a long chain
            batch = (
                await session.scalars(
                    query.where(tuple_(AuditRecord.id, AuditRecord.ts) > (last.id, last.ts))
                )
            ).all()
    del result.problems[max_problems:]
    return result
