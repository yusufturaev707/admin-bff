"""Checks that the audit log is intact (CLAUDE.md section 9; owner's decision,
2026-11-25).

    uv run python -m scripts.verify_audit [--journal-id ID --journal-hash HASH]

On the server: `admin-bff verify-audit`. It runs this with the service's
settings and credentials and passes the newest audit record found in
journald (deploy/admin-bff.sh).

* The hash chain (app.audit.verify) shows a record that was changed, deleted,
  inserted or backdated.
* Records cut off the end of the chain leave no gap in it. journald keeps a
  copy of every record with its id and hash: if the newest one there is
  missing from the database, or has another hash, the end was cut or
  rewritten.

Exit code 0: no problem found; 1: problems, or no database; 2: bad arguments.
"""

import argparse
import asyncio
import re
import sys
from collections.abc import Sequence

from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError

from app.audit.models import AuditRecord
from app.audit.verify import ChainProblem, VerifyResult, verify_chain
from app.core.db import create_engine, create_sessionmaker
from app.settings import Settings, load_settings

_HASH = re.compile(r"[0-9a-f]{64}")

JournalRecord = tuple[int, str]  # id and hash of the newest audit record in journald


async def verify(settings: Settings, journal: JournalRecord | None = None) -> VerifyResult:
    engine = create_engine(settings)
    try:
        db = create_sessionmaker(engine)
        result = await verify_chain(db)
        if journal is not None:
            record_id, record_hash = journal
            async with db() as session:
                stored = await session.scalar(
                    select(AuditRecord.hash).where(AuditRecord.id == record_id).limit(1)
                )
            if stored is None:
                result.problems.append(
                    ChainProblem(
                        record_id,
                        "missing",
                        "journald'da bor, bazada yo'q (zanjir oxiri kesilgan bo'lishi mumkin)",
                    )
                )
            elif stored != record_hash:
                result.problems.append(
                    ChainProblem(record_id, "hash", "hash'i journald'dagi nusxaga mos emas")
                )
    finally:
        await engine.dispose()
    return result


def report(result: VerifyResult, journal: JournalRecord | None) -> str:
    lines = [f"Tekshirilgan yozuvlar: {result.checked}"]
    if result.last_id is not None:
        lines.append(f"Bazadagi oxirgi yozuv: id {result.last_id}, hash {result.last_hash}")
    if journal is None:
        lines.append(
            "journald bilan solishtirilmadi: zanjir oxiridan yozuvlar o'chirilgani ko'rinmaydi."
        )
    else:
        lines.append(f"journald'dagi oxirgi yozuv: id {journal[0]}, hash {journal[1]}")
    if result.ok:
        lines.append("Natija: muammo topilmadi.")
    else:
        lines.append(
            "Natija: MUAMMO TOPILDI. Bu yozuvlar o'zgartirilgan, o'chirilgan yoki "
            "qo'shilgan bo'lishi mumkin:"
        )
        lines += [f"  id {p.record_id}: {p.message}" for p in result.problems]
    return "\n".join(lines) + "\n"


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m scripts.verify_audit", description="Audit log butunligini tekshirish"
    )
    parser.add_argument("--journal-id", type=int, help="journald'dagi oxirgi audit yozuvi id'si")
    parser.add_argument("--journal-hash", help="o'sha yozuvning hash'i")
    args = parser.parse_args(argv)
    journal: JournalRecord | None = None
    if args.journal_id is not None or args.journal_hash is not None:
        if args.journal_id is None or not _HASH.fullmatch(args.journal_hash or ""):
            parser.error("--journal-id va --journal-hash (64 ta hex belgi) birga beriladi")
        journal = (args.journal_id, args.journal_hash)
    try:
        result = asyncio.run(verify(load_settings(), journal))
    except (OSError, SQLAlchemyError) as exc:
        sys.stderr.write(f"Bazaga ulanib bo'lmadi ({type(exc).__name__}).\n")
        return 1
    sys.stdout.write(report(result, journal))
    return 0 if result.ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
