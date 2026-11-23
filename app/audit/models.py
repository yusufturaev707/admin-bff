"""Audit tables (section 9): `audit_log` and `audit_anchors`.

`audit_log` is partitioned by month (`PARTITION BY RANGE (ts)`). Partitions are
named `audit_log_yYYYYmMM` and are created only by the SQL function
`audit_ensure_partition` (migration 0003), never by hand: it also puts the
TRUNCATE guard on each partition.

Both tables are append-only: triggers reject UPDATE, DELETE and TRUNCATE for
every role, and the application role is granted only SELECT and INSERT on
`audit_log` and SELECT on `audit_anchors` (app/core/db_privileges.py).

`id` is backed by a plain sequence rather than an identity column, because
PostgreSQL 16 does not support identity columns on partitioned tables.
"""

import re
import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import (
    BigInteger,
    CheckConstraint,
    Identity,
    Index,
    Integer,
    PrimaryKeyConstraint,
    String,
    Text,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import INET, JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.core.db import Base

AUDIT_ID_SEQUENCE = "audit_log_id_seq"
PARTITION_NAME_RE = re.compile(r"^audit_log_y\d{4}m\d{2}$")

# Serialises every append to the chain, the partition DDL and the retention job
# (pg_advisory_xact_lock). int.from_bytes(b"auditlog"); the same literal is
# compiled into the SQL functions of migration 0003, never change it.
AUDIT_CHAIN_LOCK_KEY = 7022629598041763687

_HASH_SQL = "~ '^[0-9a-f]{64}$'"


def include_name(name: str | None, type_: str, _parent_names: object = None) -> bool:
    """Alembic `include_name` hook: monthly partitions are not part of the
    model (they are created at run time), so autogenerate must ignore them."""
    return not (type_ == "table" and name is not None and PARTITION_NAME_RE.fullmatch(name))


class AuditRecord(Base):
    __tablename__ = "audit_log"
    __table_args__ = (
        # The partition key must be part of every unique constraint.
        PrimaryKeyConstraint("id", "ts", name="pk_audit_log"),
        CheckConstraint("outcome IN ('success', 'denied', 'error')", name="outcome_valid"),
        CheckConstraint(f"hash {_HASH_SQL}", name="hash_format"),
        CheckConstraint(f"prev_hash {_HASH_SQL}", name="prev_hash_format"),
        Index("ix_audit_log_actor_id_id", "actor_id", "id"),
        Index("ix_audit_log_action_id", "action", "id"),
        Index("ix_audit_log_resource_id", "resource_id"),
        Index("ix_audit_log_request_id", "request_id"),
        {"postgresql_partition_by": "RANGE (ts)"},
    )

    id: Mapped[int] = mapped_column(
        BigInteger, server_default=text(f"nextval('{AUDIT_ID_SEQUENCE}'::regclass)")
    )
    ts: Mapped[datetime]
    actor_id: Mapped[uuid.UUID | None]
    actor_username: Mapped[str | None] = mapped_column(Text)
    actor_ip: Mapped[str | None] = mapped_column(INET)
    user_agent: Mapped[str | None] = mapped_column(Text)
    session_hash: Mapped[str | None] = mapped_column(Text)
    action: Mapped[str] = mapped_column(Text)
    system_id: Mapped[str | None] = mapped_column(Text)
    resource: Mapped[str | None] = mapped_column(Text)
    resource_id: Mapped[str | None] = mapped_column(Text)
    outcome: Mapped[str] = mapped_column(Text)
    status_code: Mapped[int | None] = mapped_column(Integer)
    request_id: Mapped[str | None] = mapped_column(Text)
    # PII is masked before it is written (app.audit.chain).
    before: Mapped[Any] = mapped_column(JSONB(none_as_null=True), nullable=True)
    after: Mapped[Any] = mapped_column(JSONB(none_as_null=True), nullable=True)
    # Event specifics that have no column of their own (e.g. the step of a login).
    details: Mapped[dict[str, Any]] = mapped_column(JSONB, server_default=text("'{}'::jsonb"))
    reason: Mapped[str | None] = mapped_column(Text)
    prev_hash: Mapped[str] = mapped_column(String(64))
    hash: Mapped[str] = mapped_column(String(64))


class AuditAnchor(Base):
    """Written by `audit_drop_expired_partitions` just before a partition is
    dropped: the last record of the dropped part of the chain. The remaining
    chain is verified from the newest anchor."""

    __tablename__ = "audit_anchors"
    __table_args__ = (CheckConstraint(f"last_hash {_HASH_SQL}", name="last_hash_format"),)

    id: Mapped[int] = mapped_column(BigInteger, Identity(always=True), primary_key=True)
    created_at: Mapped[datetime] = mapped_column(server_default=func.now())
    partition_name: Mapped[str] = mapped_column(Text)
    rows_dropped: Mapped[int] = mapped_column(BigInteger)
    last_id: Mapped[int] = mapped_column(BigInteger, unique=True)
    last_ts: Mapped[datetime]
    last_hash: Mapped[str] = mapped_column(String(64))
