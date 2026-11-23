"""audit tables: audit_log (monthly partitions, hash chain), audit_anchors

Revision ID: 0003
Revises: 0002
Create Date: 2026-11-23

Besides the tables this creates:

* `audit_reject_change()`: the trigger function that makes both tables
  append-only (UPDATE, DELETE and TRUNCATE raise for every role, superuser
  included);
* `audit_ensure_partition(ts)`: creates the monthly partition of `ts`, with its
  own TRUNCATE guard (statement triggers are not inherited by partitions);
* `audit_drop_expired_partitions(days)`: the retention job (section 9). Writes
  an anchor (the last record of the partition) and drops whole partitions that
  ended more than `days` (at least 90) days ago.

The two functions are SECURITY DEFINER, owned by the migration (owner) role:
the application role may call them but may not run DDL itself. Every object
they touch is schema-qualified and their search_path is `pg_catalog, pg_temp`,
so a temporary table cannot shadow anything. EXECUTE is revoked from PUBLIC.

The lock key 7022629598041763687 is app.audit.models.AUDIT_CHAIN_LOCK_KEY.
"""

import re
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import context, op
from sqlalchemy.dialects import postgresql

revision: str = "0003"
down_revision: str | None = "0002"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

LOCK_KEY = 7022629598041763687
_HASH = "~ '^[0-9a-f]{64}$'"


def _schema() -> str:
    if context.is_offline_mode():
        return "public"
    schema = op.get_bind().execute(sa.text("SELECT current_schema()")).scalar_one()
    if not isinstance(schema, str) or not re.fullmatch(r"[a-z_][a-z0-9_]*", schema):
        raise RuntimeError(f"unexpected schema name {schema!r}")
    return schema


def _reject_function(s: str) -> str:
    return f"""
CREATE FUNCTION {s}.audit_reject_change() RETURNS trigger
    LANGUAGE plpgsql
AS $fn$
BEGIN
    RAISE EXCEPTION 'audit tables are append-only: % on % is not allowed', TG_OP, TG_TABLE_NAME
        USING ERRCODE = 'insufficient_privilege';
END
$fn$
"""


def _ensure_function(s: str) -> str:
    return f"""
CREATE FUNCTION {s}.audit_ensure_partition(p_ts timestamptz) RETURNS text
    LANGUAGE plpgsql
    SECURITY DEFINER
    SET search_path = pg_catalog, pg_temp
    SET TimeZone = 'UTC'
AS $fn$
DECLARE
    v_start timestamptz;
    v_name text;
BEGIN
    -- Bounded, so the application role cannot create partitions at will.
    IF p_ts IS NULL OR p_ts < now() - interval '13 months'
            OR p_ts > now() + interval '13 months' THEN
        RAISE EXCEPTION 'audit partition for % is out of the allowed range', p_ts;
    END IF;
    v_start := date_trunc('month', p_ts);
    v_name := 'audit_log_y' || to_char(v_start, 'YYYY') || 'm' || to_char(v_start, 'MM');
    IF to_regclass('{s}.' || v_name) IS NULL THEN
        PERFORM pg_advisory_xact_lock({LOCK_KEY});
        IF to_regclass('{s}.' || v_name) IS NULL THEN
            EXECUTE format(
                'CREATE TABLE {s}.%I PARTITION OF {s}.audit_log FOR VALUES FROM (%L) TO (%L)',
                v_name, v_start, v_start + interval '1 month');
            EXECUTE format(
                'CREATE TRIGGER audit_log_no_truncate BEFORE TRUNCATE ON {s}.%I '
                'FOR EACH STATEMENT EXECUTE FUNCTION {s}.audit_reject_change()',
                v_name);
        END IF;
    END IF;
    RETURN v_name;
END
$fn$
"""


def _retention_function(s: str) -> str:
    # `s` is a schema name checked by _schema(); the rest is static SQL.
    return rf"""
CREATE FUNCTION {s}.audit_drop_expired_partitions(p_retention_days integer)
    RETURNS TABLE (
        dropped_partition text,
        dropped_rows bigint,
        anchor_last_id bigint,
        anchor_last_hash text
    )
    LANGUAGE plpgsql
    SECURITY DEFINER
    SET search_path = pg_catalog, pg_temp
    SET TimeZone = 'UTC'
AS $fn$
DECLARE
    r record;
    v_rows bigint;
    v_last_id bigint;
    v_last_ts timestamptz;
    v_last_hash text;
BEGIN
    IF p_retention_days IS NULL OR p_retention_days < 90 THEN
        RAISE EXCEPTION 'audit retention must be at least 90 days, got %', p_retention_days;
    END IF;
    -- No append may run while the head of the chain is being cut off.
    PERFORM pg_advisory_xact_lock({LOCK_KEY});
    FOR r IN
        SELECT c.relname AS name,
               substring(pg_get_expr(c.relpartbound, c.oid)
                         FROM $re$TO \('([^']+)'\)$re$)::timestamptz AS upper_bound
        FROM pg_inherits i
        JOIN pg_class c ON c.oid = i.inhrelid
        WHERE i.inhparent = '{s}.audit_log'::regclass
        ORDER BY upper_bound
    LOOP
        -- Only whole partitions that ended at least p_retention_days ago.
        EXIT WHEN r.upper_bound IS NULL
            OR r.upper_bound > now() - make_interval(days => p_retention_days);
        EXECUTE format('SELECT count(*), max(id) FROM {s}.%I', r.name)
            INTO v_rows, v_last_id;
        v_last_hash := NULL;
        IF v_rows > 0 THEN
            EXECUTE format('SELECT ts, hash FROM {s}.%I WHERE id = $1', r.name)
                INTO v_last_ts, v_last_hash
                USING v_last_id;
            INSERT INTO {s}.audit_anchors
                (partition_name, rows_dropped, last_id, last_ts, last_hash)
                VALUES (r.name, v_rows, v_last_id, v_last_ts, v_last_hash);
        END IF;
        EXECUTE format('DROP TABLE {s}.%I', r.name);
        dropped_partition := r.name;
        dropped_rows := v_rows;
        anchor_last_id := v_last_id;
        anchor_last_hash := v_last_hash;
        RETURN NEXT;
    END LOOP;
END
$fn$
"""  # noqa: S608


def upgrade() -> None:
    s = _schema()
    op.execute(f"CREATE SEQUENCE {s}.audit_log_id_seq AS bigint")
    op.create_table(
        "audit_log",
        sa.Column(
            "id",
            sa.BigInteger(),
            server_default=sa.text("nextval('audit_log_id_seq'::regclass)"),
            nullable=False,
        ),
        sa.Column("ts", sa.DateTime(timezone=True), nullable=False),
        sa.Column("actor_id", sa.Uuid(), nullable=True),
        sa.Column("actor_username", sa.Text(), nullable=True),
        sa.Column("actor_ip", postgresql.INET(), nullable=True),
        sa.Column("user_agent", sa.Text(), nullable=True),
        sa.Column("session_hash", sa.Text(), nullable=True),
        sa.Column("action", sa.Text(), nullable=False),
        sa.Column("system_id", sa.Text(), nullable=True),
        sa.Column("resource", sa.Text(), nullable=True),
        sa.Column("resource_id", sa.Text(), nullable=True),
        sa.Column("outcome", sa.Text(), nullable=False),
        sa.Column("status_code", sa.Integer(), nullable=True),
        sa.Column("request_id", sa.Text(), nullable=True),
        sa.Column("before", postgresql.JSONB(none_as_null=True), nullable=True),
        sa.Column("after", postgresql.JSONB(none_as_null=True), nullable=True),
        sa.Column(
            "details",
            postgresql.JSONB(),
            server_default=sa.text("'{}'::jsonb"),
            nullable=False,
        ),
        sa.Column("reason", sa.Text(), nullable=True),
        sa.Column("prev_hash", sa.String(length=64), nullable=False),
        sa.Column("hash", sa.String(length=64), nullable=False),
        sa.CheckConstraint(
            "outcome IN ('success', 'denied', 'error')", name=op.f("ck_audit_log_outcome_valid")
        ),
        sa.CheckConstraint(f"hash {_HASH}", name=op.f("ck_audit_log_hash_format")),
        sa.CheckConstraint(f"prev_hash {_HASH}", name=op.f("ck_audit_log_prev_hash_format")),
        sa.PrimaryKeyConstraint("id", "ts", name="pk_audit_log"),
        postgresql_partition_by="RANGE (ts)",
    )
    op.execute(f"ALTER SEQUENCE {s}.audit_log_id_seq OWNED BY {s}.audit_log.id")
    op.create_index("ix_audit_log_actor_id_id", "audit_log", ["actor_id", "id"])
    op.create_index("ix_audit_log_action_id", "audit_log", ["action", "id"])
    op.create_index("ix_audit_log_resource_id", "audit_log", ["resource_id"])
    op.create_index("ix_audit_log_request_id", "audit_log", ["request_id"])

    op.create_table(
        "audit_anchors",
        sa.Column("id", sa.BigInteger(), sa.Identity(always=True), nullable=False),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column("partition_name", sa.Text(), nullable=False),
        sa.Column("rows_dropped", sa.BigInteger(), nullable=False),
        sa.Column("last_id", sa.BigInteger(), nullable=False),
        sa.Column("last_ts", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_hash", sa.String(length=64), nullable=False),
        sa.CheckConstraint(f"last_hash {_HASH}", name=op.f("ck_audit_anchors_last_hash_format")),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_audit_anchors")),
        sa.UniqueConstraint("last_id", name=op.f("uq_audit_anchors_last_id")),
    )

    op.execute(_reject_function(s))
    for table in ("audit_log", "audit_anchors"):
        # Row triggers on a partitioned table are cloned to every partition.
        op.execute(
            f"CREATE TRIGGER {table}_append_only BEFORE UPDATE OR DELETE ON {s}.{table} "
            f"FOR EACH ROW EXECUTE FUNCTION {s}.audit_reject_change()"
        )
        op.execute(
            f"CREATE TRIGGER {table}_no_truncate BEFORE TRUNCATE ON {s}.{table} "
            f"FOR EACH STATEMENT EXECUTE FUNCTION {s}.audit_reject_change()"
        )
    op.execute(_ensure_function(s))
    op.execute(_retention_function(s))
    for signature in (
        "audit_reject_change()",
        "audit_ensure_partition(timestamptz)",
        "audit_drop_expired_partitions(integer)",
    ):
        op.execute(f"REVOKE ALL ON FUNCTION {s}.{signature} FROM PUBLIC")
    # The current and the next month; the daily retention job keeps creating
    # the next one, so the month change never waits for DDL.
    op.execute(
        f"SELECT {s}.audit_ensure_partition(now()), "
        f"{s}.audit_ensure_partition(now() + interval '1 month')"
    )


def downgrade() -> None:
    s = _schema()
    op.execute(f"DROP FUNCTION {s}.audit_drop_expired_partitions(integer)")
    op.execute(f"DROP FUNCTION {s}.audit_ensure_partition(timestamptz)")
    # Dropping the tables drops their partitions, triggers and the sequence.
    op.drop_table("audit_anchors")
    op.drop_table("audit_log")
    op.execute(f"DROP FUNCTION {s}.audit_reject_change()")
