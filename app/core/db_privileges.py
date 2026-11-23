"""Privileges of the application DB role (sections 9 and 11).

Production uses two roles:

* the owner (DB_OWNER_USER) owns the schema and runs the migrations;
* the application (DB_USER) gets only what it needs. In particular it may only
  SELECT and INSERT `audit_log` and only SELECT `audit_anchors`: it can neither
  change nor delete audit records, and it cannot drop partitions (DDL is the
  owner's). Retention and partition creation go through the owner's SECURITY
  DEFINER functions, which are the only functions it may execute.

`grant_app_privileges` runs after every `alembic upgrade` (migrations/env.py)
when the two roles differ. It is idempotent and revokes anything not listed, so
a new table gets the default privileges automatically and a restricted one
never keeps more than it should.

`audit_privilege_problems` is the check at startup: in production the service
refuses to start if its role could modify the audit tables (owner, superuser
or an extra grant).
"""

from sqlalchemy import Connection, text
from sqlalchemy.ext.asyncio import AsyncEngine

DEFAULT_TABLE_PRIVILEGES: tuple[str, ...] = ("SELECT", "INSERT", "UPDATE", "DELETE")
RESTRICTED_TABLES: dict[str, tuple[str, ...]] = {
    "audit_log": ("SELECT", "INSERT"),
    "audit_anchors": ("SELECT",),
    "alembic_version": (),
}
# Columns the application may not set on INSERT: they take their default, so
# it cannot pick the id of an audit record (column-level INSERT privilege).
DEFAULT_ONLY_COLUMNS: dict[str, tuple[str, ...]] = {"audit_log": ("id",)}
APP_SEQUENCES: tuple[str, ...] = ("audit_log_id_seq",)
APP_FUNCTIONS: tuple[str, ...] = (
    "audit_ensure_partition(timestamptz)",
    "audit_drop_expired_partitions(integer)",
)
AUDIT_TABLES: tuple[str, ...] = ("audit_log", "audit_anchors")

_COLUMNS = text(
    """
    SELECT a.attname
    FROM pg_attribute a
    JOIN pg_class c ON c.oid = a.attrelid
    JOIN pg_namespace n ON n.oid = c.relnamespace
    WHERE n.nspname = current_schema() AND c.relname = :table
      AND a.attnum > 0 AND NOT a.attisdropped
    ORDER BY a.attnum
    """
)
_TABLES = text(
    """
    SELECT c.relname, c.relispartition
    FROM pg_class c
    JOIN pg_namespace n ON n.oid = c.relnamespace
    WHERE n.nspname = current_schema() AND c.relkind IN ('r', 'p')
    ORDER BY c.relname
    """
)


def grant_app_privileges(connection: Connection, role: str) -> list[str]:
    """Run as the owner. Returns the statements it executed."""
    quote = connection.dialect.identifier_preparer.quote
    schema = connection.execute(text("SELECT current_schema()")).scalar_one()
    s, r = quote(schema), quote(role)
    statements = [
        f"GRANT USAGE ON SCHEMA {s} TO {r}",
        f"REVOKE ALL ON ALL SEQUENCES IN SCHEMA {s} FROM {r}",
        f"REVOKE ALL ON ALL FUNCTIONS IN SCHEMA {s} FROM {r}",
    ]
    for name, is_partition in connection.execute(_TABLES).all():
        table = f"{s}.{quote(name)}"
        statements.append(f"REVOKE ALL ON TABLE {table} FROM {r}")
        # Partitions are reached through their parent only.
        privileges = () if is_partition else RESTRICTED_TABLES.get(name, DEFAULT_TABLE_PRIVILEGES)
        default_only = DEFAULT_ONLY_COLUMNS.get(name, ())
        if default_only and "INSERT" in privileges:
            columns = [
                quote(c)
                for c in connection.execute(_COLUMNS, {"table": name}).scalars()
                if c not in default_only
            ]
            statements.append(f"GRANT INSERT ({', '.join(columns)}) ON TABLE {table} TO {r}")
            privileges = tuple(p for p in privileges if p != "INSERT")
        if privileges:
            statements.append(f"GRANT {', '.join(privileges)} ON TABLE {table} TO {r}")
    statements += [f"GRANT USAGE ON SEQUENCE {s}.{quote(n)} TO {r}" for n in APP_SEQUENCES]
    statements += [f"GRANT EXECUTE ON FUNCTION {s}.{f} TO {r}" for f in APP_FUNCTIONS]
    for statement in statements:
        connection.execute(text(statement))
    return statements


_PRIVILEGE_CHECK = text(
    """
    SELECT
        pg_has_role(current_user, c.relowner, 'USAGE') AS owns,
        has_any_column_privilege(c.oid, 'UPDATE') AS can_update,
        has_table_privilege(c.oid, 'DELETE') AS can_delete,
        has_table_privilege(c.oid, 'TRUNCATE') AS can_truncate,
        c.relname <> 'audit_log' AND has_any_column_privilege(c.oid, 'INSERT') AS can_insert
    FROM pg_class c
    WHERE c.oid = to_regclass(:name)
    """
)


async def audit_privilege_problems(engine: AsyncEngine) -> list[str]:
    """What the application role could do to the audit tables beyond appending."""
    problems: list[str] = []
    async with engine.connect() as conn:
        for table in AUDIT_TABLES:
            row = (await conn.execute(_PRIVILEGE_CHECK, {"name": table})).mappings().first()
            if row is None:
                problems.append(f"{table}: table is missing (run alembic upgrade head)")
                continue
            if row["owns"]:
                problems.append(f"{table}: the application role owns it (or is a superuser)")
                continue
            problems += [
                f"{table}: the application role has {privilege.upper()}"
                for privilege in ("update", "delete", "truncate", "insert")
                if row[f"can_{privilege}"]
            ]
    return problems
