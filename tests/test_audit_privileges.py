"""The application DB role may only append to the audit log (sections 9 and 11).

These tests create a temporary role, grant it the application privileges the
way migrations/env.py does and use it like the service would. They need a DB
user with CREATEROLE (CI has it); without one they are skipped, visibly.
"""

import secrets
from collections.abc import AsyncIterator
from dataclasses import dataclass

import asyncpg
import pytest
from pydantic import SecretStr
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy.pool import NullPool

from app.audit.writer import DbAuditSink
from app.core.db import database_url
from app.core.db_privileges import audit_privilege_problems, grant_app_privileges
from app.main import create_app
from app.settings import Settings
from tests.audit_helpers import event, month_partition, records, sessions, write_events
from tests.auth_helpers import login
from tests.conftest import AuditRecorder, FakeClock, Services
from tests.helpers import app_client
from tests.rbac_helpers import make_superadmin


@dataclass(frozen=True)
class AppRole:
    name: str
    password: str

    def settings(self, base: Settings, **changes: object) -> Settings:
        return base.model_copy(
            update={"db_user": self.name, "db_password": SecretStr(self.password), **changes}
        )


async def _grant(settings: Settings, role: str) -> list[str]:
    engine = create_async_engine(database_url(settings), poolclass=NullPool)
    try:
        async with engine.begin() as conn:
            return await conn.run_sync(grant_app_privileges, role)
    finally:
        await engine.dispose()


@pytest.fixture
async def app_role(services: Services, settings: Settings) -> AsyncIterator[AppRole]:
    role = AppRole(f"admin_bff_test_app_{secrets.token_hex(4)}", secrets.token_hex(16))
    await services.reset()
    conn = await services.pg_connect()
    try:
        try:
            # Both values are generated hex: safe to inline into the DDL.
            await conn.execute(f"CREATE ROLE {role.name} LOGIN PASSWORD '{role.password}'")
        except asyncpg.InsufficientPrivilegeError:
            pytest.skip("the test DB user lacks CREATEROLE (README, 'Testlar')")
        try:
            await _grant(settings, role.name)
            yield role
        finally:
            for kind in ("TABLES", "SEQUENCES", "FUNCTIONS"):
                await conn.execute(f"REVOKE ALL ON ALL {kind} IN SCHEMA public FROM {role.name}")
            await conn.execute(f"REVOKE ALL ON SCHEMA public FROM {role.name}")
            await conn.execute(f"DROP ROLE {role.name}")
    finally:
        await conn.close()
        await services.reset()


@pytest.fixture
def role_settings(settings: Settings, app_role: AppRole) -> Settings:
    return app_role.settings(settings)


async def _as_role(role_settings: Settings) -> asyncpg.Connection:
    return await asyncpg.connect(
        host=role_settings.db_host,
        port=role_settings.db_port,
        user=role_settings.db_user,
        password=role_settings.db_password.get_secret_value() if role_settings.db_password else "",
        database=role_settings.db_name,
    )


async def test_app_role_appends_but_cannot_change_the_audit_log(
    role_settings: Settings, settings: Settings, clock: FakeClock
) -> None:
    await write_events(role_settings, clock, 2)  # through the writer, as the app does
    rows = await records(settings)
    assert len(rows) == 2
    partition = month_partition(rows[0].ts)
    conn = await _as_role(role_settings)
    try:
        for sql in (
            "UPDATE audit_log SET actor_username = 'x'",
            "DELETE FROM audit_log",
            "TRUNCATE audit_log",
            f"DROP TABLE {partition}",
            f"SELECT * FROM {partition}",  # noqa: S608 - partitions only via the parent
            f"ALTER TABLE {partition} DISABLE TRIGGER audit_log_append_only",
            "UPDATE audit_anchors SET rows_dropped = 0",
            "INSERT INTO audit_anchors (partition_name, rows_dropped, last_id, last_ts, "
            "last_hash) VALUES ('x', 0, 0, now(), repeat('0', 64))",
            # The id comes from the sequence: the app cannot choose one.
            f"INSERT INTO audit_log (id, ts, action, outcome, prev_hash, hash) VALUES "  # noqa: S608
            f"({rows[0].id}, now(), 'x', 'success', repeat('0', 64), repeat('0', 64))",
            "SELECT setval('audit_log_id_seq', 1)",
        ):
            with pytest.raises(asyncpg.InsufficientPrivilegeError):
                await conn.execute(sql)
        # The SECURITY DEFINER functions are callable, within their limits.
        assert await conn.fetchval("SELECT audit_ensure_partition(now())") == month_partition(
            rows[0].ts
        )
        with pytest.raises(asyncpg.RaiseError, match="at least 90 days"):
            await conn.fetch("SELECT * FROM audit_drop_expired_partitions(1)")
        assert await conn.fetch("SELECT * FROM audit_drop_expired_partitions(90)") == []
    finally:
        await conn.close()
    assert [r.hash for r in await records(settings)] == [r.hash for r in rows]


async def test_app_role_has_full_access_to_the_other_tables(role_settings: Settings) -> None:
    conn = await _as_role(role_settings)
    try:
        for table in ("admin_users", "roles", "permissions", "role_permissions", "user_roles"):
            for privilege in ("SELECT", "INSERT", "UPDATE", "DELETE"):
                assert await conn.fetchval(
                    "SELECT has_table_privilege($1, $2)", table, privilege
                ), (table, privilege)
            assert not await conn.fetchval("SELECT has_table_privilege($1, 'TRUNCATE')", table)
        assert not await conn.fetchval("SELECT has_table_privilege('alembic_version', 'SELECT')")
    finally:
        await conn.close()


async def test_granting_again_revokes_extra_privileges(
    services: Services, settings: Settings, app_role: AppRole
) -> None:
    role_settings = app_role.settings(settings)
    conn = await services.pg_connect()
    try:
        await conn.execute(f"GRANT UPDATE, TRUNCATE ON audit_log TO {app_role.name}")
    finally:
        await conn.close()
    engine = create_async_engine(database_url(role_settings), poolclass=NullPool)
    try:
        assert await audit_privilege_problems(engine) == [
            "audit_log: the application role has UPDATE",
            "audit_log: the application role has TRUNCATE",
        ]
        statements = await _grant(settings, app_role.name)
        assert any(s.startswith("GRANT INSERT (ts, ") for s in statements)
        assert await audit_privilege_problems(engine) == []
    finally:
        await engine.dispose()


async def test_the_owner_role_is_reported(settings: Settings) -> None:
    engine = create_async_engine(database_url(settings), poolclass=NullPool)
    try:
        assert await audit_privilege_problems(engine) == [
            "audit_log: the application role owns it (or is a superuser)",
            "audit_anchors: the application role owns it (or is a superuser)",
        ]
    finally:
        await engine.dispose()


async def test_production_refuses_to_start_as_the_owner(settings: Settings) -> None:
    production = settings.model_copy(
        update={"app_env": "production", "argon2_time_cost": 2, "argon2_memory_cost_kib": 19456}
    )
    app = create_app(production)
    with pytest.raises(RuntimeError, match="can modify the audit log"):
        async with app.router.lifespan_context(app):
            pass


async def test_production_refuses_to_start_without_the_database(settings: Settings) -> None:
    production = settings.model_copy(
        update={
            "app_env": "production",
            "argon2_time_cost": 2,
            "argon2_memory_cost_kib": 19456,
            "db_name": f"missing_{secrets.token_hex(4)}",
        }
    )
    app = create_app(production)
    with pytest.raises(RuntimeError, match="cannot check the DB privileges"):
        async with app.router.lifespan_context(app):
            pass


async def test_development_only_warns_without_the_database(settings: Settings) -> None:
    app = create_app(settings.model_copy(update={"db_name": f"missing_{secrets.token_hex(4)}"}))
    async with app.router.lifespan_context(app):
        pass


async def test_production_starts_with_the_restricted_role(
    role_settings: Settings, clock: FakeClock
) -> None:
    production = role_settings.model_copy(
        update={"app_env": "production", "argon2_time_cost": 2, "argon2_memory_cost_kib": 19456}
    )
    async with app_client(create_app(production, clock=clock)) as client:
        assert (await client.get("/ready")).status_code == 200


async def test_the_service_works_with_the_restricted_role(
    role_settings: Settings, settings: Settings, clock: FakeClock
) -> None:
    """Sign-in and an admin change, all audited, with only the app privileges."""
    superadmin = await make_superadmin(settings, clock)
    recorder = AuditRecorder()
    async with app_client(create_app(role_settings, clock=clock, audit_listeners=[recorder])) as c:
        csrf = await login(c, superadmin, clock)
        response = await c.post(
            "/api/v1/admin/roles",
            json={"name": "auditor", "description": "", "permissions": ["audit:logs:read"]},
            headers={"X-CSRF-Token": csrf},
        )
        assert response.status_code == 201, response.text
        listed = await c.get("/api/v1/audit", params={"action": "admin.role.create"})
        assert listed.status_code == 200
        assert [i["after"]["name"] for i in listed.json()["items"]] == ["auditor"]
    assert {e.action for e in recorder.events} >= {"auth.login", "admin.role.create"}
    async with sessions(role_settings) as db:
        await DbAuditSink(db, clock=clock).write(event())
