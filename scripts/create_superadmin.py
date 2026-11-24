"""Creates a superadmin: the only way to get the first one (CLAUDE.md section 6).

    uv run python -m scripts.create_superadmin --username admin

* The password is asked twice on the terminal, never taken from arguments or
  the environment. The new admin changes it at the first sign-in.
* The `superadmin` system role (`*:*:*`) is created if it does not exist yet.
* The creation is audited: actor `script`, plus the operating system user who
  ran it.

On a server it runs as root with the service's settings and credentials
(README, "Superadmin").
"""

import argparse
import asyncio
import getpass
import os
import sys
import uuid
from collections.abc import Sequence

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.audit.sink import AuditEvent, AuditOutcome
from app.audit.writer import DbAuditSink
from app.auth.models import AuthMethod, User, normalize_username
from app.auth.passwords import PasswordPolicyError, PasswordService, check_password_policy
from app.core.db import create_engine, create_sessionmaker, database_revision, migration_heads
from app.core.time import utcnow
from app.rbac.models import SUPERADMIN_ROLE, Role, RolePermission, UserRole
from app.rbac.permissions import ALL_PERMISSIONS
from app.settings import Settings, load_settings


class ScriptError(Exception):
    """A message for the operator (Uzbek); the script exits with 1."""


def _os_user() -> str | None:
    """Who ran the script: the sudo caller rather than root, if known."""
    try:
        return os.environ.get("SUDO_USER") or getpass.getuser()
    except (OSError, KeyError):  # no name for the uid
        return None


async def _superadmin_role(db: AsyncSession) -> Role:
    role = await db.scalar(select(Role).where(Role.name == SUPERADMIN_ROLE))
    if role is None:
        role = Role(
            id=uuid.uuid4(),
            name=SUPERADMIN_ROLE,
            description="Barcha tizimlarda barcha huquqlar (tizim roli)",
            is_system=True,
        )
        db.add(role)
        await db.flush()
    elif not role.is_system:
        raise ScriptError(f"'{SUPERADMIN_ROLE}' nomli rol bor, lekin u tizim roli emas")
    granted = await db.scalar(
        select(RolePermission.role_id).where(
            RolePermission.role_id == role.id, RolePermission.permission == ALL_PERMISSIONS
        )
    )
    if granted is None:
        db.add(RolePermission(role_id=role.id, permission=ALL_PERMISSIONS))
    return role


async def create_superadmin(settings: Settings, username: str, password: str) -> uuid.UUID:
    """Creates the admin with the superadmin role and returns its id.
    `username` must already be normalised. Raises ScriptError."""
    try:
        check_password_policy(password, username=username)
    except PasswordPolicyError as exc:
        raise ScriptError(exc.message) from exc
    engine = create_engine(settings)
    try:
        if await database_revision(engine) not in migration_heads():
            raise ScriptError("Baza sxemasi eskirgan. Avval: uv run alembic upgrade head")
        password_hash = await PasswordService(settings).hash(password)
        async with create_sessionmaker(engine)() as db, db.begin():
            if await db.scalar(select(User.id).where(User.username == username)):
                raise ScriptError(f"'{username}' nomli admin allaqachon bor")
            role = await _superadmin_role(db)
            user = User(
                id=uuid.uuid4(),
                username=username,
                password_hash=password_hash,
                # Section 6: every new admin changes the password at the first sign-in.
                must_change_password=True,
                auth_methods=[AuthMethod.PASSWORD.value],
            )
            db.add(user)
            await db.flush()
            db.add(UserRole(user_id=user.id, role_id=role.id))
        await DbAuditSink(create_sessionmaker(engine), clock=utcnow).write(
            AuditEvent(
                action="admin.superadmin.create",
                outcome=AuditOutcome.SUCCESS,
                actor_username="script",
                system_id="admin",
                resource="users",
                resource_id=str(user.id),
                details={"username": username, "os_user": _os_user()},
            )
        )
    finally:
        await engine.dispose()
    return user.id


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m scripts.create_superadmin", description="Superadmin yaratish"
    )
    parser.add_argument("--username", required=True)
    args = parser.parse_args(argv)
    username = normalize_username(args.username)
    if username is None:
        sys.stderr.write(
            "Foydalanuvchi nomi noto'g'ri: 3-64 belgi, kichik lotin harflari, "
            "raqamlar, '.', '_' yoki '-'.\n"
        )
        return 2
    password = getpass.getpass("Parol: ")
    if password != getpass.getpass("Parolni takrorlang: "):
        sys.stderr.write("Parollar mos kelmadi.\n")
        return 1
    try:
        asyncio.run(create_superadmin(load_settings(), username, password))
    except ScriptError as exc:
        sys.stderr.write(f"{exc}\n")
        return 1
    sys.stdout.write(
        f"Superadmin '{username}' yaratildi. Birinchi kirishda parol almashtiriladi.\n"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
