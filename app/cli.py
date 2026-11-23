"""Command line interface: `uv run python -m app.cli <command>`.

Commands:
    export-openapi     writes the OpenAPI snapshot (openapi/v1.json); with --check
                       only compares and exits with 1 if the snapshot is outdated.
    create-superadmin  creates the first admin; the password is asked interactively.
                       There is no HTTP endpoint for this (section 6).
    unlock-login       lifts a login lockout of a username and/or an IP early.

Later phases add: sync-permissions, rotate-keys, verify-audit.
"""

import argparse
import asyncio
import getpass
import json
import sys
from collections.abc import Sequence
from pathlib import Path

from sqlalchemy import select

from app.audit.sink import AuditEvent, AuditOutcome, LogAuditSink
from app.auth.lockout import LoginLimiter
from app.auth.models import AdminUser, AuthMethod, normalize_username
from app.auth.passwords import PasswordPolicyError, PasswordService, check_password_policy
from app.core.db import create_engine, create_sessionmaker
from app.core.redis import create_redis
from app.settings import Settings, load_settings

DEFAULT_OPENAPI_PATH = Path("openapi/v1.json")


def _out(message: str) -> None:
    sys.stdout.write(message + "\n")


def _err(message: str) -> None:
    sys.stderr.write(message + "\n")


def build_openapi_document() -> str:
    """Renders the OpenAPI schema deterministically (independent of the environment)."""
    from app.main import create_app

    settings = Settings(_env_file=None, app_env="test", log_level="WARNING")
    schema = create_app(settings).openapi()
    return json.dumps(schema, indent=2, ensure_ascii=False, sort_keys=False) + "\n"


def _export_openapi(args: argparse.Namespace) -> int:
    path: Path = args.output
    document = build_openapi_document()
    if args.check:
        current = path.read_text(encoding="utf-8") if path.exists() else ""
        if current != document:
            sys.stderr.write(
                f"OpenAPI snapshot {path} eskirgan. Yangilash: "
                "uv run python -m app.cli export-openapi\n"
            )
            return 1
        return 0
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(document, encoding="utf-8", newline="\n")
    return 0


async def create_superadmin(username_raw: str) -> int:
    username = normalize_username(username_raw)
    if username is None:
        _err(
            "Foydalanuvchi nomi noto'g'ri: 3-64 belgi, kichik lotin harflari, "
            "raqamlar, '.', '_' yoki '-'."
        )
        return 2
    password = getpass.getpass("Parol: ")
    if password != getpass.getpass("Parolni takrorlang: "):
        _err("Parollar mos kelmadi.")
        return 1
    try:
        check_password_policy(password, username=username)
    except PasswordPolicyError as exc:
        _err(exc.message)
        return 1

    settings = load_settings()
    engine = create_engine(settings)
    try:
        async with create_sessionmaker(engine)() as db, db.begin():
            if await db.scalar(select(AdminUser.id).where(AdminUser.username == username)):
                _err(f"'{username}' nomli admin allaqachon mavjud.")
                return 1
            user = AdminUser(
                username=username,
                password_hash=await PasswordService(settings).hash(password),
                # Section 6: every new admin changes the password and enrolls
                # TOTP at the first sign-in.
                must_change_password=True,
                auth_methods=[AuthMethod.PASSWORD.value],
            )
            db.add(user)
        await LogAuditSink().write(
            AuditEvent(
                action="admin.superadmin.create",
                outcome=AuditOutcome.SUCCESS,
                actor_username="cli",
                details={"user_id": str(user.id), "username": username},
            )
        )
    finally:
        await engine.dispose()
    _out(
        f"Admin '{username}' yaratildi. Birinchi kirishda TOTP ulanadi va parol "
        "almashtiriladi. Superadmin roli 2-bosqichda (RBAC) biriktiriladi."
    )
    return 0


def _create_superadmin(args: argparse.Namespace) -> int:
    return asyncio.run(create_superadmin(args.username))


async def unlock_login(username_raw: str | None, ip: str | None) -> int:
    username = normalize_username(username_raw) if username_raw else None
    if username_raw and username is None:
        _err("Foydalanuvchi nomi noto'g'ri.")
        return 2
    if not username and not ip:
        _err("--username yoki --ip kerak.")
        return 2
    settings = load_settings()
    redis = create_redis(settings)
    try:
        removed = await LoginLimiter(redis, prefix=settings.redis_key_prefix).unlock(
            username=username, ip=ip
        )
    finally:
        await redis.aclose()
    await LogAuditSink().write(
        AuditEvent(
            action="auth.unlock",
            outcome=AuditOutcome.SUCCESS,
            actor_username="cli",
            details={"username": username, "ip": ip, "removed_keys": removed},
        )
    )
    _out("Blok olib tashlandi." if removed else "Faol blok topilmadi.")
    return 0


def _unlock_login(args: argparse.Namespace) -> int:
    return asyncio.run(unlock_login(args.username, args.ip))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="python -m app.cli", description="Admin BFF CLI")
    commands = parser.add_subparsers(dest="command", required=True)

    export = commands.add_parser("export-openapi", help="OpenAPI snapshot'ini yozish")
    export.add_argument("--output", type=Path, default=DEFAULT_OPENAPI_PATH)
    export.add_argument("--check", action="store_true", help="faqat solishtirish")
    export.set_defaults(handler=_export_openapi)

    superadmin = commands.add_parser("create-superadmin", help="birinchi adminni yaratish")
    superadmin.add_argument("--username", required=True)
    superadmin.set_defaults(handler=_create_superadmin)

    unlock = commands.add_parser("unlock-login", help="login blokini muddatidan oldin ochish")
    unlock.add_argument("--username")
    unlock.add_argument("--ip")
    unlock.set_defaults(handler=_unlock_login)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    exit_code: int = args.handler(args)
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
