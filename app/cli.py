"""Command line interface: `uv run python -m app.cli <command>`.

Commands:
    export-openapi     writes the OpenAPI snapshot (openapi/v1.json); with --check
                       only compares and exits with 1 if the snapshot is outdated.
    create-superadmin  creates the first admin; the password is asked interactively.
                       There is no HTTP endpoint for this (section 6).
    unlock-login       lifts a login lockout of a username and/or an IP early.
    reencrypt-totp     after a TOTP_ENC_KEY rotation, re-encrypts every TOTP
                       secret with the current key (docs/security.md).
    reset-totp         clears TOTP and recovery codes of one admin (--username)
                       or of everyone (--all --yes, if TOTP_ENC_KEY is lost);
                       they enroll again at the next sign-in.

Later phases add: sync-permissions, rotate-keys, verify-audit.
"""

import argparse
import asyncio
import getpass
import json
import sys
from collections.abc import Sequence
from pathlib import Path

from sqlalchemy import delete, select

from app.audit.sink import AuditEvent, AuditOutcome, LogAuditSink
from app.auth.crypto import DecryptionError, SecretBox
from app.auth.lockout import LoginLimiter
from app.auth.models import AdminUser, AuthMethod, RecoveryCode, normalize_username
from app.auth.passwords import PasswordPolicyError, PasswordService, check_password_policy
from app.auth.sessions import SessionStore
from app.core.db import create_engine, create_sessionmaker
from app.core.redis import create_redis
from app.core.time import utcnow
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


async def reencrypt_totp() -> int:
    settings = load_settings()
    box = SecretBox(settings.totp_key(), previous=settings.totp_previous_keys())
    updated = unchanged = 0
    failed: list[str] = []
    engine = create_engine(settings)
    try:
        async with create_sessionmaker(engine)() as db, db.begin():
            users = await db.scalars(
                select(AdminUser).where(AdminUser.totp_secret_enc.is_not(None))
            )
            for user in users.all():
                blob = user.totp_secret_enc
                if blob is None or box.is_current(blob):
                    unchanged += 1
                    continue
                try:
                    secret = box.decrypt(blob, aad=user.id.bytes)
                except DecryptionError:
                    failed.append(user.username)
                    continue
                user.totp_secret_enc = box.encrypt(secret, aad=user.id.bytes)
                updated += 1
    finally:
        await engine.dispose()
    await LogAuditSink().write(
        AuditEvent(
            action="auth.totp.reencrypt",
            outcome=AuditOutcome.ERROR if failed else AuditOutcome.SUCCESS,
            actor_username="cli",
            details={"updated": updated, "unchanged": unchanged, "failed": failed},
        )
    )
    _out(f"Qayta shifrlandi: {updated}, o'zgarmadi: {unchanged}, ochib bo'lmadi: {len(failed)}.")
    if failed:
        _err(
            "Bu adminlarning TOTP secret'ini sozlangan kalitlar bilan ochib bo'lmadi: "
            f"{', '.join(failed)}. TOTP_ENC_KEY_PREVIOUS'ni tekshiring yoki ular uchun "
            "reset-totp bajaring."
        )
        return 1
    return 0


def _reencrypt_totp(args: argparse.Namespace) -> int:
    return asyncio.run(reencrypt_totp())


async def reset_totp(username_raw: str | None, *, everyone: bool, confirmed: bool) -> int:
    if everyone and not confirmed:
        _err("--all barcha adminlarning TOTP'ini o'chiradi: tasdiqlash uchun --yes qo'shing.")
        return 2
    username = normalize_username(username_raw) if username_raw else None
    if everyone == bool(username_raw) or (username_raw and username is None):
        _err("--username <login> yoki --all --yes kerak.")
        return 2

    settings = load_settings()
    engine = create_engine(settings)
    redis = create_redis(settings)
    try:
        async with create_sessionmaker(engine)() as db, db.begin():
            query = select(AdminUser)
            if not everyone:
                query = query.where(AdminUser.username == username)
            users = list((await db.scalars(query)).all())
            if not users:
                _err("Admin topilmadi.")
                return 1
            for user in users:
                user.totp_secret_enc = None
                user.totp_confirmed_at = None
                user.totp_last_timecode = None
            await db.execute(
                delete(RecoveryCode).where(RecoveryCode.user_id.in_([u.id for u in users]))
            )
        # Existing sessions were created with the old second factor: end them.
        sessions = SessionStore(
            redis,
            prefix=settings.redis_key_prefix,
            idle_timeout_s=settings.session_idle_timeout_s,
            absolute_timeout_s=settings.session_absolute_timeout_s,
            clock=utcnow,
        )
        for user in users:
            await sessions.delete_all_for_user(user.id)
    finally:
        await redis.aclose()
        await engine.dispose()
    await LogAuditSink().write(
        AuditEvent(
            action="auth.totp.reset",
            outcome=AuditOutcome.SUCCESS,
            actor_username="cli",
            details={"all": everyone, "usernames": [u.username for u in users]},
        )
    )
    _out(
        f"{len(users)} ta adminning TOTP'i o'chirildi, sessiyalari tugatildi. "
        "Ular keyingi kirishda TOTP'ni qaytadan ulaydi."
    )
    return 0


def _reset_totp(args: argparse.Namespace) -> int:
    return asyncio.run(reset_totp(args.username, everyone=args.all, confirmed=args.yes))


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

    reencrypt = commands.add_parser(
        "reencrypt-totp", help="TOTP secret'larini joriy TOTP_ENC_KEY bilan qayta shifrlash"
    )
    reencrypt.set_defaults(handler=_reencrypt_totp)

    reset = commands.add_parser("reset-totp", help="adminning TOTP'ini o'chirish (qayta ulash)")
    reset.add_argument("--username")
    reset.add_argument("--all", action="store_true", help="barcha adminlar (kalit yo'qolganda)")
    reset.add_argument("--yes", action="store_true", help="--all ni tasdiqlash")
    reset.set_defaults(handler=_reset_totp)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    exit_code: int = args.handler(args)
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
