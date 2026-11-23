"""Command line interface: `uv run python -m app.cli <command>`.

Commands:
    export-openapi     writes the OpenAPI snapshot (openapi/v1.json); with --check
                       only compares and exits with 1 if the snapshot is outdated.
    create-superadmin  creates a superadmin (role `superadmin`, every scope); the
                       password is asked interactively. --existing promotes an
                       existing admin. There is no HTTP endpoint for this.
    sync-permissions   copies the permission registry to the DB (after deploy).
    unlock-login       lifts a login lockout of a username and/or an IP early.
    reencrypt-totp     after a TOTP_ENC_KEY rotation, re-encrypts every TOTP
                       secret with the current key (docs/security.md).
    reset-totp         clears TOTP and recovery codes of one admin (--username)
                       or of everyone (--all --yes, if TOTP_ENC_KEY is lost);
                       they enroll again at the next sign-in.
    verify-audit       checks the audit hash chain; exits with 1 if it is broken.
    audit-retention    daily (systemd timer): creates the next audit partition
                       and drops whole partitions older than AUDIT_RETENTION_DAYS.

Every command that changes something is audited like a request (actor "cli",
plus the operating system user who ran it).

Phase 4 adds: rotate-keys.
"""

import argparse
import asyncio
import dataclasses
import getpass
import json
import os
import sys
import uuid
from collections.abc import Sequence
from pathlib import Path

from redis.asyncio import Redis
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.audit.sink import AuditEvent, AuditOutcome
from app.audit.verify import apply_retention, verify_chain
from app.audit.writer import DbAuditSink
from app.auth.crypto import DecryptionError, SecretBox
from app.auth.lockout import LoginLimiter
from app.auth.models import AdminUser, AuthMethod, RecoveryCode, normalize_username
from app.auth.passwords import PasswordPolicyError, PasswordService, check_password_policy
from app.auth.sessions import SessionStore
from app.core.db import create_engine, create_sessionmaker
from app.core.redis import create_redis
from app.core.time import utcnow
from app.rbac.models import (
    SCOPE_ALL,
    SUPERADMIN_ROLE,
    Permission,
    Role,
    RolePermission,
    ScopeType,
    UserRole,
    UserScope,
)
from app.rbac.permissions import ALL_PERMISSIONS
from app.rbac.registry import build_registry
from app.settings import Settings, load_settings

DEFAULT_OPENAPI_PATH = Path("openapi/v1.json")


def _out(message: str) -> None:
    sys.stdout.write(message + "\n")


def _err(message: str) -> None:
    sys.stderr.write(message + "\n")


def _os_user() -> str | None:
    """Who ran the command: the sudo caller rather than root, if known."""
    try:
        return os.environ.get("SUDO_USER") or getpass.getuser()
    except (OSError, KeyError):  # no name for the uid (e.g. a bare container)
        return None


async def _audit(settings: Settings, event: AuditEvent) -> None:
    """Appends a CLI event to the audit chain (and its journald copy)."""
    event = dataclasses.replace(
        event, actor_username="cli", details={**event.details, "os_user": _os_user()}
    )
    engine = create_engine(settings)
    try:
        await DbAuditSink(create_sessionmaker(engine), clock=utcnow).write(event)
    finally:
        await engine.dispose()


def _sessions(settings: Settings, redis: Redis) -> SessionStore:
    return SessionStore(
        redis,
        prefix=settings.redis_key_prefix,
        idle_timeout_s=settings.session_idle_timeout_s,
        absolute_timeout_s=settings.session_absolute_timeout_s,
        clock=utcnow,
    )


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


async def _superadmin_role(db: AsyncSession) -> Role:
    """The seeded system role (section 7): all permissions, `*:*:*`."""
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
        raise RuntimeError(f"role {SUPERADMIN_ROLE!r} exists but is not the system role")
    await db.execute(
        delete(RolePermission).where(
            RolePermission.role_id == role.id, RolePermission.permission != ALL_PERMISSIONS
        )
    )
    if not await db.scalar(
        select(RolePermission.role_id).where(
            RolePermission.role_id == role.id, RolePermission.permission == ALL_PERMISSIONS
        )
    ):
        db.add(RolePermission(role_id=role.id, permission=ALL_PERMISSIONS))
    return role


async def _grant_superadmin(db: AsyncSession, user: AdminUser) -> None:
    role = await _superadmin_role(db)
    if not await db.scalar(
        select(UserRole.user_id).where(UserRole.user_id == user.id, UserRole.role_id == role.id)
    ):
        db.add(UserRole(user_id=user.id, role_id=role.id))
    for scope_type in ScopeType:
        if not await db.scalar(
            select(UserScope.user_id).where(
                UserScope.user_id == user.id,
                UserScope.scope_type == scope_type.value,
                UserScope.scope_value == SCOPE_ALL,
            )
        ):
            db.add(UserScope(user_id=user.id, scope_type=scope_type.value, scope_value=SCOPE_ALL))
    user.perm_version += 1


async def create_superadmin(username_raw: str, *, existing: bool = False) -> int:
    username = normalize_username(username_raw)
    if username is None:
        _err(
            "Foydalanuvchi nomi noto'g'ri: 3-64 belgi, kichik lotin harflari, "
            "raqamlar, '.', '_' yoki '-'."
        )
        return 2
    settings = load_settings()
    engine = create_engine(settings)
    try:
        # Checked before asking for a password, so nobody types one in vain.
        async with create_sessionmaker(engine)() as db:
            found = await db.scalar(select(AdminUser.id).where(AdminUser.username == username))
        if existing and found is None:
            _err(f"'{username}' nomli admin topilmadi.")
            return 1
        if not existing and found is not None:
            _err(
                f"'{username}' nomli admin allaqachon mavjud. Uni superadmin qilish "
                "uchun: create-superadmin --username ... --existing"
            )
            return 1
        password: str | None = None
        if not existing:
            password = getpass.getpass("Parol: ")
            if password != getpass.getpass("Parolni takrorlang: "):
                _err("Parollar mos kelmadi.")
                return 1
            try:
                check_password_policy(password, username=username)
            except PasswordPolicyError as exc:
                _err(exc.message)
                return 1
        async with create_sessionmaker(engine)() as db, db.begin():
            user = await db.scalar(select(AdminUser).where(AdminUser.username == username))
            if user is None:
                if password is None:  # pragma: no cover - creation always asks for one
                    raise RuntimeError("no password for a new superadmin")
                user = AdminUser(
                    id=uuid.uuid4(),
                    username=username,
                    password_hash=await PasswordService(settings).hash(password),
                    # Section 6: every new admin changes the password and enrolls
                    # TOTP at the first sign-in.
                    must_change_password=True,
                    auth_methods=[AuthMethod.PASSWORD.value],
                    perm_version=0,
                )
                db.add(user)
                await db.flush()
            await _grant_superadmin(db, user)
        if existing:
            # The admin's rights changed: its sessions end (section 6).
            redis = create_redis(settings)
            try:
                await _sessions(settings, redis).delete_all_for_user(user.id)
            finally:
                await redis.aclose()
        await _audit(
            settings,
            AuditEvent(
                action="admin.superadmin.create",
                outcome=AuditOutcome.SUCCESS,
                system_id="admin",
                resource="users",
                resource_id=str(user.id),
                details={"username": username, "existing": existing},
            ),
        )
    finally:
        await engine.dispose()
    if existing:
        _out(f"'{username}' superadmin qilindi (barcha huquqlar va hududlar).")
    else:
        _out(
            f"Superadmin '{username}' yaratildi. Birinchi kirishda TOTP ulanadi va parol "
            "almashtiriladi."
        )
    return 0


def _create_superadmin(args: argparse.Namespace) -> int:
    return asyncio.run(create_superadmin(args.username, existing=args.existing))


async def sync_permissions() -> int:
    """Copies the permission registry to the `permissions` table (section 7).
    Permissions that are no longer declared are removed, together with role
    grants of exactly those codes; wildcard grants stay."""
    registry = build_registry()
    declared = {spec.code: spec for spec in registry}
    settings = load_settings()
    engine = create_engine(settings)
    try:
        async with create_sessionmaker(engine)() as db, db.begin():
            stored = {p.code: p for p in (await db.scalars(select(Permission))).all()}
            added = sorted(set(declared) - set(stored))
            removed = sorted(set(stored) - set(declared))
            updated: list[str] = []
            for code, spec in declared.items():
                row = stored.get(code)
                if row is None:
                    db.add(
                        Permission(
                            code=code, system_id=spec.system_id, description=spec.description
                        )
                    )
                elif (row.system_id, row.description) != (spec.system_id, spec.description):
                    row.system_id, row.description = spec.system_id, spec.description
                    updated.append(code)
            if removed:
                await db.execute(
                    delete(RolePermission).where(RolePermission.permission.in_(removed))
                )
                await db.execute(delete(Permission).where(Permission.code.in_(removed)))
            await _superadmin_role(db)
    finally:
        await engine.dispose()
    await _audit(
        settings,
        AuditEvent(
            action="rbac.permissions.sync",
            outcome=AuditOutcome.SUCCESS,
            system_id="admin",
            resource="permissions",
            details={"added": added, "updated": updated, "removed": removed},
        ),
    )
    _out(
        f"Permission'lar: {len(declared)} ta, yangi {len(added)}, o'zgargan {len(updated)}, "
        f"o'chirilgan {len(removed)}."
    )
    for code in removed:
        _out(f"  o'chirildi: {code}")
    return 0


def _sync_permissions(args: argparse.Namespace) -> int:
    return asyncio.run(sync_permissions())


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
    await _audit(
        settings,
        AuditEvent(
            action="auth.unlock",
            outcome=AuditOutcome.SUCCESS,
            details={"username": username, "ip": ip, "removed_keys": removed},
        ),
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
    await _audit(
        settings,
        AuditEvent(
            action="auth.totp.reencrypt",
            outcome=AuditOutcome.ERROR if failed else AuditOutcome.SUCCESS,
            details={"updated": updated, "unchanged": unchanged, "failed": failed},
        ),
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
        sessions = _sessions(settings, redis)
        for user in users:
            await sessions.delete_all_for_user(user.id)
    finally:
        await redis.aclose()
        await engine.dispose()
    await _audit(
        settings,
        AuditEvent(
            action="auth.totp.reset",
            outcome=AuditOutcome.SUCCESS,
            details={"all": everyone, "usernames": [u.username for u in users]},
        ),
    )
    _out(
        f"{len(users)} ta adminning TOTP'i o'chirildi, sessiyalari tugatildi. "
        "Ular keyingi kirishda TOTP'ni qaytadan ulaydi."
    )
    return 0


def _reset_totp(args: argparse.Namespace) -> int:
    return asyncio.run(reset_totp(args.username, everyone=args.all, confirmed=args.yes))


async def verify_audit() -> int:
    settings = load_settings()
    engine = create_engine(settings)
    try:
        result = await verify_chain(create_sessionmaker(engine))
    finally:
        await engine.dispose()
    start = f"anchor #{result.anchor_id} dan" if result.anchor_id else "boshidan"
    if result.ok:
        _out(f"Audit zanjiri butun: {result.checked} ta yozuv tekshirildi ({start}).")
        if result.last_id is not None:
            _out(f"Oxirgi yozuv: id={result.last_id}, hash={result.last_hash}")
            _out("Uni journald'dagi nusxa bilan solishtiring (docs/security.md).")
    else:
        _err(f"XATO: audit zanjiri buzilgan ({start} tekshirildi):")
        for problem in result.problems:
            _err(f"  id={problem.record_id} [{problem.kind}]: {problem.message}")
    await _audit(
        settings,
        AuditEvent(
            action="audit.chain.verify",
            outcome=AuditOutcome.SUCCESS if result.ok else AuditOutcome.ERROR,
            resource="logs",
            details={
                "checked": result.checked,
                "anchor_id": result.anchor_id,
                "first_id": result.first_id,
                "last_id": result.last_id,
                "last_hash": result.last_hash,
                "problems": [{"id": p.record_id, "kind": p.kind} for p in result.problems],
            },
        ),
    )
    return 0 if result.ok else 1


def _verify_audit(args: argparse.Namespace) -> int:
    return asyncio.run(verify_audit())


async def audit_retention() -> int:
    settings = load_settings()
    engine = create_engine(settings)
    try:
        dropped = await apply_retention(
            create_sessionmaker(engine), retention_days=settings.audit_retention_days
        )
    finally:
        await engine.dispose()
    for partition in dropped:
        await _audit(
            settings,
            AuditEvent(
                action="audit.partition.drop",
                outcome=AuditOutcome.SUCCESS,
                resource="partitions",
                resource_id=partition.name,
                details={
                    "rows": partition.rows,
                    "anchor_last_id": partition.last_id,
                    "anchor_last_hash": partition.last_hash,
                    "retention_days": settings.audit_retention_days,
                },
            ),
        )
        _out(f"O'chirildi: {partition.name} ({partition.rows} ta yozuv)")
    _out(
        f"Audit retention ({settings.audit_retention_days} kun): "
        f"{len(dropped)} ta partition o'chirildi."
    )
    return 0


def _audit_retention(args: argparse.Namespace) -> int:
    return asyncio.run(audit_retention())


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="python -m app.cli", description="Admin BFF CLI")
    commands = parser.add_subparsers(dest="command", required=True)

    export = commands.add_parser("export-openapi", help="OpenAPI snapshot'ini yozish")
    export.add_argument("--output", type=Path, default=DEFAULT_OPENAPI_PATH)
    export.add_argument("--check", action="store_true", help="faqat solishtirish")
    export.set_defaults(handler=_export_openapi)

    superadmin = commands.add_parser("create-superadmin", help="superadmin yaratish")
    superadmin.add_argument("--username", required=True)
    superadmin.add_argument(
        "--existing", action="store_true", help="mavjud adminni superadmin qilish (parolsiz)"
    )
    superadmin.set_defaults(handler=_create_superadmin)

    sync = commands.add_parser("sync-permissions", help="permission'larni DB bilan sinxronlash")
    sync.set_defaults(handler=_sync_permissions)

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

    verify = commands.add_parser("verify-audit", help="audit hash zanjirini tekshirish")
    verify.set_defaults(handler=_verify_audit)

    retention = commands.add_parser(
        "audit-retention", help="eski audit partition'larini o'chirish (har kuni, systemd timer)"
    )
    retention.set_defaults(handler=_audit_retention)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    exit_code: int = args.handler(args)
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
