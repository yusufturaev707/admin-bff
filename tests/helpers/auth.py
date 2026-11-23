"""Helpers for auth tests: create admins directly in the DB and sign in over HTTP."""

import secrets
import uuid
from collections.abc import Sequence
from dataclasses import dataclass

import httpx
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy.pool import NullPool

from app.auth.crypto import hmac_sha256_hex
from app.auth.models import AdminUser
from app.auth.passwords import PasswordService
from app.core.db import create_sessionmaker, database_url
from app.settings import Settings
from tests.conftest import FakeClock

AUTH = "/api/v1/auth"


@dataclass(frozen=True)
class Admin:
    id: uuid.UUID
    username: str
    password: str


def random_password() -> str:
    return secrets.token_urlsafe(18)


async def create_admin(
    settings: Settings,
    clock: FakeClock,
    *,
    username: str | None = None,
    password: str | None = None,
    must_change_password: bool = False,
    methods: Sequence[str] = ("password",),
    pinfl: str | None = None,
    active: bool = True,
) -> Admin:
    username = username or f"admin_{secrets.token_hex(4)}"
    password = password or random_password()
    passwords = PasswordService(settings)
    user = AdminUser(
        id=uuid.uuid4(),
        username=username,
        password_hash=await passwords.hash(password),
        must_change_password=must_change_password,
        auth_methods=list(methods),
        is_active=active,
    )
    if pinfl is not None:
        user.oneid_pinfl_hash = hmac_sha256_hex(settings.pinfl_key(), pinfl)
    engine = create_async_engine(database_url(settings), poolclass=NullPool)
    try:
        async with create_sessionmaker(engine)() as db, db.begin():
            db.add(user)
    finally:
        await engine.dispose()
    return Admin(id=user.id, username=username, password=password)


async def start_login(client: httpx.AsyncClient, admin: Admin) -> httpx.Response:
    return await client.post(
        f"{AUTH}/login", json={"username": admin.username, "password": admin.password}
    )


async def login(client: httpx.AsyncClient, admin: Admin, clock: FakeClock) -> str:
    """Signs in with the password. Returns the CSRF token."""
    response = await start_login(client, admin)
    assert response.status_code == 200, response.text
    csrf: str = response.json()["csrf_token"]
    return csrf
