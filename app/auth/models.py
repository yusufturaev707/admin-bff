"""Admin DB tables of the auth module.

Roles, permissions and scopes are added in Phase 2, the audit table in Phase 3.
"""

import re
import uuid
from datetime import datetime
from enum import StrEnum

from sqlalchemy import (
    CheckConstraint,
    String,
    Text,
    func,
    text,
    true,
)
from sqlalchemy.dialects.postgresql import ARRAY
from sqlalchemy.orm import Mapped, mapped_column

from app.core.db import Base

_USERNAME_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{2,63}$")


def normalize_username(value: str) -> str | None:
    """Usernames are case-insensitive: stored and compared in lower case."""
    username = value.strip().lower()
    return username if _USERNAME_RE.fullmatch(username) else None


class AuthMethod(StrEnum):
    PASSWORD = "password"  # noqa: S105 - a method name, not a secret  # nosec B105
    ONEID = "oneid"  # citizen's OneID (+ TOTP)


class AdminUser(Base):
    __tablename__ = "admin_users"
    __table_args__ = (
        CheckConstraint("username = lower(username)", name="username_lowercase"),
        CheckConstraint(
            "cardinality(auth_methods) > 0 AND auth_methods <@ ARRAY['password', 'oneid']::text[]",
            name="auth_methods_valid",
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    username: Mapped[str] = mapped_column(String(64), unique=True)
    full_name: Mapped[str | None] = mapped_column(String(128))

    # Null for an admin who may only sign in with OneID.
    password_hash: Mapped[str | None] = mapped_column(Text)
    password_changed_at: Mapped[datetime | None]
    must_change_password: Mapped[bool] = mapped_column(server_default=true())

    # Which primary methods this admin may use; set by the superadmin.
    auth_methods: Mapped[list[str]] = mapped_column(
        ARRAY(Text), server_default=text("ARRAY['password']::text[]")
    )

    # OneID link: HMAC-SHA256 of the PINFL (lookup) and its masked form (display).
    # The PINFL itself is not stored.
    oneid_pinfl_hash: Mapped[str | None] = mapped_column(String(64), unique=True)
    pinfl_masked: Mapped[str | None] = mapped_column(String(16))

    is_active: Mapped[bool] = mapped_column(server_default=true())
    # Bumped when roles change (Phase 2); sessions carry the version they saw.
    perm_version: Mapped[int] = mapped_column(server_default=text("0"))

    created_at: Mapped[datetime] = mapped_column(server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(server_default=func.now(), onupdate=func.now())
    last_login_at: Mapped[datetime | None]

    def allows(self, method: AuthMethod) -> bool:
        return method.value in self.auth_methods
