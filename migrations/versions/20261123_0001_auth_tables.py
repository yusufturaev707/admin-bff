"""auth tables: admin_users, recovery_codes

Revision ID: 0001
Revises:
Create Date: 2026-11-23
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0001"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def _ts(name: str, *, nullable: bool = True, now: bool = False) -> sa.Column[object]:
    return sa.Column(
        name,
        sa.DateTime(timezone=True),
        nullable=nullable,
        server_default=sa.func.now() if now else None,
    )


def upgrade() -> None:
    op.create_table(
        "admin_users",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("username", sa.String(length=64), nullable=False),
        sa.Column("password_hash", sa.Text(), nullable=True),
        _ts("password_changed_at"),
        sa.Column("must_change_password", sa.Boolean(), server_default=sa.true(), nullable=False),
        sa.Column(
            "auth_methods",
            postgresql.ARRAY(sa.Text()),
            server_default=sa.text("ARRAY['password']::text[]"),
            nullable=False,
        ),
        sa.Column("totp_secret_enc", sa.LargeBinary(), nullable=True),
        _ts("totp_confirmed_at"),
        sa.Column("totp_last_timecode", sa.BigInteger(), nullable=True),
        sa.Column("oneid_pinfl_hash", sa.String(length=64), nullable=True),
        sa.Column("pinfl_masked", sa.String(length=16), nullable=True),
        sa.Column("is_active", sa.Boolean(), server_default=sa.true(), nullable=False),
        sa.Column("perm_version", sa.Integer(), server_default=sa.text("0"), nullable=False),
        _ts("created_at", nullable=False, now=True),
        _ts("updated_at", nullable=False, now=True),
        _ts("last_login_at"),
        sa.CheckConstraint(
            "username = lower(username)", name=op.f("ck_admin_users_username_lowercase")
        ),
        sa.CheckConstraint(
            "cardinality(auth_methods) > 0 AND auth_methods <@ ARRAY['password', 'oneid']::text[]",
            name=op.f("ck_admin_users_auth_methods_valid"),
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_admin_users")),
        sa.UniqueConstraint("username", name=op.f("uq_admin_users_username")),
        sa.UniqueConstraint("oneid_pinfl_hash", name=op.f("uq_admin_users_oneid_pinfl_hash")),
    )
    op.create_table(
        "recovery_codes",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("code_hash", sa.Text(), nullable=False),
        _ts("created_at", nullable=False, now=True),
        _ts("used_at"),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["admin_users.id"],
            name=op.f("fk_recovery_codes_user_id_admin_users"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_recovery_codes")),
    )
    op.create_index(op.f("ix_recovery_codes_user_id"), "recovery_codes", ["user_id"])


def downgrade() -> None:
    op.drop_index(op.f("ix_recovery_codes_user_id"), table_name="recovery_codes")
    op.drop_table("recovery_codes")
    op.drop_table("admin_users")
