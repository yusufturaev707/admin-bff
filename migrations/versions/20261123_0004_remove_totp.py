"""remove TOTP: admin_users.totp_* columns and the recovery_codes table

Revision ID: 0004
Revises: 0003
Create Date: 2026-11-23

The owner removed TOTP (2026-11-23): sign-in is username and password, or
OneID. The encrypted TOTP secrets and the recovery code hashes are dropped.
A downgrade recreates the empty columns and table only; the data is gone.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0004"
down_revision: str | None = "0003"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.drop_index(op.f("ix_recovery_codes_user_id"), table_name="recovery_codes")
    op.drop_table("recovery_codes")
    op.drop_column("admin_users", "totp_last_timecode")
    op.drop_column("admin_users", "totp_confirmed_at")
    op.drop_column("admin_users", "totp_secret_enc")


def downgrade() -> None:
    op.add_column("admin_users", sa.Column("totp_secret_enc", sa.LargeBinary(), nullable=True))
    op.add_column(
        "admin_users", sa.Column("totp_confirmed_at", sa.DateTime(timezone=True), nullable=True)
    )
    op.add_column("admin_users", sa.Column("totp_last_timecode", sa.BigInteger(), nullable=True))
    op.create_table(
        "recovery_codes",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("code_hash", sa.Text(), nullable=False),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column("used_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["admin_users.id"],
            name=op.f("fk_recovery_codes_user_id_admin_users"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_recovery_codes")),
    )
    op.create_index(op.f("ix_recovery_codes_user_id"), "recovery_codes", ["user_id"])
