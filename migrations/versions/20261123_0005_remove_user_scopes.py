"""remove the user_scopes table (row-level scopes are not used)

Revision ID: 0005
Revises: 0004
Create Date: 2026-11-23

The owner removed admin scopes (region, zone, branch) on 2026-11-23: every
admin works in one central building. A downgrade recreates the empty table.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0005"
down_revision: str | None = "0004"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.drop_table("user_scopes")


def downgrade() -> None:
    op.create_table(
        "user_scopes",
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("scope_type", sa.String(length=16), nullable=False),
        sa.Column("scope_value", sa.String(length=64), nullable=False),
        sa.CheckConstraint(
            "scope_type IN ('region', 'zone', 'branch')",
            name=op.f("ck_user_scopes_scope_type_valid"),
        ),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["admin_users.id"],
            name=op.f("fk_user_scopes_user_id_admin_users"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint(
            "user_id", "scope_type", "scope_value", name=op.f("pk_user_scopes")
        ),
    )
