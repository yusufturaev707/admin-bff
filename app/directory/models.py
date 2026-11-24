"""Regions and organizations. A user (app.auth.models.User) may belong to one
organization and one region.

Integer ids (owner's decision, 2026-11-24): reference data, compared with
other systems' region numbers. `status` is true for an active record.
Neither can be deleted while something refers to it (ON DELETE RESTRICT).
"""

from datetime import datetime

from sqlalchemy import ForeignKey, Identity, Integer, String, UniqueConstraint, func, true
from sqlalchemy.orm import Mapped, mapped_column

from app.core.db import Base


class Region(Base):
    __tablename__ = "regions"

    id: Mapped[int] = mapped_column(Integer, Identity(), primary_key=True)
    name: Mapped[str] = mapped_column(String(128), unique=True)
    # The region's id in the DTM (now UZBMB) systems, for matching their data.
    dtm_id: Mapped[int | None] = mapped_column(Integer, unique=True)
    p_code: Mapped[str | None] = mapped_column(String(32))
    status: Mapped[bool] = mapped_column(server_default=true())
    created_at: Mapped[datetime] = mapped_column(server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(server_default=func.now(), onupdate=func.now())


class Organization(Base):
    __tablename__ = "organizations"
    # The same name may exist in two regions, not twice in one.
    __table_args__ = (
        UniqueConstraint("region_id", "name", name="uq_organizations_region_id_name"),
    )

    id: Mapped[int] = mapped_column(Integer, Identity(), primary_key=True)
    name: Mapped[str] = mapped_column(String(255))
    region_id: Mapped[int] = mapped_column(
        ForeignKey("regions.id", ondelete="RESTRICT"), index=True
    )
    status: Mapped[bool] = mapped_column(server_default=true())
    created_at: Mapped[datetime] = mapped_column(server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(server_default=func.now(), onupdate=func.now())
