"""Request and response models of /api/v1/admin/regions and /organizations."""

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field


class _Request(BaseModel):
    model_config = ConfigDict(extra="forbid")


class RegionOut(BaseModel):
    id: int
    name: str
    dtm_id: int | None
    p_code: str | None
    status: bool = Field(description="true: faol")
    created_at: datetime
    updated_at: datetime


class RegionCreate(_Request):
    model_config = ConfigDict(
        extra="forbid",
        json_schema_extra={
            "example": {"name": "Toshkent shahri", "dtm_id": 26, "p_code": "26", "status": True}
        },
    )

    name: str = Field(min_length=2, max_length=128)
    dtm_id: int | None = Field(default=None, ge=1, description="DTM tizimlaridagi id")
    p_code: str | None = Field(default=None, min_length=1, max_length=32)
    status: bool = True


class RegionUpdate(_Request):
    """Only the fields that are sent are changed. `dtm_id` and `p_code` may be
    cleared with null, `name` and `status` may not."""

    name: str | None = Field(default=None, min_length=2, max_length=128)
    dtm_id: int | None = Field(default=None, ge=1)
    p_code: str | None = Field(default=None, min_length=1, max_length=32)
    status: bool | None = None


class OrganizationOut(BaseModel):
    id: int
    name: str
    region_id: int
    status: bool = Field(description="true: faol")
    created_at: datetime
    updated_at: datetime


class OrganizationCreate(_Request):
    model_config = ConfigDict(
        extra="forbid",
        json_schema_extra={"example": {"name": "1-son test markazi", "region_id": 1}},
    )

    name: str = Field(min_length=2, max_length=255)
    region_id: int = Field(ge=1)
    status: bool = True


class OrganizationUpdate(_Request):
    """Only the fields that are sent are changed; none of them may be null."""

    name: str | None = Field(default=None, min_length=2, max_length=255)
    region_id: int | None = Field(default=None, ge=1)
    status: bool | None = None
