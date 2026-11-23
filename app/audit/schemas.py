"""Response and request models of /api/v1/audit."""

import uuid
from datetime import datetime
from typing import Any, Self

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, model_validator

from app.audit.models import AuditRecord
from app.audit.service import AuditFilters
from app.audit.sink import AuditOutcome
from app.core.errors import field_error

USERNAME_MAX = 64
SYSTEM_MAX = 64
ACTION_MAX = 128
RESOURCE_MAX = 64
RESOURCE_ID_MAX = 256
REQUEST_ID_MAX = 64


class AuditEntry(BaseModel):
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "id": "1042",
                "ts": "2026-11-23T09:15:02.123456Z",
                "actor_id": "7d1c2f0e-1b2a-4c3d-9e8f-0a1b2c3d4e5f",
                "actor_username": "superadmin",
                "actor_ip": "10.20.30.40",
                "user_agent": "Mozilla/5.0",
                "session_hash": "9f2c...e1",
                "action": "admin.user.roles",
                "system_id": "admin",
                "resource": "users",
                "resource_id": "0b9c5e1e-3f7a-4d43-9a43-6f1a2b9d8c11",
                "outcome": "success",
                "status_code": None,
                "request_id": "5b0c9a7e-7c41-4f43-8c5e-2f3c1d0e9a87",
                "reason": None,
                "before": ["auditor"],
                "after": ["auditor", "operator"],
                "details": {},
            }
        }
    )

    id: str = Field(description="Yozuv raqami (string)")
    ts: datetime = Field(description="UTC")
    actor_id: uuid.UUID | None
    actor_username: str | None
    actor_ip: str | None
    user_agent: str | None
    session_hash: str | None = Field(description="Sessiya ID'sining SHA-256 hash'i")
    action: str = Field(description="Masalan `auth.login`, `admin.user.create`, `http.request`")
    system_id: str | None
    resource: str | None
    resource_id: str | None
    outcome: AuditOutcome
    status_code: int | None = Field(description="Faqat so'rov darajasidagi yozuvlarda")
    request_id: str | None
    reason: str | None
    before: Any = Field(default=None, description="O'zgarishdan oldin (PII maskalangan)")
    after: Any = Field(default=None, description="O'zgarishdan keyin (PII maskalangan)")
    details: dict[str, Any]

    @classmethod
    def from_record(cls, record: AuditRecord) -> Self:
        return cls(
            id=str(record.id),
            ts=record.ts,
            actor_id=record.actor_id,
            actor_username=record.actor_username,
            actor_ip=str(record.actor_ip) if record.actor_ip is not None else None,
            user_agent=record.user_agent,
            session_hash=record.session_hash,
            action=record.action,
            system_id=record.system_id,
            resource=record.resource,
            resource_id=record.resource_id,
            outcome=AuditOutcome(record.outcome),
            status_code=record.status_code,
            request_id=record.request_id,
            reason=record.reason,
            before=record.before,
            after=record.after,
            details=record.details,
        )


INVALID_RANGE = "`to` `from`dan keyin bo'lishi kerak"


def check_query_range(since: datetime | None, until: datetime | None) -> None:
    if since is not None and until is not None and since >= until:
        raise field_error(("query", "to"), "invalid_range", INVALID_RANGE)


class AuditExportRequest(BaseModel):
    """The same filters as the list; all optional. `from` is inclusive, `to` exclusive."""

    model_config = ConfigDict(
        extra="forbid",
        populate_by_name=True,
        json_schema_extra={
            "example": {
                "action": "auth.login",
                "outcome": "denied",
                "from": "2026-11-01T00:00:00Z",
                "to": "2026-11-23T00:00:00Z",
            }
        },
    )

    actor_id: uuid.UUID | None = None
    actor_username: str | None = Field(default=None, min_length=1, max_length=USERNAME_MAX)
    system_id: str | None = Field(default=None, min_length=1, max_length=SYSTEM_MAX)
    action: str | None = Field(default=None, min_length=1, max_length=ACTION_MAX)
    outcome: AuditOutcome | None = None
    resource: str | None = Field(default=None, min_length=1, max_length=RESOURCE_MAX)
    resource_id: str | None = Field(default=None, min_length=1, max_length=RESOURCE_ID_MAX)
    request_id: str | None = Field(default=None, min_length=1, max_length=REQUEST_ID_MAX)
    since: AwareDatetime | None = Field(default=None, alias="from")
    until: AwareDatetime | None = Field(default=None, alias="to")

    @model_validator(mode="after")
    def _range(self) -> Self:
        if self.since is not None and self.until is not None and self.since >= self.until:
            raise ValueError(INVALID_RANGE)
        return self

    def filters(self) -> AuditFilters:
        return AuditFilters(
            actor_id=self.actor_id,
            actor_username=self.actor_username.lower() if self.actor_username else None,
            system_id=self.system_id,
            action=self.action,
            outcome=self.outcome,
            resource=self.resource,
            resource_id=self.resource_id,
            request_id=self.request_id,
            since=self.since,
            until=self.until,
        )
