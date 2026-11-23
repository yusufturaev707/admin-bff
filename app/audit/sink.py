"""Audit events (section 9).

Callers build an `AuditEvent` and hand it to the app's `AuditSink`
(`app.state.audit_sink`). In the running service that is
`app.audit.writer.DbAuditSink`: it appends the event to the hash-chained
`audit_log` table and writes a copy to the `audit` logger (JSON -> journald),
so the trail also exists outside the database.
"""

import uuid
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from typing import Any, Protocol

from app.core.logging import get_logger
from app.core.time import isoformat_z


class AuditOutcome(StrEnum):
    SUCCESS = "success"
    DENIED = "denied"
    ERROR = "error"


@dataclass(frozen=True, slots=True)
class AuditEvent:
    """Never secrets (passwords, codes, tokens). Personal data is masked by the
    writer as well, but callers pass it masked in the first place."""

    action: str  # e.g. "auth.login", "admin.user.create"
    outcome: AuditOutcome
    actor_id: uuid.UUID | None = None
    actor_username: str | None = None
    actor_ip: str | None = None
    user_agent: str | None = None
    session_hash: str | None = None
    request_id: str | None = None
    # Which system and object the action concerns. `system_id` defaults to the
    # first segment of `action` ("auth.login" -> "auth").
    system_id: str | None = None
    resource: str | None = None
    resource_id: str | None = None
    status_code: int | None = None
    # State of the object before and after a change (JSON-like values).
    before: object = None
    after: object = None
    # Why the admin did it; required for dangerous actions (section 9).
    reason: str | None = None
    details: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class StoredAudit:
    """Where an event ended up in the chain."""

    id: int
    ts: datetime
    hash: str


class AuditSink(Protocol):
    async def write(self, event: AuditEvent) -> None: ...


class LogAuditSink:
    """Writes audit events to the `audit` logger: the copy of the trail that
    leaves the database (journald, then syslog or Loki)."""

    def __init__(self) -> None:
        self._logger = get_logger("audit")

    async def write(self, event: AuditEvent) -> None:
        self.log(
            {
                "action": event.action,
                "outcome": str(event.outcome),
                "actor_id": str(event.actor_id) if event.actor_id else None,
                "actor_username": event.actor_username,
                "actor_ip": event.actor_ip,
                "user_agent": event.user_agent,
                "session_hash": event.session_hash,
                "request_id": event.request_id,
                "system_id": event.system_id,
                "resource": event.resource,
                "resource_id": event.resource_id,
                "status_code": event.status_code,
                "before": event.before,
                "after": event.after,
                "reason": event.reason,
                "details": dict(event.details),
            }
        )

    def log(
        self,
        fields: Mapping[str, Any],
        *,
        stored: StoredAudit | None = None,
        error: str | None = None,
    ) -> None:
        """`stored` names the chain record (its hash lets the two copies be
        compared); `error` says that the database write failed."""
        # The request id of the HTTP request is bound to every log line already;
        # the event's own one is kept under another key.
        record = {("audit_request_id" if k == "request_id" else k): v for k, v in fields.items()}
        if stored is not None:
            record.update(audit_id=stored.id, audit_ts=isoformat_z(stored.ts), hash=stored.hash)
        if error is not None:
            self._logger.error("audit", stored=False, error=error, **record)
        else:
            self._logger.info("audit", **record)
