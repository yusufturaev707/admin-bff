"""Audit events (section 9).

Phase 1 writes audit events to the structured log only (`audit` logger, JSON to
journald). Phase 3 adds the `audit_log` table with the hash chain as another
`AuditSink`; callers do not change.
"""

import uuid
from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any, Protocol

from app.core.logging import get_logger


class AuditOutcome(StrEnum):
    SUCCESS = "success"
    DENIED = "denied"
    ERROR = "error"


@dataclass(frozen=True, slots=True)
class AuditEvent:
    action: str  # e.g. "auth.login", "auth.lockout"
    outcome: AuditOutcome
    actor_id: uuid.UUID | None = None
    actor_username: str | None = None
    actor_ip: str | None = None
    user_agent: str | None = None
    session_hash: str | None = None
    request_id: str | None = None
    # Never secrets (passwords, codes, tokens); personal data only masked.
    details: Mapping[str, Any] = field(default_factory=dict)


class AuditSink(Protocol):
    async def write(self, event: AuditEvent) -> None: ...


class LogAuditSink:
    """Writes audit events to the `audit` logger."""

    def __init__(self) -> None:
        self._logger = get_logger("audit")

    async def write(self, event: AuditEvent) -> None:
        self._logger.info(
            "audit",
            action=event.action,
            outcome=str(event.outcome),
            actor_id=str(event.actor_id) if event.actor_id else None,
            actor_username=event.actor_username,
            actor_ip=event.actor_ip,
            user_agent=event.user_agent,
            session_hash=event.session_hash,
            audit_request_id=event.request_id,
            details=dict(event.details),
        )
