"""The audit hash chain (section 9).

    hash = sha256(prev_hash + canonical_json(row))

`row` is every stored column except `id`, `prev_hash` and `hash`. The order of
the chain is the order of `id` (appends are serialised by an advisory lock), and
`ts` never decreases along it. The first record of the chain follows
`GENESIS_HASH`; after the retention job has dropped old partitions, the first
remaining record follows the newest anchor (`audit_anchors.last_hash`).

`AuditRow` is the normalised form of a record. It is built from an event when a
record is written and from the database when the chain is verified, and both
must give the same canonical JSON. Hence the normalisation before writing:

* text: NUL characters removed (PostgreSQL rejects them), invalid surrogates
  replaced, lengths capped;
* JSON values: only str, int, bool, null, lists and objects with string keys;
  floats become strings (jsonb would turn `1e+16` into an integer), UUIDs and
  datetimes become strings, sets become sorted lists;
* personal data: sensitive keys (password, token, ...) redacted and PINFL,
  phone and passport numbers masked, exactly like in the logs;
* IP addresses: canonical text form, or null if the value is not an address.
"""

import hashlib
import ipaddress
import json
import uuid
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import Enum
from typing import Any, Self

from app.audit.models import AuditRecord
from app.audit.sink import AuditEvent
from app.core.logging import redact_value
from app.core.pii import scrub_text
from app.core.time import ensure_utc, isoformat_z

GENESIS_HASH = "0" * 64

MAX_TEXT = 2000
MAX_ITEMS = 1000
MAX_DEPTH = 8
_LIMITS = {
    "actor_username": 128,
    "user_agent": 256,
    "session_hash": 128,
    "action": 128,
    "system_id": 64,
    "resource": 64,
    "resource_id": 256,
    "request_id": 64,
    "reason": MAX_TEXT,
}

type JsonValue = str | int | bool | list[JsonValue] | dict[str, JsonValue] | None


def clean_text(value: str, max_len: int = MAX_TEXT) -> str:
    """Text that PostgreSQL accepts and that survives a round trip unchanged."""
    cleaned = value.replace("\x00", "").encode("utf-8", "replace").decode("utf-8")
    return cleaned[:max_len]


def _optional_text(value: object, name: str) -> str | None:
    if value is None:
        return None
    return clean_text(str(value), _LIMITS[name])


def format_ts(value: datetime) -> str:
    """Always with microseconds, so the text does not depend on the value."""
    return ensure_utc(value).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def canonical_ip(value: object) -> str | None:
    """`10.20.30.40`, `2001:db8::1`, `::ffff:10.0.0.1`; None for anything that is
    not an address (e.g. "unknown" when the client address is missing).

    The text is part of the hashed row, so it must not depend on the Python
    version: 3.13 prints an IPv4-mapped IPv6 address as `::ffff:10.0.0.1`, 3.12
    as `::ffff:a00:1`. It is always written in the dotted form."""
    if value is None:
        return None
    raw = str(value).split("%", 1)[0]  # an IPv6 zone id cannot be stored
    try:
        ip = ipaddress.ip_interface(raw).ip
    except ValueError:
        return None
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        return f"::ffff:{ip.ipv4_mapped}"
    return str(ip)


def normalize_json(value: object, depth: int = 0) -> JsonValue:
    """Plain JSON that jsonb gives back unchanged (see the module docstring)."""
    if depth > MAX_DEPTH:
        return "[too deep]"
    if isinstance(value, Enum):
        value = value.value
    if value is None:
        return None
    if isinstance(value, bool):
        return value
    if isinstance(value, int):
        return int(value)
    if isinstance(value, str):
        return clean_text(value)
    if isinstance(value, float):
        return repr(value)
    if isinstance(value, datetime):
        return isoformat_z(value)
    if isinstance(value, uuid.UUID):
        return str(value)
    if isinstance(value, Mapping):
        items = list(value.items())[:MAX_ITEMS]
        return {clean_text(str(k), 128): normalize_json(v, depth + 1) for k, v in items}
    if isinstance(value, set | frozenset):
        return [normalize_json(v, depth + 1) for v in sorted(value, key=str)[:MAX_ITEMS]]
    if isinstance(value, list | tuple):
        return [normalize_json(v, depth + 1) for v in value[:MAX_ITEMS]]
    return clean_text(str(value))


def _private_json(value: object) -> JsonValue:
    redacted: JsonValue = redact_value(normalize_json(value))
    return redacted


def _private_resource_id(value: object) -> str | None:
    """Resource ids are identifiers, but a connector might use a PINFL as one:
    masked like any text unless it is a UUID."""
    text = _optional_text(value, "resource_id")
    if text is None:
        return None
    try:
        uuid.UUID(text)
    except ValueError:
        return scrub_text(text)
    return text


def canonical_json(fields: Mapping[str, Any]) -> str:
    return json.dumps(
        fields, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    )


def chain_hash(prev_hash: str, fields: Mapping[str, Any]) -> str:
    return hashlib.sha256((prev_hash + canonical_json(fields)).encode("utf-8")).hexdigest()


@dataclass(frozen=True, slots=True)
class AuditRow:
    """One record of the chain, normalised (module docstring)."""

    ts: datetime
    actor_id: uuid.UUID | None
    actor_username: str | None
    actor_ip: str | None
    user_agent: str | None
    session_hash: str | None
    action: str
    system_id: str | None
    resource: str | None
    resource_id: str | None
    outcome: str
    status_code: int | None
    request_id: str | None
    before: JsonValue
    after: JsonValue
    details: dict[str, JsonValue]
    reason: str | None

    @classmethod
    def from_event(cls, event: AuditEvent, ts: datetime) -> Self:
        details = _private_json(event.details)
        user_agent = _optional_text(event.user_agent, "user_agent")
        reason = _optional_text(event.reason, "reason")
        return cls(
            ts=ensure_utc(ts),
            actor_id=event.actor_id,
            actor_username=_optional_text(event.actor_username, "actor_username"),
            actor_ip=canonical_ip(event.actor_ip),
            user_agent=scrub_text(user_agent) if user_agent is not None else None,
            session_hash=_optional_text(event.session_hash, "session_hash"),
            action=clean_text(event.action, _LIMITS["action"]),
            system_id=_optional_text(event.system_id or event.action.split(".", 1)[0], "system_id"),
            resource=_optional_text(event.resource, "resource"),
            resource_id=_private_resource_id(event.resource_id),
            outcome=str(event.outcome),
            status_code=event.status_code,
            request_id=_optional_text(event.request_id, "request_id"),
            before=_private_json(event.before),
            after=_private_json(event.after),
            details=details if isinstance(details, dict) else {"value": details},
            reason=scrub_text(reason) if reason is not None else None,
        )

    @classmethod
    def from_record(cls, record: AuditRecord) -> Self:
        """As stored: the values were normalised when they were written."""
        return cls(
            ts=record.ts.astimezone(UTC),
            actor_id=record.actor_id,
            actor_username=record.actor_username,
            actor_ip=canonical_ip(record.actor_ip),
            user_agent=record.user_agent,
            session_hash=record.session_hash,
            action=record.action,
            system_id=record.system_id,
            resource=record.resource,
            resource_id=record.resource_id,
            outcome=record.outcome,
            status_code=record.status_code,
            request_id=record.request_id,
            before=record.before,
            after=record.after,
            details=record.details,
            reason=record.reason,
        )

    def columns(self) -> dict[str, Any]:
        """Values for INSERT."""
        return {
            "ts": self.ts,
            "actor_id": self.actor_id,
            "actor_username": self.actor_username,
            "actor_ip": self.actor_ip,
            "user_agent": self.user_agent,
            "session_hash": self.session_hash,
            "action": self.action,
            "system_id": self.system_id,
            "resource": self.resource,
            "resource_id": self.resource_id,
            "outcome": self.outcome,
            "status_code": self.status_code,
            "request_id": self.request_id,
            "before": self.before,
            "after": self.after,
            "details": self.details,
            "reason": self.reason,
        }

    def canonical_fields(self) -> dict[str, Any]:
        """JSON-ready values: what the hash covers."""
        fields = self.columns()
        fields["ts"] = format_ts(self.ts)
        fields["actor_id"] = str(self.actor_id) if self.actor_id is not None else None
        return fields

    def chain_hash(self, prev_hash: str) -> str:
        return chain_hash(prev_hash, self.canonical_fields())
