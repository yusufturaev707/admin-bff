"""Time helpers.

Every timestamp in the BFF is timezone-aware UTC. Naive datetimes caused bugs in
the past (`datetime.now()` vs UTC), so ruff's DTZ rules forbid them and the
helpers below reject them. `Asia/Tashkent` is used only for display.
"""

from datetime import UTC, datetime


def utcnow() -> datetime:
    return datetime.now(UTC)


def ensure_utc(value: datetime) -> datetime:
    """Converts an aware datetime to UTC; rejects naive ones."""
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("naive datetime is not allowed, use timezone-aware UTC")
    return value.astimezone(UTC)


def isoformat_z(value: datetime) -> str:
    """ISO 8601 in UTC with a `Z` suffix, e.g. `2026-11-20T09:15:02Z`."""
    return ensure_utc(value).isoformat().replace("+00:00", "Z")
