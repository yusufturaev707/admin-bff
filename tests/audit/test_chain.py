"""Hash chain unit tests: normalisation, privacy and the canonical form (section 9)."""

import json
import uuid
from datetime import UTC, datetime, timedelta, timezone
from enum import StrEnum

import pytest

from app.audit.chain import (
    GENESIS_HASH,
    MAX_DEPTH,
    MAX_ITEMS,
    AuditRow,
    canonical_ip,
    canonical_json,
    chain_hash,
    clean_text,
    format_ts,
    normalize_json,
)
from app.audit.context import RequestAudit
from app.audit.middleware import needs_record, outcome_for_status, system_for_path
from app.audit.sink import AuditEvent, AuditOutcome
from app.core.logging import REDACTED

TS = datetime(2026, 11, 23, 9, 15, 2, 123456, tzinfo=UTC)


class Color(StrEnum):
    RED = "red"


class Thing:
    def __str__(self) -> str:
        return "thing"


def test_clean_text_removes_nul_and_surrogates_and_caps_length() -> None:
    assert clean_text("a\x00b") == "ab"
    assert clean_text("x\udcffy") == "x?y"
    assert clean_text("abcdef", 3) == "abc"
    assert clean_text("O'zbekiston o\u02bbg\u02bbil") == "O'zbekiston o\u02bbg\u02bbil"


def test_format_ts_always_has_microseconds_and_z() -> None:
    assert format_ts(TS) == "2026-11-23T09:15:02.123456Z"
    assert format_ts(TS.replace(microsecond=0)) == "2026-11-23T09:15:02.000000Z"
    tashkent = timezone(timedelta(hours=5))
    assert format_ts(TS.astimezone(tashkent)) == "2026-11-23T09:15:02.123456Z"
    with pytest.raises(ValueError, match="naive"):
        format_ts(TS.replace(tzinfo=None))


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("10.20.30.40", "10.20.30.40"),
        ("10.20.30.40/32", "10.20.30.40"),
        ("2001:0db8:0000::0001", "2001:db8::1"),
        ("fe80::1%eth0", "fe80::1"),
        ("::ffff:10.0.0.1", "::ffff:10.0.0.1"),
        ("unknown", None),
        ("", None),
        (None, None),
    ],
)
def test_canonical_ip(raw: str | None, expected: str | None) -> None:
    assert canonical_ip(raw) == expected


def test_normalize_json_gives_plain_json_that_jsonb_keeps() -> None:
    user_id = uuid.uuid4()
    value = {
        "uuid": user_id,
        "when": TS,
        "ratio": 1e16,
        "enum": Color.RED,
        "tags": {"b", "a"},
        "pair": (1, True),
        "none": None,
        "nested": {"k\x00": "v\x00"},
        3: "int key",
        "obj": Thing(),  # anything else becomes its str()
    }
    normalized = normalize_json(value)
    assert isinstance(normalized, dict)
    assert normalized["uuid"] == str(user_id)
    assert normalized["when"] == "2026-11-23T09:15:02.123456Z"
    assert normalized["ratio"] == "1e+16"  # jsonb would turn the float 1e16 into an int
    assert normalized["enum"] == "red"
    assert normalized["tags"] == ["a", "b"]
    assert normalized["pair"] == [1, True]
    assert normalized["none"] is None
    assert normalized["nested"] == {"k": "v"}
    assert normalized["3"] == "int key"
    assert normalized["obj"] == "thing"
    json.dumps(normalized, allow_nan=False)  # plain JSON


def test_normalize_json_limits_depth_and_size() -> None:
    deep: object = "leaf"
    for _ in range(MAX_DEPTH + 3):
        deep = [deep]
    flat = normalize_json(deep)
    for _ in range(MAX_DEPTH + 1):
        assert isinstance(flat, list)
        flat = flat[0]
    assert flat == "[too deep]"
    assert len(normalize_json(list(range(MAX_ITEMS + 50)))) == MAX_ITEMS  # type: ignore[arg-type]


def test_canonical_json_is_deterministic() -> None:
    a = canonical_json({"b": 1, "a": "o\u02bb", "c": [None, True]})
    b = canonical_json({"c": [None, True], "a": "o\u02bb", "b": 1})
    assert a == b == '{"a":"o\u02bb","b":1,"c":[null,true]}'
    assert chain_hash(GENESIS_HASH, {"a": 1}) == chain_hash(GENESIS_HASH, {"a": 1})
    assert chain_hash(GENESIS_HASH, {"a": 1}) != chain_hash("1" * 64, {"a": 1})
    assert chain_hash(GENESIS_HASH, {"a": 1}) != chain_hash(GENESIS_HASH, {"a": 2})


def _event(**changes: object) -> AuditEvent:
    base: dict[str, object] = {
        "action": "admin.user.update",
        "outcome": AuditOutcome.SUCCESS,
        "actor_id": uuid.uuid4(),
        "actor_username": "superadmin",
        "actor_ip": "10.20.30.40",
        "user_agent": "Mozilla/5.0",
        "session_hash": "ab" * 32,
        "request_id": str(uuid.uuid4()),
    }
    base.update(changes)
    return AuditEvent(**base)  # type: ignore[arg-type]


def test_row_masks_personal_data_and_redacts_secrets() -> None:
    row = AuditRow.from_event(
        _event(
            user_agent="agent 31201234560045",
            reason="telefon +998 90 123 45 45 so'radi",
            resource_id="31201234560045",
            before={"pinfl": "31201234560045", "password": "hunter2-hunter2"},
            after={"phone": "+998901234545", "passport": "AB1234567"},
            details={"token": "abc", "note": "PINFL 31201234560045", "list": ["AB1234567"]},
        ),
        TS,
    )
    assert row.user_agent == "agent 3120*****0045"
    assert row.reason == "telefon +998 90 *** ** 45 so'radi"
    assert row.resource_id == "3120*****0045"
    assert row.before == {"pinfl": "3120*****0045", "password": REDACTED}
    assert row.after == {"phone": "+998 90 *** ** 45", "passport": "AB*****67"}
    assert row.details == {"token": REDACTED, "note": "PINFL 3120*****0045", "list": ["AB*****67"]}


def test_row_keeps_uuid_resource_ids_and_defaults_the_system() -> None:
    resource_id = str(uuid.uuid4())
    row = AuditRow.from_event(_event(resource_id=resource_id, actor_ip="unknown"), TS)
    assert row.resource_id == resource_id
    assert row.system_id == "admin"
    assert row.actor_ip is None
    assert AuditRow.from_event(_event(system_id="faceid"), TS).system_id == "faceid"


def test_row_canonical_fields_cover_every_column_but_the_chain() -> None:
    row = AuditRow.from_event(_event(details={"step": "mfa"}), TS)
    fields = row.canonical_fields()
    assert set(fields) == set(row.columns())
    assert not {"id", "prev_hash", "hash"} & set(fields)
    assert fields["ts"] == "2026-11-23T09:15:02.123456Z"
    assert fields["actor_id"] == str(row.actor_id)
    assert row.chain_hash(GENESIS_HASH) == chain_hash(GENESIS_HASH, fields)


def test_non_mapping_details_are_wrapped() -> None:
    event = AuditEvent(action="x.y", outcome=AuditOutcome.ERROR, details=["a"])  # type: ignore[arg-type]
    assert AuditRow.from_event(event, TS).details == {"value": ["a"]}


@pytest.mark.parametrize(
    ("status", "outcome"),
    [
        (200, AuditOutcome.SUCCESS),
        (204, AuditOutcome.SUCCESS),
        (302, AuditOutcome.SUCCESS),
        (401, AuditOutcome.DENIED),
        (403, AuditOutcome.DENIED),
        (429, AuditOutcome.DENIED),
        (404, AuditOutcome.ERROR),
        (422, AuditOutcome.ERROR),
        (500, AuditOutcome.ERROR),
    ],
)
def test_outcome_for_status(status: int, outcome: AuditOutcome) -> None:
    assert outcome_for_status(status) is outcome


@pytest.mark.parametrize(
    ("path", "system"),
    [
        ("/api/v1/admin/users", "admin"),
        ("/api/v1/auth/login", "auth"),
        ("/api/v1/systems/faceid/resources/students", "faceid"),
        ("/api/v1/systems/", None),
        ("/api/v1/", None),
        ("/health", None),
        ("/other/v1/admin", None),
    ],
)
def test_system_for_path(path: str, system: str | None) -> None:
    assert system_for_path(path) == system


def test_needs_record() -> None:
    anonymous = RequestAudit()
    known = RequestAudit(actor_id=uuid.uuid4())
    assert needs_record("POST", 201, anonymous)
    assert needs_record("GET", 403, anonymous)
    assert not needs_record("GET", 200, known)
    assert not needs_record("GET", 401, known)
    # Scanners: unknown paths without a session are not audited ...
    assert not needs_record("POST", 404, anonymous)
    assert not needs_record("DELETE", 405, anonymous)
    # ... but an admin probing objects is.
    assert needs_record("PATCH", 404, known)
    assert not needs_record("POST", 201, RequestAudit(written=True))
