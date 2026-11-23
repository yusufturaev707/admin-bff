import hashlib
from datetime import UTC, datetime, timedelta, timezone

import pytest

from app.core.pii import mask_passport, mask_phone, mask_pinfl, scrub_text
from app.core.time import ensure_utc, isoformat_z, utcnow


def test_utcnow_is_aware_utc() -> None:
    now = utcnow()
    assert now.tzinfo is UTC


def test_ensure_utc_rejects_naive_datetime() -> None:
    with pytest.raises(ValueError, match="naive"):
        ensure_utc(datetime(2026, 11, 20, 9, 0))  # noqa: DTZ001 - the point of the test


def test_ensure_utc_converts_tashkent_time() -> None:
    tashkent = timezone(timedelta(hours=5))
    value = datetime(2026, 11, 20, 14, 15, 2, tzinfo=tashkent)
    assert ensure_utc(value) == datetime(2026, 11, 20, 9, 15, 2, tzinfo=UTC)
    assert isoformat_z(value) == "2026-11-20T09:15:02Z"


def test_masks() -> None:
    assert mask_pinfl("31201234560045") == "3120*****0045"
    assert mask_phone("+998 90 123 45 45") == "+998 90 *** ** 45"
    assert mask_phone("901234545") == "+998 90 *** ** 45"
    assert mask_passport("ab1234567") == "AB*****67"


@pytest.mark.parametrize("bad", ["", "123", "3120123456004X"])
def test_mask_pinfl_never_returns_input(bad: str) -> None:
    assert mask_pinfl(bad) == "*****"


def test_scrub_text_masks_all_patterns() -> None:
    text = "pinfl=31201234560045 tel: +998901234545, passport AB1234567, id 1234"
    scrubbed = scrub_text(text)
    assert "31201234560045" not in scrubbed
    assert "901234545" not in scrubbed
    assert "1234567" not in scrubbed
    assert "3120*****0045" in scrubbed
    assert "+998 90 *** ** 45" in scrubbed
    assert "AB*****67" in scrubbed
    assert scrubbed.endswith("id 1234")


def test_scrub_text_leaves_uuids_and_timestamps() -> None:
    text = "request 0b9c5e1e-3f7a-4d43-9a43-6f1a2b9d8c11 at 1763640000"
    assert scrub_text(text) == text


def test_scrub_text_leaves_hashes_intact() -> None:
    # The audit copy in journald carries record hashes; a digit run inside a hex
    # hash is not a PINFL or a phone number. (Before the fix ~1% were altered.)
    assert scrub_text("ab12345678901234cd") == "ab12345678901234cd"
    assert scrub_text("f0998901234545ee") == "f0998901234545ee"
    for i in range(20_000):
        digest = hashlib.sha256(str(i).encode()).hexdigest()
        assert scrub_text(digest) == digest, digest


@pytest.mark.parametrize(
    ("text", "masked"),
    [
        ('{"pinfl": "31201234560045"}', '{"pinfl": "3120*****0045"}'),
        ("/students/31201234560045/photo", "/students/3120*****0045/photo"),
        ("PINFL_31201234560045", "PINFL_3120*****0045"),
        ("31201234560045", "3120*****0045"),
        ("tel:+998901234545.", "tel:+998 90 *** ** 45."),
    ],
)
def test_scrub_text_still_masks_standalone_values(text: str, masked: str) -> None:
    assert scrub_text(text) == masked
