import io
import json
import logging
import secrets
from typing import Any

import pytest
import structlog

from app.core.logging import REDACTED, configure_logging, get_logger
from app.settings import Settings


@pytest.fixture
def log_stream(settings: Settings) -> io.StringIO:
    stream = io.StringIO()
    configure_logging(settings, stream=stream)
    structlog.contextvars.clear_contextvars()
    return stream


def _records(stream: io.StringIO) -> list[dict[str, Any]]:
    return [json.loads(line) for line in stream.getvalue().splitlines() if line]


def test_json_record_has_required_fields(log_stream: io.StringIO) -> None:
    structlog.contextvars.bind_contextvars(request_id="rid-1")
    get_logger("test").info("hello", status=200)

    [record] = _records(log_stream)
    assert record["event"] == "hello"
    assert record["level"] == "info"
    assert record["request_id"] == "rid-1"
    assert record["status"] == 200
    assert record["ts"].endswith("Z")


def test_sensitive_keys_are_redacted_at_any_depth(log_stream: io.StringIO) -> None:
    password = secrets.token_urlsafe(16)
    totp = f"{secrets.randbelow(10**6):06d}"
    token = secrets.token_urlsafe(32)
    get_logger("test").info(
        "login_attempt",
        password=password,
        totp_code=totp,
        headers={"Cookie": f"__Host-admin_session={token}", "Accept": "application/json"},
        nested=[{"mfa_token": token}],
    )

    output = log_stream.getvalue()
    for value in (password, totp, token):
        assert value not in output
    [record] = _records(log_stream)
    assert record["password"] == REDACTED
    assert record["totp_code"] == REDACTED
    assert record["headers"] == {"Cookie": REDACTED, "Accept": "application/json"}
    assert record["nested"] == [{"mfa_token": REDACTED}]


def test_pii_is_masked_in_messages_values_and_stdlib_logs(log_stream: io.StringIO) -> None:
    get_logger("test").info("student 31201234560045 checked", phone="+998901234545")
    logging.getLogger("thirdparty").warning("passport AB1234567 rejected")

    output = log_stream.getvalue()
    assert "31201234560045" not in output
    assert "901234545" not in output
    assert "AB1234567" not in output
    first, second = _records(log_stream)
    assert first["event"] == "student 3120*****0045 checked"
    assert first["phone"] == "+998 90 *** ** 45"
    assert second["event"] == "passport AB*****67 rejected"
    assert second["logger"] == "thirdparty"


def test_exception_text_is_masked(log_stream: io.StringIO) -> None:
    try:
        raise ValueError("bad pinfl 31201234560045")
    except ValueError:
        get_logger("test").exception("failed")

    assert "31201234560045" not in log_stream.getvalue()
    [record] = _records(log_stream)
    assert "3120*****0045" in record["exception"]


def test_level_filtering(settings: Settings) -> None:
    stream = io.StringIO()
    configure_logging(settings.model_copy(update={"log_level": "WARNING"}), stream=stream)
    get_logger("test").info("hidden")
    get_logger("test").warning("shown")
    assert [r["event"] for r in _records(stream)] == ["shown"]
