"""Structured logging (structlog -> stdout -> journald).

All records, including those of the standard `logging` module (uvicorn,
SQLAlchemy, ...), go through one processor chain, so redaction applies to
everything:

* values of sensitive keys (password, token, cookie, TOTP code, ...) are
  replaced with `[REDACTED]`, at any nesting depth;
* PINFL, phone and passport numbers inside any string are masked.
"""

import logging
import sys
from collections.abc import Mapping, MutableMapping
from typing import IO, Any

import structlog
from structlog.typing import Processor

from app.core.pii import scrub_text
from app.settings import Settings

REDACTED = "[REDACTED]"

# A key is sensitive if its lower-cased name contains one of these fragments.
# Over-redaction is preferred to leaking a secret.
SENSITIVE_KEY_FRAGMENTS: tuple[str, ...] = (
    "password",
    "passwd",
    "secret",
    "token",
    "authorization",
    "cookie",
    "csrf",
    "otp",
    "recovery_code",
    "private_key",
    "api_key",
    "session_id",
    "embedding",
)

# Keys produced by structlog/stdlib itself; never redacted.
_RESERVED_KEYS = frozenset({"event", "level", "ts", "logger", "_record", "_from_structlog"})


def is_sensitive_key(key: str) -> bool:
    lowered = key.lower()
    return any(fragment in lowered for fragment in SENSITIVE_KEY_FRAGMENTS)


def _scrub(value: Any) -> Any:
    if isinstance(value, str):
        return scrub_text(value)
    if isinstance(value, Mapping):
        return {
            k: REDACTED if isinstance(k, str) and is_sensitive_key(k) else _scrub(v)
            for k, v in value.items()
        }
    if isinstance(value, list | tuple | set | frozenset):
        return [_scrub(v) for v in value]
    return value


def redact_processor(
    _logger: Any, _method_name: str, event_dict: MutableMapping[str, Any]
) -> MutableMapping[str, Any]:
    for key, value in list(event_dict.items()):
        if key in _RESERVED_KEYS:
            if key == "event" and isinstance(value, str):
                event_dict[key] = scrub_text(value)
            continue
        event_dict[key] = REDACTED if is_sensitive_key(key) else _scrub(value)
    return event_dict


def _shared_processors() -> list[Processor]:
    return [
        structlog.contextvars.merge_contextvars,
        structlog.stdlib.add_log_level,
        structlog.stdlib.add_logger_name,
        structlog.processors.TimeStamper(fmt="iso", utc=True, key="ts"),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
        structlog.processors.UnicodeDecoder(),
    ]


def configure_logging(settings: Settings, stream: IO[str] | None = None) -> None:
    renderer: Processor
    if settings.log_format == "json":
        renderer = structlog.processors.JSONRenderer()
    else:
        renderer = structlog.dev.ConsoleRenderer(colors=False)

    shared = _shared_processors()
    structlog.configure(
        processors=[
            structlog.stdlib.filter_by_level,
            *shared,
            structlog.stdlib.ProcessorFormatter.wrap_for_formatter,
        ],
        logger_factory=structlog.stdlib.LoggerFactory(),
        wrapper_class=structlog.stdlib.BoundLogger,
        cache_logger_on_first_use=False,
    )

    formatter = structlog.stdlib.ProcessorFormatter(
        foreign_pre_chain=shared,
        processors=[
            structlog.stdlib.ProcessorFormatter.remove_processors_meta,
            redact_processor,
            renderer,
        ],
    )
    handler = logging.StreamHandler(stream if stream is not None else sys.stdout)
    handler.setFormatter(formatter)

    root = logging.getLogger()
    root.handlers.clear()
    root.addHandler(handler)
    root.setLevel(settings.log_level)

    # uvicorn installs its own handlers; route its records through ours.
    # The BFF writes its own access log (core.request_id), so uvicorn's is muted.
    for name in ("uvicorn", "uvicorn.error", "uvicorn.access"):
        uv_logger = logging.getLogger(name)
        uv_logger.handlers.clear()
        uv_logger.propagate = True
    logging.getLogger("uvicorn.access").setLevel(logging.WARNING)


def get_logger(name: str) -> structlog.stdlib.BoundLogger:
    logger: structlog.stdlib.BoundLogger = structlog.stdlib.get_logger(name)
    return logger
