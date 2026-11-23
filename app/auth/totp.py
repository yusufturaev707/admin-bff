"""TOTP (RFC 6238) and recovery codes (section 6).

6 digits, 30 second steps, one step of clock drift accepted (`valid_window=1`).
A code is accepted only if its time step is newer than the last accepted one,
so the same code can never be used twice.
"""

import hmac
import secrets
from datetime import datetime

import pyotp

DIGITS = 6
INTERVAL_S = 30
VALID_WINDOW = 1

RECOVERY_CODE_COUNT = 10
# Crockford-like alphabet without 0/O and 1/I: 32 symbols, 16 symbols = 80 bits.
_RECOVERY_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
_RECOVERY_LENGTH = 16


def new_secret() -> str:
    return pyotp.random_base32()  # 160 bits


def provisioning_uri(secret: str, *, username: str, issuer: str) -> str:
    """`otpauth://` URI. The frontend renders it as a QR code once, at enrollment."""
    return pyotp.TOTP(secret, digits=DIGITS, interval=INTERVAL_S).provisioning_uri(
        name=username, issuer_name=issuer
    )


def is_code_format(code: str) -> bool:
    return len(code) == DIGITS and code.isascii() and code.isdigit()


def match_timecode(secret: str, code: str, now: datetime) -> int | None:
    """Returns the time step `code` belongs to, or None if it is not valid now."""
    if not is_code_format(code):
        return None
    totp = pyotp.TOTP(secret, digits=DIGITS, interval=INTERVAL_S)
    current = totp.timecode(now)
    matched: int | None = None
    # Every candidate is compared (no early exit) in constant time.
    for step in range(current - VALID_WINDOW, current + VALID_WINDOW + 1):
        if hmac.compare_digest(totp.generate_otp(step), code):
            matched = step
    return matched


def new_recovery_code() -> str:
    raw = "".join(secrets.choice(_RECOVERY_ALPHABET) for _ in range(_RECOVERY_LENGTH))
    return "-".join(raw[i : i + 4] for i in range(0, _RECOVERY_LENGTH, 4))


def normalize_recovery_code(value: str) -> str | None:
    """`abcd-efgh ...` -> `ABCDEFGH...`; None if it cannot be a recovery code."""
    compact = value.replace("-", "").replace(" ", "").upper()
    if len(compact) != _RECOVERY_LENGTH or any(c not in _RECOVERY_ALPHABET for c in compact):
        return None
    return compact
