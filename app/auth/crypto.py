"""Small crypto helpers for auth secrets."""

import hashlib
import hmac
import secrets


def sha256_hex(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def hmac_sha256_hex(key: bytes, value: str) -> str:
    return hmac.new(key, value.encode(), hashlib.sha256).hexdigest()


def new_token() -> str:
    """256-bit random token for session ids, CSRF tokens and OAuth state."""
    return secrets.token_urlsafe(32)
