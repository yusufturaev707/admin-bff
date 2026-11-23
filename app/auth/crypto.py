"""Small crypto helpers for auth secrets."""

import hashlib
import hmac
import secrets

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

_VERSION = b"\x01"
_NONCE_BYTES = 12


class DecryptionError(Exception):
    pass


class SecretBox:
    """AES-256-GCM encryption of small secrets (TOTP secrets).

    Blob layout: version (1 byte) || nonce (12 bytes) || ciphertext+tag.
    `aad` binds a ciphertext to its owner (the admin's id), so an encrypted
    secret copied to another row does not decrypt.
    """

    def __init__(self, key: bytes) -> None:
        if len(key) != 32:
            raise ValueError("AES-256-GCM key must be 32 bytes")
        self._aead = AESGCM(key)

    def encrypt(self, plaintext: bytes, *, aad: bytes) -> bytes:
        nonce = secrets.token_bytes(_NONCE_BYTES)
        return _VERSION + nonce + self._aead.encrypt(nonce, plaintext, aad)

    def decrypt(self, blob: bytes, *, aad: bytes) -> bytes:
        if len(blob) <= 1 + _NONCE_BYTES or blob[:1] != _VERSION:
            raise DecryptionError("unknown ciphertext format")
        nonce = blob[1 : 1 + _NONCE_BYTES]
        try:
            return self._aead.decrypt(nonce, blob[1 + _NONCE_BYTES :], aad)
        except InvalidTag as exc:
            raise DecryptionError("ciphertext was modified or the key is wrong") from exc


def sha256_hex(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def hmac_sha256_hex(key: bytes, value: str) -> str:
    return hmac.new(key, value.encode(), hashlib.sha256).hexdigest()


def new_token() -> str:
    """256-bit random token for session ids, CSRF tokens, mfa tokens, OAuth state."""
    return secrets.token_urlsafe(32)
