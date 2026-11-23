"""Small crypto helpers for auth secrets."""

import hashlib
import hmac
import secrets
from collections.abc import Sequence

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

_VERSION = b"\x01"
_KEY_ID_BYTES = 4
_NONCE_BYTES = 12
_HEADER_BYTES = 1 + _KEY_ID_BYTES + _NONCE_BYTES


class DecryptionError(Exception):
    pass


def key_id(key: bytes) -> bytes:
    """Short public identifier of a key (a hash prefix, reveals nothing about it)."""
    return hashlib.sha256(b"admin-bff:key-id:" + key).digest()[:_KEY_ID_BYTES]


class SecretBox:
    """AES-256-GCM encryption of small secrets (TOTP secrets), with key rotation.

    Blob layout: version (1) || key id (4) || nonce (12) || ciphertext+tag.

    New data is always encrypted with the current key. Blobs of the previous
    keys still decrypt (the key id says which key to use) until
    `cli reencrypt-totp` has rewritten them; then the old key is removed.
    `aad` binds a ciphertext to its owner (the admin's id), so an encrypted
    secret copied to another row does not decrypt.
    """

    def __init__(self, key: bytes, *, previous: Sequence[bytes] = ()) -> None:
        for candidate in (key, *previous):
            if len(candidate) != 32:
                raise ValueError("AES-256-GCM key must be 32 bytes")
        self._current_id = key_id(key)
        self._current = AESGCM(key)
        self._keys = {key_id(old): AESGCM(old) for old in previous}
        self._keys[self._current_id] = self._current

    def encrypt(self, plaintext: bytes, *, aad: bytes) -> bytes:
        nonce = secrets.token_bytes(_NONCE_BYTES)
        return _VERSION + self._current_id + nonce + self._current.encrypt(nonce, plaintext, aad)

    def decrypt(self, blob: bytes, *, aad: bytes) -> bytes:
        if len(blob) <= _HEADER_BYTES or blob[:1] != _VERSION:
            raise DecryptionError("unknown ciphertext format")
        aead = self._keys.get(blob[1 : 1 + _KEY_ID_BYTES])
        if aead is None:
            raise DecryptionError("encrypted with a key that is not configured")
        nonce = blob[1 + _KEY_ID_BYTES : _HEADER_BYTES]
        try:
            return aead.decrypt(nonce, blob[_HEADER_BYTES:], aad)
        except InvalidTag as exc:
            raise DecryptionError("ciphertext was modified") from exc

    def is_current(self, blob: bytes) -> bool:
        """True if `blob` is already encrypted with the current key."""
        return blob[1 : 1 + _KEY_ID_BYTES] == self._current_id


def sha256_hex(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def hmac_sha256_hex(key: bytes, value: str) -> str:
    return hmac.new(key, value.encode(), hashlib.sha256).hexdigest()


def new_token() -> str:
    """256-bit random token for session ids, CSRF tokens, mfa tokens, OAuth state."""
    return secrets.token_urlsafe(32)
