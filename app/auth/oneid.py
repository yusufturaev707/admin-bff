"""OneID (citizen single sign-on) client: template.

The login flow around it is complete (`/auth/oneid/start` and
`/auth/oneid/callback`, state check, PINFL -> admin lookup, TOTP afterwards).
Only the HTTP client that talks to OneID is missing:

TODO(owner): OneID integration documents are needed: authorization, token and
user-info endpoints, request parameters, response format and test credentials.
The real client implements `OneIdClient` in this file (httpx.AsyncClient, tests
with respx) and is returned by `build_oneid_client`; nothing else changes.

Until then `build_oneid_client` raises, so `ONEID_ENABLED=true` stops the
startup instead of offering a broken login button.
"""

from dataclasses import dataclass
from typing import Protocol

from app.settings import Settings


class OneIdError(Exception):
    """OneID rejected the code or answered with something unexpected."""


@dataclass(frozen=True, slots=True)
class OneIdIdentity:
    pinfl: str  # 14 digits; used only for the lookup, never stored or logged

    def __post_init__(self) -> None:
        if len(self.pinfl) != 14 or not self.pinfl.isascii() or not self.pinfl.isdigit():
            raise OneIdError("OneID returned an invalid PINFL")


class OneIdClient(Protocol):
    def authorization_url(self, state: str) -> str:
        """URL of the OneID login page; `state` must come back to the callback."""
        ...

    async def exchange_code(self, code: str) -> OneIdIdentity:
        """Exchanges the callback `code` server-side (with the client secret)."""
        ...

    async def aclose(self) -> None: ...


def build_oneid_client(settings: Settings) -> OneIdClient:
    # TODO(owner): return the real OneID client here (see the module docstring).
    raise RuntimeError(
        "ONEID_ENABLED=true, but the OneID client is not implemented yet "
        "(TODO(owner) in app/auth/oneid.py)"
    )
