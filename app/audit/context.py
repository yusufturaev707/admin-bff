"""Per-request audit state (a context variable set by AuditRequestMiddleware).

* `written`: an audit event was written while handling the request, so the
  request-level fallback record is not needed;
* the actor: set by the session dependency as soon as the session is known, so
  even a request rejected later (CSRF token, validation) names its admin.

The state object is shared by reference, so code running in a thread pool
(with a copy of the context) updates the same object.
"""

import uuid
from contextvars import ContextVar, Token
from dataclasses import dataclass


@dataclass(slots=True)
class RequestAudit:
    written: bool = False
    actor_id: uuid.UUID | None = None
    actor_username: str | None = None
    session_hash: str | None = None


_current: ContextVar[RequestAudit | None] = ContextVar("admin_bff_request_audit", default=None)


def start_request() -> tuple[RequestAudit, Token[RequestAudit | None]]:
    state = RequestAudit()
    return state, _current.set(state)


def end_request(token: Token[RequestAudit | None]) -> None:
    _current.reset(token)


def mark_written() -> None:
    state = _current.get()
    if state is not None:
        state.written = True


def set_actor(user_id: uuid.UUID, username: str, session_hash: str) -> None:
    state = _current.get()
    if state is not None:
        state.actor_id = user_id
        state.actor_username = username
        state.session_hash = session_hash
