"""Per-task ContextVar carrying the pending Cert.

The Progent runtime calls ``generate_update_security_policy`` after each
tool call. In the T-AuthAgent flow, that hook decides "expansion needs
approval", obtains a Cert, and parks it here. The very next
``check_tool_call`` reads it back to feed the gateway predicate.

ContextVar is the right primitive: the Progent code already runs each
agent task in an asyncio/threaded context, and we want each task's Cert
to stay isolated.
"""
from __future__ import annotations

from contextvars import ContextVar
from typing import Optional

from .cert import Cert


_pending: ContextVar[Optional[Cert]] = ContextVar("tauth_pending_cert", default=None)


def set_pending(cert: Cert) -> None:
    _pending.set(cert)


def get_pending() -> Optional[Cert]:
    return _pending.get()


def clear_pending() -> None:
    _pending.set(None)


def take_pending() -> Optional[Cert]:
    """Atomic get-and-clear."""
    cert = _pending.get()
    if cert is not None:
        _pending.set(None)
    return cert
