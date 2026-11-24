"""tool.py:573 hook -- consult the pending Cert against the gateway.

Called when ``_check_tool_call`` raises (i.e., the current policy denies
the call). If a Cert is parked in the ContextVar AND the gateway
predicate Pi accepts (cert, call) under the current session/policy
state, the call is admitted; otherwise the original deny propagates.

Every gateway decision is appended to an in-memory ``audit_log`` ring so
the attack drivers can read out which pi_j rejected.
"""
from __future__ import annotations

import sys
from collections import deque
from dataclasses import asdict, dataclass

from .context import take_pending
from .gateway import GatewayResult, SessionCtx, accept
from .hook_update import current_catalog, current_session, current_transition_log
from .replay_store import default_store


@dataclass
class AuditEntry:
    tool: str
    accepted: bool
    rejected_clause: str | None
    detail: str | None
    verify_ns: int
    cert_size: int | None


_audit: deque[AuditEntry] = deque(maxlen=1024)


def audit_log() -> list[AuditEntry]:
    return list(_audit)


def reset_audit() -> None:
    _audit.clear()


def try_accept_with_cert(tool_name: str, kwargs: dict) -> bool:
    """Return True iff a pending Cert exists and the gateway accepts it.

    Always consumes (clears) the pending Cert -- a single-use semantic
    that mirrors the nonce rule on the verify side.
    """
    cert = take_pending()
    if cert is None:
        return False
    from .. import tool as _tool  # avoid circular import on module load

    session = current_session()
    ctx = SessionCtx(
        tid=session["tid"],
        sid=session["sid"],
        aid=session["aid"],
        uid=session["uid"],
        P_current=_tool.security_policy,
        P_new=None,
        transition_log=current_transition_log(),
    )
    result: GatewayResult = accept(
        cert=cert,
        tau_c=tool_name,
        args_c=dict(kwargs),
        ctx=ctx,
        catalog=current_catalog(),
        replay=default_store(),
    )
    _audit.append(
        AuditEntry(
            tool=tool_name,
            accepted=result.accepted,
            rejected_clause=result.rejected_clause,
            detail=result.detail,
            verify_ns=result.verify_ns,
            cert_size=cert.size_bytes(),
        )
    )
    if result.accepted:
        print(
            f"[gateway] ACCEPT {tool_name} verify_ns={result.verify_ns}",
            file=sys.stderr,
        )
        return True
    print(
        f"[gateway] REJECT {tool_name} clause={result.rejected_clause} "
        f"detail={result.detail}",
        file=sys.stderr,
    )
    return False


