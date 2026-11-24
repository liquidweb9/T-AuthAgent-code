"""Shared authorization-layer harness for the revision experiments.

The original attack drivers run through the full Progent pipeline
(``experiments/runner.py``). The revision experiments need finer control
over the *authorization layer* itself -- choosing exactly which approver
shares sign a request, forging configurations, racing threads against the
same certificate. This module provides that control directly on top of
``secagent.auth`` without going through Progent.

Everything here is deterministic given its arguments (only nonces and, where
requested, share subsets are randomised), so results are reproducible.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Sequence

from secagent.auth.canon import policy_hash
from secagent.auth.catalog import ApprovalCatalog
from secagent.auth.cert import Cert
from secagent.auth.gateway import SessionCtx
from secagent.auth.req import Req, default_exp, make_nonce
from secagent.auth.threshold_sig import combine, sign_share
from secagent.auth.transition_log import TransitionLog, TransitionRecord

SESSION = {"tid": "t_run", "sid": "s_run", "aid": "a_run", "uid": "u_run"}

DELTA = {"send_email": [{"type": "object"}]}


def fixed_catalog(t: int, n: int, apid: str = "cfg",
                  cid: str = "committee_main") -> ApprovalCatalog:
    """A single, plain (t, n) configuration -- no risk selector."""
    cat = ApprovalCatalog()
    cat.register(apid=apid, cid=cid, t=t, n=n, pkid="")
    return cat


def make_req(catalog: ApprovalCatalog, apid: str, *, tau: str = "send_email",
             phi: dict | None = None, delta_sym: dict | None = None,
             rho: int = 2, session: dict | None = None, ttl: int = 60,
             trid: str = "", pkid: str | None = None,
             nonce: bytes | None = None) -> Req:
    s = dict(SESSION)
    if session:
        s.update(session)
    entry = catalog.entry(apid)
    return Req(
        trid=trid,
        tid=s["tid"], sid=s["sid"], aid=s["aid"], uid=s["uid"],
        h_P=policy_hash(None),
        h_P_prime=policy_hash({tau: [(100, 0, dict(phi or {}), 0)]}),
        delta_sym=delta_sym if delta_sym is not None else {tau: [{"type": "object"}]},
        tau=tau,
        phi=phi if phi is not None else {},
        rho=rho,
        apid=apid, cid=entry.cid, t=entry.t,
        pkid=entry.pkid if pkid is None else pkid,
        exp=default_exp(ttl),
        nonce=nonce or make_nonce(),
    )


def mint(catalog: ApprovalCatalog, req: Req,
         signer_indices: Sequence[int]) -> Cert:
    """Produce a certificate from the named approver shares (1-based).

    Using fewer than ``t`` shares yields an *invalid* combination (Lagrange
    interpolation over an under-sized set), which is exactly the property
    the corruption experiment measures.
    """
    shares = catalog.shares(req.apid)
    chosen = [shares[i - 1] for i in signer_indices]
    parts = [sign_share(s, req.hash()) for s in chosen]
    return Cert(req=req, sigma=combine(parts), mode="A")


def ctx_for(*, session: dict | None = None, P_current: dict | None = None,
            transition_log: TransitionLog | None = None,
            context: dict | None = None) -> SessionCtx:
    s = dict(SESSION)
    if session:
        s.update(session)
    return SessionCtx(
        tid=s["tid"], sid=s["sid"], aid=s["aid"], uid=s["uid"],
        P_current=P_current, P_new=None,
        transition_log=transition_log, context=context,
    )


def log_for(req: Req, detected: bool = True) -> TransitionLog:
    log = TransitionLog()
    log.append(TransitionRecord(
        trid=req.trid, h_P=req.h_P, h_P_prime=req.h_P_prime,
        delta_sym=req.delta_sym, tau=req.tau,
        tid=req.tid, sid=req.sid, aid=req.aid, uid=req.uid,
        detected=detected,
    ))
    return log


def all_indices(n: int) -> list[int]:
    return list(range(1, n + 1))


# ─── Honest / compromised approver behaviour ──────────────────────────

BENIGN_RECIPIENT = "bob@example.com"


def honest_approves(req: Req) -> bool:
    """Reference honest-approver policy.

    An honest approver signs only a request whose predicate confines the
    recipient to the benign one. A request for any other recipient is
    refused -- this is the "request the threshold did not endorse" in the
    theorem. Compromised approvers sign unconditionally.
    """
    phi = req.phi or {}
    props = phi.get("properties", {}) if isinstance(phi, dict) else {}
    to = props.get("to", {})
    enum = to.get("enum") if isinstance(to, dict) else None
    return enum == [BENIGN_RECIPIENT]


def attack_phi(recipient: str = "eve@evil.example") -> dict:
    return {"type": "object",
            "properties": {"to": {"enum": [recipient]}},
            "required": ["to"]}


def benign_phi() -> dict:
    return {"type": "object",
            "properties": {"to": {"enum": [BENIGN_RECIPIENT]}},
            "required": ["to"]}
