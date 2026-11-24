r"""Gateway acceptance predicate Pi = pi_1 /\ ... /\ pi_12.

The clause set follows the paper's ``GWAccept``:

    pi_1   signature verifies under the catalog-selected group key
    pi_2   signed (tid, sid, aid, uid) == authenticated current context
    pi_3   the transition log entry L[trid] matches the signed transition
    pi_4   tool name matches
    pi_5   (tau_c, args_c) in Delta_sym
    pi_6   Phi(args_c) = 1
    pi_7   not expired
    pi_8   nonce is fresh (atomically consumed)
    pi_9   configuration is in the catalog and active
    pi_10  the configuration's public-key id matches Req.pkid
    pi_11  rho equals RiskTier(tau, Phi, CurrentContext), recomputed here
    pi_12  S(rho) selects this configuration

pi_11/pi_12 are enforced only when the catalog declares a risk selector
(i.e. its entries carry a ``risk_tier``); configurations without one (the
single-approver ablation and the legacy test catalog) are exempt. pi_10 is
enforced when the catalog entry declares a ``pkid``. Both exemptions are
recorded as prototype limitations in the experiment document.

Each pi_j returns either None (pass) or a short string explaining the
rejection -- the experiment harness collects these per attack to populate
the metrics table.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from time import time
from typing import Any, Iterable, Optional

from jsonschema import Draft7Validator, ValidationError

from . import risk as risk_mod
from .canon import policy_hash
from .catalog import ApprovalCatalog
from .cert import Cert
from .replay_store import ReplayStore
from .threshold_sig import verify as verify_sig
from .transition_log import TransitionLog, matches as transition_matches


@dataclass
class SessionCtx:
    tid: str
    sid: str
    aid: str
    uid: str
    P_current: dict | None
    P_new: dict | None
    transition_log: TransitionLog | None = None
    context: dict | None = None   # extra context features for pi_11


@dataclass
class GatewayResult:
    accepted: bool
    rejected_clause: Optional[str] = None
    detail: Optional[str] = None
    verify_ns: int = 0
    risk_tier: str | None = None
    risk_score: float | None = None


def _match_delta(delta_sym: dict, tau: str, args: dict) -> bool:
    """pi_5: (tau, args) in delta_sym.

    ``delta_sym`` is the policy difference set restricted to newly-allowed
    (tool -> list of json-schema condition dicts) entries. The call is
    inside delta iff ``tau`` is one of its keys AND args satisfy at least
    one of the entries.
    """
    entries = delta_sym.get(tau)
    if not entries:
        return False
    for cond in entries:
        try:
            Draft7Validator(cond).validate(args)
            return True
        except ValidationError:
            continue
    return False


def _match_phi(phi: dict, args: dict) -> bool:
    """pi_6: Phi(args) = 1."""
    if not phi:
        return True
    try:
        Draft7Validator(phi).validate(args)
        return True
    except ValidationError:
        return False


def accept(
    cert: Cert,
    tau_c: str,
    args_c: dict,
    ctx: SessionCtx,
    catalog: ApprovalCatalog,
    replay: ReplayStore,
    now: int | None = None,
) -> GatewayResult:
    """Run pi_1 .. pi_12, short-circuiting on first rejection.

    On accept the nonce is consumed (atomic check_and_consume).
    """
    from time import perf_counter_ns

    t0 = perf_counter_ns()
    req = cert.req

    def _fail(clause: str, detail: str, **kw) -> GatewayResult:
        return GatewayResult(False, clause, detail,
                             verify_ns=perf_counter_ns() - t0, **kw)

    # -- pi_9: configuration membership + active flag ------------------
    entry = catalog.entry(req.apid)
    if entry is None:
        return _fail("pi_9", "apid not in catalog")
    if not entry.active:
        return _fail("pi_9", "configuration not active")
    if entry.cid != req.cid or entry.t != req.t:
        return _fail("pi_9", "apid/cid/t not in catalog")

    # -- pi_10: public-key identifier pinning --------------------------
    if entry.pkid and req.pkid != entry.pkid:
        return _fail("pi_10", "pkid mismatch")

    # -- pi_1: signature verification against the group key ------------
    if not verify_sig(entry.group, req.hash(), cert.sigma, req.t):
        return _fail("pi_1", "signature does not verify")

    # -- pi_2: identity pinning (tid, sid, aid, uid) -------------------
    if (req.tid, req.sid, req.aid, req.uid) != (ctx.tid, ctx.sid, ctx.aid, ctx.uid):
        return _fail("pi_2", "identity tuple mismatch")

    # -- pi_3: transition-record binding -------------------------------
    # When an authenticated transition log is supplied we require the
    # certificate to match a *detected* transition entry. Without one we
    # fall back to the policy-hash equality used by the prototype.
    if ctx.transition_log is not None:
        rec = ctx.transition_log.get(req.trid)
        if not transition_matches(
            rec, h_P=req.h_P, h_P_prime=req.h_P_prime,
            delta_sym=req.delta_sym, tau=req.tau,
            tid=req.tid, sid=req.sid, aid=req.aid, uid=req.uid,
        ):
            return _fail("pi_3", "transition log mismatch")
    elif req.h_P != policy_hash(ctx.P_current):
        return _fail("pi_3", "h_P does not match current policy")

    # -- pi_4: tool name match -----------------------------------------
    if req.tau != tau_c:
        return _fail("pi_4", "tool name mismatch")

    # -- pi_5: call inside symbolic expansion delta --------------------
    if not _match_delta(req.delta_sym, tau_c, args_c):
        return _fail("pi_5", "(tau, args) not in delta_sym")

    # -- pi_6: argument constraints ------------------------------------
    if not _match_phi(req.phi, args_c):
        return _fail("pi_6", "phi(args) failed")

    # -- pi_11 / pi_12: risk recomputation + configuration selection ---
    assessment = None
    if catalog.has_risk_policy():
        assessment = risk_mod.assess(tau_c, req.phi, ctx.context)
        if assessment.tier_int != req.rho:
            return _fail("pi_11",
                         f"risk tier {assessment.tier} != declared rho {req.rho}")
        expected = catalog.config_for_tier(assessment.tier)
        if expected is None or expected.apid != req.apid:
            return _fail("pi_12", "S(rho) does not select this configuration")

    # -- pi_7: not expired ---------------------------------------------
    cur = now if now is not None else int(time())
    if cur > req.exp:
        return _fail("pi_7", "expired")

    # -- pi_8: single-use nonce, atomically consume --------------------
    if not replay.check_and_consume(req.nonce):
        return _fail("pi_8", "nonce already consumed")

    return GatewayResult(
        True, None, None, verify_ns=perf_counter_ns() - t0,
        risk_tier=assessment.tier if assessment else None,
        risk_score=assessment.score if assessment else None,
    )
