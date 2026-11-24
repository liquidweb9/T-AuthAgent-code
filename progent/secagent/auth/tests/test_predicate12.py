"""Clause-level tests for the extended gateway predicate.

Covers the clauses added for the revision: pi_3 (transition-log binding),
pi_9 active flag, pi_10 (pkid pinning), pi_11 (risk recomputation) and
pi_12 (configuration selection), plus atomic concurrency of pi_8.
"""
import threading

import pytest

from secagent.auth.canon import policy_hash
from secagent.auth.catalog import make_risk_catalog
from secagent.auth.cert import Cert
from secagent.auth.committee import make_uniform_committee
from secagent.auth.gateway import SessionCtx, accept
from secagent.auth.replay_store import ReplayStore
from secagent.auth.req import Req, default_exp, make_nonce
from secagent.auth.transition_log import TransitionLog, TransitionRecord

SESSION = dict(tid="t1", sid="s1", aid="a1", uid="u1")

TIGHT_SEND_PHI = {
    "type": "object",
    "properties": {"to": {"enum": ["bob@example.com"]},
                   "subject": {"type": "string", "maxLength": 80}},
    "required": ["to"],
}


def _risk_env(tau="send_email", phi=None, apid="med_risk", rho=2, pkid=None,
              ttl=60, log=None, delta_sym=None, t=None):
    """Build a risk-adaptive (catalog, cert, ctx) triple."""
    catalog = make_risk_catalog()
    entry = catalog.entry(apid)
    committee = make_uniform_committee(catalog, apid=apid, n=entry.n)
    phi = TIGHT_SEND_PHI if phi is None else phi
    delta_sym = delta_sym or {tau: [{"type": "object"}]}
    req = Req(
        tid=SESSION["tid"], sid=SESSION["sid"], aid=SESSION["aid"], uid=SESSION["uid"],
        h_P=policy_hash(None),
        h_P_prime=policy_hash({tau: [(100, 0, {"type": "object"}, 0)]}),
        delta_sym=delta_sym,
        tau=tau, phi=phi, rho=rho,
        apid=apid, cid=entry.cid, t=t or entry.t,
        pkid=entry.pkid if pkid is None else pkid,
        exp=default_exp(ttl), nonce=make_nonce(),
    )
    cert = committee.approve(req)
    assert cert is not None, "committee should approve on the happy path"
    ctx = SessionCtx(P_current=None, P_new=None, transition_log=log, **SESSION)
    return catalog, cert, ctx


# ─── pi_11 / pi_12: risk recomputation and configuration selection ────

def test_risk_happy_path_accepted():
    cat, cert, ctx = _risk_env()
    res = accept(cert, "send_email", {"to": "bob@example.com"}, ctx, cat,
                 ReplayStore())
    assert res.accepted, res
    assert res.risk_tier == "medium"


def test_pi_11_understated_risk_rejected():
    """A request claiming a lower tier than the call warrants fails pi_11."""
    cat, cert, ctx = _risk_env(tau="delete_file", phi={"type": "object"},
                               apid="med_risk", rho=2)
    # delete_file with a bare predicate is HIGH risk, not medium.
    res = accept(cert, "delete_file", {"path": "/x"}, ctx, cat, ReplayStore())
    assert not res.accepted
    assert res.rejected_clause == "pi_11"


def test_pi_12_wrong_configuration_for_tier_rejected():
    """Correct rho but a configuration that S(rho) does not select."""
    cat, cert, ctx = _risk_env(apid="low_risk", rho=2)  # medium risk, low cfg
    res = accept(cert, "send_email", {"to": "bob@example.com"}, ctx, cat,
                 ReplayStore())
    assert not res.accepted
    assert res.rejected_clause == "pi_12"


def test_pi_10_pkid_mismatch_rejected():
    cat, cert, ctx = _risk_env(pkid="pk::not-the-right-one")
    res = accept(cert, "send_email", {"to": "bob@example.com"}, ctx, cat,
                 ReplayStore())
    assert not res.accepted
    assert res.rejected_clause == "pi_10"


# ─── pi_9: active flag / revocation ───────────────────────────────────

def test_pi_9_inactive_configuration_rejected():
    cat, cert, ctx = _risk_env()
    cat.deactivate("med_risk")
    res = accept(cert, "send_email", {"to": "bob@example.com"}, ctx, cat,
                 ReplayStore())
    assert not res.accepted
    assert res.rejected_clause == "pi_9"


def test_rotated_key_invalidates_old_certificate():
    """Rotation rebinds the apid to a new key and a new key identifier.

    The stale certificate must therefore be rejected -- either at pi_10
    (identifier no longer matches) or, if the identifier were reused, at
    pi_1 (signature no longer verifies under the rebuilt key).
    """
    cat, cert, ctx = _risk_env()
    cat.rotate_key("med_risk")
    res = accept(cert, "send_email", {"to": "bob@example.com"}, ctx, cat,
                 ReplayStore())
    assert not res.accepted
    assert res.rejected_clause in ("pi_10", "pi_1")


# ─── pi_3: transition-log binding ─────────────────────────────────────

def _log_for(cert, detected=True):
    log = TransitionLog()
    r = cert.req
    log.append(TransitionRecord(
        trid=r.trid, h_P=r.h_P, h_P_prime=r.h_P_prime, delta_sym=r.delta_sym,
        tau=r.tau, tid=r.tid, sid=r.sid, aid=r.aid, uid=r.uid, detected=detected,
    ))
    return log


def test_pi_3_matching_transition_is_accepted():
    cat, cert, ctx = _risk_env(log=TransitionLog())
    ctx.transition_log = _log_for(cert)
    res = accept(cert, "send_email", {"to": "bob@example.com"}, ctx, cat,
                 ReplayStore())
    assert res.accepted, res


def test_pi_3_unknown_transition_rejected():
    cat, cert, ctx = _risk_env(log=TransitionLog())  # empty log
    res = accept(cert, "send_email", {"to": "bob@example.com"}, ctx, cat,
                 ReplayStore())
    assert not res.accepted
    assert res.rejected_clause == "pi_3"


def test_pi_3_undetected_transition_rejected():
    cat, cert, ctx = _risk_env(log=TransitionLog())
    ctx.transition_log = _log_for(cert, detected=False)
    res = accept(cert, "send_email", {"to": "bob@example.com"}, ctx, cat,
                 ReplayStore())
    assert not res.accepted
    assert res.rejected_clause == "pi_3"


def test_pi_3_evicted_transition_rejected():
    """Stale/expired transition records must not authorize new calls."""
    cat, cert, ctx = _risk_env(log=TransitionLog())
    log = _log_for(cert)
    log.evict(cert.req.trid)
    ctx.transition_log = log
    res = accept(cert, "send_email", {"to": "bob@example.com"}, ctx, cat,
                 ReplayStore())
    assert not res.accepted
    assert res.rejected_clause == "pi_3"


# ─── pi_8: atomic concurrency ─────────────────────────────────────────

def test_concurrent_check_and_consume_exactly_one_wins():
    store = ReplayStore()
    nonce = make_nonce()
    n = 64
    barrier = threading.Barrier(n)
    results: list[bool] = []
    lock = threading.Lock()

    def worker():
        barrier.wait()          # line every thread up before the race
        ok = store.check_and_consume(nonce)
        with lock:
            results.append(ok)

    threads = [threading.Thread(target=worker) for _ in range(n)]
    for th in threads:
        th.start()
    for th in threads:
        th.join()

    assert sum(results) == 1, f"expected exactly one winner, got {sum(results)}"


def test_concurrent_accept_exactly_one_effect():
    """Concurrent submissions of the SAME valid certificate: one accept."""
    cat, cert, ctx = _risk_env()
    store = ReplayStore()
    n = 32
    barrier = threading.Barrier(n)
    accepts: list[bool] = []
    lock = threading.Lock()

    def worker():
        barrier.wait()
        res = accept(cert, "send_email", {"to": "bob@example.com"}, ctx, cat, store)
        with lock:
            accepts.append(res.accepted)

    threads = [threading.Thread(target=worker) for _ in range(n)]
    for th in threads:
        th.start()
    for th in threads:
        th.join()

    assert sum(accepts) == 1, f"expected exactly one accept, got {sum(accepts)}"
