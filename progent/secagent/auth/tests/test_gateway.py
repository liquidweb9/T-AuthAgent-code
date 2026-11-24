"""Each of pi_1 .. pi_8 has a dedicated failure-injection test.

pi_3 has only a single conjunct in this prototype (h_P), see gateway.py.
pi_9 is exercised inside the catalog-mismatch test.
"""
import copy
import time

import pytest

from secagent.auth.canon import policy_hash
from secagent.auth.catalog import make_default_catalog
from secagent.auth.cert import Cert
from secagent.auth.committee import make_uniform_committee
from secagent.auth.gateway import SessionCtx, accept
from secagent.auth.replay_store import ReplayStore
from secagent.auth.req import Req, default_exp, make_nonce
from secagent.auth.threshold_sig import CombinedSig, SignatureShare


SESSION = dict(tid="t1", sid="s1", aid="a1", uid="u1")


def _make_env(rho=1, apid="low_risk", t=2, install_current=None,
              tau="send_email", delta_tau=None, phi=None, ttl=60, nonce=None):
    """Build a Req, get a Cert from the committee, plus the matching ctx."""
    catalog = make_default_catalog()
    entry = catalog.entry(apid)
    committee = make_uniform_committee(catalog, apid=apid, n=entry.n)
    P_current = install_current
    delta_tau = delta_tau or tau
    req = Req(
        tid=SESSION["tid"], sid=SESSION["sid"], aid=SESSION["aid"], uid=SESSION["uid"],
        h_P=policy_hash(P_current),
        h_P_prime=policy_hash({delta_tau: [(100, 0, {"type": "object"}, 0)]}),
        delta_sym={delta_tau: [{"type": "object"}]},
        tau=tau,
        phi=phi or {},
        rho=rho,
        apid=apid, cid=entry.cid, t=t,
        exp=default_exp(ttl),
        nonce=nonce or make_nonce(),
    )
    cert = committee.approve(req)
    assert cert is not None, "committee should approve happy-path Req"
    ctx = SessionCtx(P_current=P_current, P_new=None, **SESSION)
    return catalog, committee, cert, ctx


def test_happy_path_accepted():
    cat, _, cert, ctx = _make_env()
    res = accept(cert, "send_email", {"to": "bob@x"}, ctx, cat, ReplayStore())
    assert res.accepted, res
    assert res.verify_ns > 0


def test_pi_1_signature_tamper():
    cat, _, cert, ctx = _make_env()
    # Flip one bit in the first signature
    parts = list(cert.sigma.parts)
    bad_sig = bytes([parts[0].sig[0] ^ 0x01]) + parts[0].sig[1:]
    parts[0] = SignatureShare(parts[0].index, bad_sig)
    tampered = Cert(req=cert.req, sigma=CombinedSig(tuple(parts)))
    res = accept(tampered, "send_email", {"to": "bob"}, ctx, cat, ReplayStore())
    assert not res.accepted
    assert res.rejected_clause == "pi_1"


def test_pi_2_identity_mismatch():
    cat, _, cert, ctx = _make_env()
    ctx_wrong = SessionCtx(tid="OTHER", sid=ctx.sid, aid=ctx.aid, uid=ctx.uid,
                           P_current=ctx.P_current, P_new=None)
    res = accept(cert, "send_email", {"to": "bob"}, ctx_wrong, cat, ReplayStore())
    assert not res.accepted
    assert res.rejected_clause == "pi_2"


def test_pi_3_policy_drift():
    cat, _, cert, ctx = _make_env(install_current=None)
    # Simulate policy drift: gateway sees a different P_current
    ctx_drift = SessionCtx(P_current={"x": [(100, 0, {}, 0)]}, P_new=None, **SESSION)
    res = accept(cert, "send_email", {"to": "bob"}, ctx_drift, cat, ReplayStore())
    assert not res.accepted
    assert res.rejected_clause == "pi_3"


def test_pi_4_wrong_tool():
    cat, _, cert, ctx = _make_env(tau="send_email", delta_tau="send_email")
    res = accept(cert, "delete_file", {"path": "/x"}, ctx, cat, ReplayStore())
    assert not res.accepted
    assert res.rejected_clause == "pi_4"


def test_pi_5_args_outside_delta():
    """pi_5: delta_sym says args must satisfy {type: object} (anything is an object).
    To force pi_5 failure, use a stricter delta -- to-restricted -- and then
    call with a non-object payload (string)."""
    cat = make_default_catalog()
    entry = cat.entry("low_risk")
    committee = make_uniform_committee(cat, apid="low_risk", n=entry.n)
    req = Req(
        tid=SESSION["tid"], sid=SESSION["sid"], aid=SESSION["aid"], uid=SESSION["uid"],
        h_P=policy_hash(None),
        h_P_prime=policy_hash({"send_email": [(100, 0, {"type": "object",
                       "properties": {"to": {"enum": ["bob@x"]}}}, 0)]}),
        delta_sym={"send_email": [{"type": "object",
                       "properties": {"to": {"enum": ["bob@x"]}},
                       "required": ["to"]}]},
        tau="send_email", phi={}, rho=1, apid="low_risk", cid=entry.cid, t=2,
        exp=default_exp(60), nonce=make_nonce(),
    )
    cert = committee.approve(req)
    ctx = SessionCtx(P_current=None, P_new=None, **SESSION)
    res = accept(cert, "send_email", {"to": "eve@evil"}, ctx, cat, ReplayStore())
    assert not res.accepted
    assert res.rejected_clause == "pi_5"


def test_pi_6_phi_violation():
    cat = make_default_catalog()
    entry = cat.entry("low_risk")
    committee = make_uniform_committee(cat, apid="low_risk", n=entry.n)
    phi = {"type": "object", "properties": {"to": {"enum": ["bob@x"]}}, "required": ["to"]}
    req = Req(
        tid=SESSION["tid"], sid=SESSION["sid"], aid=SESSION["aid"], uid=SESSION["uid"],
        h_P=policy_hash(None),
        h_P_prime=policy_hash({"send_email": [(100, 0, {"type": "object"}, 0)]}),
        delta_sym={"send_email": [{"type": "object"}]},  # delta permissive
        tau="send_email", phi=phi, rho=1, apid="low_risk", cid=entry.cid, t=2,
        exp=default_exp(60), nonce=make_nonce(),
    )
    cert = committee.approve(req)
    ctx = SessionCtx(P_current=None, P_new=None, **SESSION)
    res = accept(cert, "send_email", {"to": "eve@evil"}, ctx, cat, ReplayStore())
    assert not res.accepted
    assert res.rejected_clause == "pi_6"


def test_pi_7_expired():
    cat, _, cert, ctx = _make_env()
    res = accept(cert, "send_email", {"to": "bob"}, ctx, cat, ReplayStore(),
                 now=int(time.time()) + 10_000)
    assert not res.accepted
    assert res.rejected_clause == "pi_7"


def test_pi_8_replay():
    cat, _, cert, ctx = _make_env()
    store = ReplayStore()
    r1 = accept(cert, "send_email", {"to": "bob"}, ctx, cat, store)
    assert r1.accepted
    r2 = accept(cert, "send_email", {"to": "bob"}, ctx, cat, store)
    assert not r2.accepted
    assert r2.rejected_clause == "pi_8"


def test_pi_9_unknown_apid():
    cat, _, cert, ctx = _make_env()
    # Mutate the cert's apid to one not in the catalog
    bad_req = cert.req.model_copy(update={"apid": "ghost"})
    bad_cert = Cert(req=bad_req, sigma=cert.sigma)
    res = accept(bad_cert, "send_email", {"to": "bob"}, ctx, cat, ReplayStore())
    assert not res.accepted
    assert res.rejected_clause == "pi_9"
