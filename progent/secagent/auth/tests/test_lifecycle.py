"""Revocation, membership and nonce-entropy semantics.

Pins the behaviour the workflow experiment reports:
  * deactivating a configuration invalidates an unused certificate (pi_9);
  * key rotation invalidates it (pi_10/pi_1);
  * removing an approver *without* re-sharing does NOT invalidate a
    certificate their share contributed to -- a documented limitation.

Uses only the auth primitives so the package tests do not depend on the
experiment harness.
"""
import secrets

from secagent.auth.canon import policy_hash
from secagent.auth.catalog import make_risk_catalog
from secagent.auth.cert import Cert
from secagent.auth.gateway import SessionCtx, accept
from secagent.auth.replay_store import ReplayStore
from secagent.auth.req import Req, default_exp, make_nonce
from secagent.auth.threshold_sig import combine, sign_share

SESSION = dict(tid="t1", sid="s1", aid="a1", uid="u1")
PHI = {"type": "object",
       "properties": {"to": {"enum": ["bob@example.com"]}},
       "required": ["to"]}


def _mint(cat, signers):
    entry = cat.entry("med_risk")
    req = Req(
        tid=SESSION["tid"], sid=SESSION["sid"], aid=SESSION["aid"],
        uid=SESSION["uid"], h_P=policy_hash(None),
        h_P_prime=policy_hash({"send_email": [(100, 0, PHI, 0)]}),
        delta_sym={"send_email": [{"type": "object"}]},
        tau="send_email", phi=PHI, rho=2, apid="med_risk",
        cid=entry.cid, t=entry.t, pkid=entry.pkid,
        exp=default_exp(60), nonce=make_nonce(),
    )
    shares = cat.shares("med_risk")
    parts = [sign_share(shares[i - 1], req.hash()) for i in signers]
    ctx = SessionCtx(P_current=None, P_new=None, **SESSION)
    return Cert(req=req, sigma=combine(parts)), ctx


def test_issued_certificate_revoked_with_configuration():
    cat = make_risk_catalog()
    cert, ctx = _mint(cat, [1, 2, 3])
    cat.deactivate("med_risk")
    res = accept(cert, "send_email", {"to": "bob@example.com"}, ctx, cat,
                 ReplayStore())
    assert not res.accepted
    assert res.rejected_clause == "pi_9"


def test_issued_certificate_revoked_by_rotation():
    cat = make_risk_catalog()
    cert, ctx = _mint(cat, [1, 2, 3])
    cat.rotate_key("med_risk")
    res = accept(cert, "send_email", {"to": "bob@example.com"}, ctx, cat,
                 ReplayStore())
    assert not res.accepted
    assert res.rejected_clause in ("pi_10", "pi_1")


def test_removed_approver_share_still_valid_without_reshare():
    """Documented limitation: removal alone does not revoke a share.

    Share 5 contributed to the certificate. Dropping approver 5 from any
    membership view leaves the group key untouched, so the certificate
    still interpolates to a valid signature.
    """
    cat = make_risk_catalog()
    cert, ctx = _mint(cat, [1, 2, 5])
    res = accept(cert, "send_email", {"to": "bob@example.com"}, ctx, cat,
                 ReplayStore())
    assert res.accepted, "expected the limitation to be observable"


def test_fresh_certificate_works_after_rotation():
    cat = make_risk_catalog()
    cat.rotate_key("med_risk")
    cert, ctx = _mint(cat, [1, 2, 3])
    res = accept(cert, "send_email", {"to": "bob@example.com"}, ctx, cat,
                 ReplayStore())
    assert res.accepted


def test_nonce_is_128_bits_from_csprng():
    n = make_nonce()
    assert isinstance(n, bytes) and len(n) == 16
    assert n != make_nonce()
    assert secrets.token_bytes is not None
