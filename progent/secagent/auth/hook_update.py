"""tool.py:464 hook -- build Req, ask committee, park Cert in ContextVar.

This is the single integration point between Progent's policy lifecycle
and the T-AuthAgent approval layer. Called from
``generate_update_security_policy`` whenever ``security_policy_subset_check``
rejects the LLM-proposed update.

The default behavior (Progent) was to discard the proposal silently;
T-AuthAgent replaces that with: synthesize a Req describing the requested
expansion, hand it to the committee, and -- on success -- write the
returned Cert into the per-task ContextVar so the very next
``check_tool_call`` can present it to the gateway.
"""
from __future__ import annotations

import os
import sys
from typing import Any

from . import risk as risk_mod
from .canon import policy_hash
from .catalog import ApprovalCatalog, make_default_catalog
from .cert import Cert
from .committee import Committee, make_uniform_committee
from .context import set_pending
from .req import Req, default_exp, make_nonce
from .transition_log import TransitionLog, TransitionRecord, default_log


# Module-level catalog + committee + session context. The experiment
# harness can swap them via ``configure(...)`` for adversarial setups
# (corrupted approvers, swapped apid, etc.).
_catalog: ApprovalCatalog = make_default_catalog()
_committee: Committee = make_uniform_committee(_catalog, apid="low_risk")
_transition_log: TransitionLog = default_log()
_session = {
    "tid": "task-default",
    "sid": "sess-default",
    "aid": "agent-default",
    "uid": "user-default",
}


def configure(
    *,
    catalog: ApprovalCatalog | None = None,
    committee: Committee | None = None,
    transition_log: TransitionLog | None = None,
    tid: str | None = None,
    sid: str | None = None,
    aid: str | None = None,
    uid: str | None = None,
) -> None:
    global _catalog, _committee, _transition_log
    if catalog is not None:
        _catalog = catalog
    if committee is not None:
        _committee = committee
    if transition_log is not None:
        _transition_log = transition_log
    for k, v in (("tid", tid), ("sid", sid), ("aid", aid), ("uid", uid)):
        if v is not None:
            _session[k] = v


def current_catalog() -> ApprovalCatalog:
    return _catalog


def current_transition_log() -> TransitionLog:
    return _transition_log


def current_session() -> dict[str, str]:
    return dict(_session)


def normalize_condition(cond: Any) -> dict:
    """Lift a Progent per-argument condition into a whole-argument schema.

    Progent stores an argument condition as ``{arg_name: restriction}``
    (see ``policy_analysis.py`` and ``tool.check_arg``), e.g.
    ``{"to": {"enum": ["bob@example.com"]}}``. The certificate binds a
    predicate over the *whole* argument object, so the per-argument mapping
    is lifted to ``{"type": "object", "properties": {...}, "required": [...]}``.

    A condition that is already object-shaped is passed through unchanged.
    Without this step the signed ``Delta_sym``/``Phi`` would be a per-arg
    mapping, which JSON Schema evaluation silently ignores (unknown
    keywords), so the gateway would accept arguments the policy forbids.
    """
    if not isinstance(cond, dict):
        return {"type": "object"}
    if cond.get("type") == "object" or "properties" in cond:
        return cond
    props = {k: v for k, v in cond.items()}
    normalized: dict[str, Any] = {"type": "object", "properties": props}
    if props:
        normalized["required"] = list(props.keys())
    return normalized


def _delta_sym(old_policy: dict | None, new_policy: dict | None) -> dict:
    """Tool -> list of *object-schema* condition dicts new in P' vs P.

    Mirrors ``security_policy_subset_check`` granularity: we only consider
    priority-100 entries (the LLM-generated ones). The conditions are
    normalized from Progent's per-argument shape to the whole-object shape
    the certificate signs.
    """
    old = {} if old_policy is None else old_policy
    new = {} if new_policy is None else new_policy
    delta: dict[str, list[dict[str, Any]]] = {}
    for tool, entries in new.items():
        new_dyn = [e for e in entries if len(e) == 4 and e[0] == 100]
        old_dyn = [e for e in old.get(tool, []) if len(e) == 4 and e[0] == 100]
        old_conds = [e[2] for e in old_dyn]
        new_only = [normalize_condition(e[2]) for e in new_dyn
                    if e[2] not in old_conds]
        if new_only:
            delta[tool] = new_only
    return delta


def _transition_log_id(old_policy: dict | None, new_policy: dict | None,
                       tau: str) -> str:
    """Deterministic transition id: binds (P, P', tool).

    The gateway only needs to look the record up by key; deriving the id
    deterministically from the transition makes it reproducible across the
    request builder and any auditor replaying the same policy pair.
    """
    raw = f"{policy_hash(old_policy)}|{policy_hash(new_policy)}|{tau}"
    import hashlib
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:32]


def _focal_tool(
    delta: dict, tool_call_param: list[dict] | None
) -> tuple[str, dict]:
    """Pick the (tool, phi) the Req is authorizing.

    Strategy: prefer the just-called tool if it shows up in delta;
    otherwise the first tool in delta. ``phi`` is the matching condition.
    """
    called: str | None = None
    if tool_call_param:
        called = tool_call_param[0].get("name")
    if called and called in delta and delta[called]:
        return called, delta[called][0]
    if delta:
        tool = next(iter(delta))
        return tool, delta[tool][0] if delta[tool] else {}
    return "", {}


def _risk_tier(delta: dict, phi: dict | None = None,
               tau: str | None = None) -> int:
    """Risk tier via the fixed model in ``risk.py`` (spec section 6).

    Kept under this name so existing call sites are unchanged. The tier is
    recomputed identically by the gateway in pi_11.
    """
    tool = tau or next(iter(delta), "")
    return risk_mod.assess(tool, phi or {}).tier_int


def handle_expansion(
    *,
    old_policy: dict | None,
    new_policy: dict | None,
    generated_policy: list[dict] | None,
    tool_call_param: list[dict] | None,
) -> Cert | None:
    """Build Req, call committee, return Cert (or None on refuse)."""
    delta = _delta_sym(old_policy, new_policy)
    if not delta:
        # Subset-check failed but our diff produced nothing -- nothing to
        # authorize. Treat as silent discard, same as Progent default.
        return None
    tau, phi = _focal_tool(delta, tool_call_param)
    if not tau:
        return None
    rho = _risk_tier(delta, phi, tau)
    catalog = _catalog
    # Pick the catalog entry for this rho. When the catalog declares a
    # risk selector (the risk-adaptive baseline), S(rho) is authoritative
    # and the gateway will re-derive it in pi_12. Otherwise fall back to
    # the committee's explicit rho->apid map, then to its default apid.
    if catalog.has_risk_policy():
        entry = catalog.config_for_tier(risk_mod.TIER_INT_TO_NAME[rho])
        apid = entry.apid if entry is not None else ""
    elif _committee.rho_to_apid and rho in _committee.rho_to_apid:
        apid = _committee.rho_to_apid[rho]
        entry = catalog.entry(apid)
    else:
        apid = _committee.apid
        entry = catalog.entry(apid)
    if entry is None:
        print(f"[hook_update] apid {apid!r} not in catalog; refuse", file=sys.stderr)
        return None

    # Record the detected transition so the gateway can bind pi_3 to it.
    trid = _transition_log_id(old_policy, new_policy, tau)
    _transition_log.append(TransitionRecord(
        trid=trid,
        h_P=policy_hash(old_policy),
        h_P_prime=policy_hash(new_policy),
        delta_sym=delta,
        tau=tau,
        tid=_session["tid"], sid=_session["sid"],
        aid=_session["aid"], uid=_session["uid"],
        detected=True,
    ))

    req = Req(
        trid=trid,
        tid=_session["tid"],
        sid=_session["sid"],
        aid=_session["aid"],
        uid=_session["uid"],
        h_P=policy_hash(old_policy),
        h_P_prime=policy_hash(new_policy),
        delta_sym=delta,
        tau=tau,
        phi=phi,
        rho=rho,
        apid=apid,
        cid=entry.cid,
        t=entry.t,
        pkid=entry.pkid,
        exp=default_exp(int(os.getenv("SECAGENT_CERT_TTL_SEC", "60"))),
        nonce=make_nonce(),
    )
    cert = _committee.approve(req)
    if cert is None:
        print(
            f"[hook_update] committee refused Req for tool {tau!r} (rho={rho})",
            file=sys.stderr,
        )
        return None
    set_pending(cert)
    print(
        f"[hook_update] cert minted: tau={tau} rho={rho} t={req.t} "
        f"|cert|={cert.size_bytes()}B",
        file=sys.stderr,
    )
    return cert
