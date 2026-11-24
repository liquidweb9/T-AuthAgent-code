"""Approver-committee simulation.

A committee inspects a Req and returns either a Cert (>= t share
signatures combined) or None (refuse). The decision policy is a Python
predicate ``approver_policy(req) -> bool`` per approver, so tests can
stage scenarios like "2 out of 5 approvers always sign".

This module deliberately does not implement any judgement of policy
*quality*. T-AuthAgent claims only approval-result integrity, not
approval correctness; see outline.tex Limitations.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Optional

from .catalog import ApprovalCatalog, CatalogEntry
from .cert import Cert
from .req import Req
from .threshold_sig import ShareKey, combine, sign_share


ApproverPolicy = Callable[[Req, int], bool]


def always_approve(req: Req, approver_index: int) -> bool:
    return True


def never_approve(req: Req, approver_index: int) -> bool:
    return False


@dataclass
class Committee:
    """Wraps a catalog entry with per-approver decision policies."""
    catalog: ApprovalCatalog
    apid: str
    approver_policies: list[ApproverPolicy]
    rho_to_apid: dict[int, str] | None = None

    def _pick_apid(self, req: Req) -> str:
        # The request names the configuration it needs approved. If the
        # catalog knows it, that is the configuration whose shares must
        # sign -- this is what lets one committee serve several
        # independently keyed configurations (the risk-adaptive profile).
        if self.catalog.entry(req.apid) is not None:
            return req.apid
        if self.rho_to_apid and req.rho in self.rho_to_apid:
            return self.rho_to_apid[req.rho]
        return self.apid

    def approve(self, req: Req) -> Optional[Cert]:
        apid = self._pick_apid(req)
        entry: CatalogEntry | None = self.catalog.entry(apid)
        if entry is None:
            return None
        if entry.t != req.t or entry.cid != req.cid or entry.apid != req.apid:
            # Req declares a (apid, cid, t) that doesn't match the catalog
            # entry: the approver-side check rejects before signing.
            return None
        shares = self.catalog.shares(apid)
        signing_shares: list[ShareKey] = []
        for share in shares:
            if len(signing_shares) >= entry.t:
                break
            policy = self.approver_policies[share.index - 1]
            if policy(req, share.index):
                signing_shares.append(share)
        if len(signing_shares) < entry.t:
            return None
        msg = req.hash()
        parts = [sign_share(s, msg) for s in signing_shares]
        sigma = combine(parts)
        return Cert(req=req, sigma=sigma, mode="A")


def make_uniform_committee(
    catalog: ApprovalCatalog,
    apid: str,
    default_policy: ApproverPolicy = always_approve,
    n: int = 5,
) -> Committee:
    return Committee(
        catalog=catalog,
        apid=apid,
        approver_policies=[default_policy for _ in range(n)],
    )
