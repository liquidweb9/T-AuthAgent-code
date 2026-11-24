"""ApprovalCatalog: registry of approval configurations.

Each entry binds a configuration ``gamma = (apid, cid, t, pkid)`` to an
*independently generated* threshold key: threshold ``t``, total ``n``, group
public key, and a public-key identifier ``pkid``. Distinct configurations
therefore have distinct keys, which is what prevents a valid low-threshold
signature from satisfying a high-threshold request (pi_10, pi_12).

The gateway uses the catalog to implement:

    pi_9   (apid) in C  and  C[apid].active == 1
    pi_10  C[apid].pk == the key the signature was verified under, and
           C[apid].pkid == Req.pkid
    pi_12  S(rho) == apid          (risk selector consistency)

Stock entries (risk-adaptive profile, matching experiment spec section 6):

    low_risk   t=3 n=5   serves rho=low
    med_risk   t=3 n=5   serves rho=medium
    high_risk  t=4 n=5   serves rho=high

``register`` also accepts ``risk_tier=None`` for configurations that are
not part of the risk selector (e.g. the single-approver ablation); those
entries are exempt from pi_11/pi_12 (documented prototype limitation).
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from .threshold_sig import GroupKey, ShareKey, setup


@dataclass(frozen=True)
class CatalogEntry:
    apid: str
    cid: str
    t: int
    n: int
    group: GroupKey
    pkid: str = ""
    active: bool = True
    risk_tier: str | None = None   # "low" | "medium" | "high" | None


class ApprovalCatalog:
    """In-memory registry. The prototype runs in a single process so a
    plain dict is enough; real deployments would back this with a
    transparency log.
    """

    def __init__(self) -> None:
        self._entries: dict[str, CatalogEntry] = {}
        self._shares: dict[str, list[ShareKey]] = {}

    def register(self, apid: str, cid: str, t: int, n: int,
                 pkid: str | None = None, active: bool = True,
                 risk_tier: str | None = None) -> CatalogEntry:
        group, shares = setup(n=n, t=t)
        entry = CatalogEntry(
            apid=apid, cid=cid, t=t, n=n, group=group,
            pkid=pkid if pkid is not None else f"pk::{apid}",
            active=active, risk_tier=risk_tier,
        )
        self._entries[apid] = entry
        self._shares[apid] = shares
        return entry

    def entry(self, apid: str) -> Optional[CatalogEntry]:
        return self._entries.get(apid)

    def shares(self, apid: str) -> list[ShareKey]:
        return self._shares.get(apid, [])

    def config_for_tier(self, tier: str) -> Optional[CatalogEntry]:
        """Selector S: the catalog entry bound to a risk tier."""
        for entry in self._entries.values():
            if entry.risk_tier == tier and entry.active:
                return entry
        return None

    def has_risk_policy(self) -> bool:
        """True iff this catalog declares a risk selector (pi_11/pi_12 on)."""
        return any(e.risk_tier is not None for e in self._entries.values())

    def deactivate(self, apid: str) -> None:
        """Revoke a configuration (rotation / revocation tests)."""
        old = self._entries.get(apid)
        if old is None:
            return
        self._entries[apid] = CatalogEntry(
            apid=old.apid, cid=old.cid, t=old.t, n=old.n, group=old.group,
            pkid=old.pkid, active=False, risk_tier=old.risk_tier,
        )

    def rotate_key(self, apid: str) -> CatalogEntry:
        """Rebind an existing apid to a *fresh* threshold key (rotation)."""
        old = self._entries.get(apid)
        if old is None:
            raise KeyError(apid)
        group, shares = setup(n=old.n, t=old.t)
        entry = CatalogEntry(
            apid=apid, cid=old.cid, t=old.t, n=old.n, group=group,
            pkid=f"{old.pkid}::v2", active=True, risk_tier=old.risk_tier,
        )
        self._entries[apid] = entry
        self._shares[apid] = shares
        return entry

    def __contains__(self, apid: str) -> bool:
        return apid in self._entries


def make_default_catalog() -> ApprovalCatalog:
    """Legacy two-entry catalog WITHOUT a risk selector.

    Kept for backwards compatibility with the original unit tests and the
    non-risk baselines. pi_11/pi_12 are not enforced against this catalog.
    """
    cat = ApprovalCatalog()
    cat.register(apid="low_risk", cid="committee_main", t=2, n=5, pkid="")
    cat.register(apid="high_risk", cid="committee_main", t=4, n=5, pkid="")
    return cat


def make_risk_catalog(low_t: int = 3, med_t: int = 3, high_t: int = 4,
                      n: int = 5, cid: str = "committee_main") -> ApprovalCatalog:
    """Risk-adaptive catalog: three independently keyed configurations.

    This is the catalog the (3,5)/(4,5) risk-adaptive baseline uses, and
    the one against which pi_11/pi_12 are enforced.
    """
    cat = ApprovalCatalog()
    cat.register(apid="low_risk", cid=cid, t=low_t, n=n, risk_tier="low")
    cat.register(apid="med_risk", cid=cid, t=med_t, n=n, risk_tier="medium")
    cat.register(apid="high_risk", cid=cid, t=high_t, n=n, risk_tier="high")
    return cat


def make_single_catalog(t: int = 1, n: int = 1) -> ApprovalCatalog:
    """Single-approver ablation configuration (no risk selector)."""
    cat = ApprovalCatalog()
    cat.register(apid="single", cid="committee_single", t=t, n=n)
    return cat
