"""Authenticated transition log L for gateway clause pi_3.

When Progent's expansion detector classifies ``P -> P'`` as an expansion,
the record builder writes one entry per affected high-risk tool into this
log. The gateway looks the entry up by ``trid`` and requires that it
matches every field the certificate carries:

    L[trid] = (h_P, h_P', delta_sym, tau, tid, sid, aid, uid, detected)

This is what makes the certificate bound to a *detected* transition rather
than to an arbitrary policy pair: a request whose ``trid`` is unknown, or
whose hashes/delta/context disagree with the recorded transition, fails
pi_3 even if it carries a perfectly valid signature.

The prototype store is in-process and append-only within a run. The paper
treats the log as authenticated state (signed / append-only deployment);
the experiment document lists that as an assumption, not an implemented
mechanism. ``TransitionLog`` here is the *interface* the gateway consumes.
"""
from __future__ import annotations

import threading
from dataclasses import dataclass
from typing import Optional


@dataclass(frozen=True)
class TransitionRecord:
    trid: str
    h_P: str
    h_P_prime: str
    delta_sym: dict
    tau: str
    tid: str
    sid: str
    aid: str
    uid: str
    detected: bool = True


class TransitionLog:
    """Append-only, in-process transition log."""

    def __init__(self) -> None:
        self._records: dict[str, TransitionRecord] = {}
        self._order: list[str] = []
        self._lock = threading.Lock()

    def append(self, rec: TransitionRecord) -> None:
        with self._lock:
            if rec.trid not in self._records:
                self._order.append(rec.trid)
            self._records[rec.trid] = rec

    def get(self, trid: str) -> Optional[TransitionRecord]:
        with self._lock:
            return self._records.get(trid)

    def __contains__(self, trid: str) -> bool:
        return self.get(trid) is not None

    def __len__(self) -> int:
        return len(self._records)

    def clear(self) -> None:
        with self._lock:
            self._records.clear()
            self._order.clear()

    def evict(self, trid: str) -> None:
        """Drop a record (used by transition-expiry tests)."""
        with self._lock:
            self._records.pop(trid, None)
            if trid in self._order:
                self._order.remove(trid)


_default = TransitionLog()


def default_log() -> TransitionLog:
    return _default


def matches(rec: Optional[TransitionRecord], *, h_P: str, h_P_prime: str,
            delta_sym: dict, tau: str, tid: str, sid: str, aid: str,
            uid: str) -> bool:
    """The pi_3 equality test, factored out so tests can target it directly."""
    if rec is None or not rec.detected:
        return False
    return (
        rec.h_P == h_P
        and rec.h_P_prime == h_P_prime
        and rec.delta_sym == delta_sym
        and rec.tau == tau
        and rec.tid == tid
        and rec.sid == sid
        and rec.aid == aid
        and rec.uid == uid
    )
