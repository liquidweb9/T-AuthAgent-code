"""Consumed-nonce set R.

The gateway atomically (a) checks ``nonce not in R`` and (b) inserts on
accept. The store is process-local for the prototype -- single-process
experiments don't need anything more, and we explicitly call this out in
the plan as a known limitation.
"""
from __future__ import annotations

import threading


class ReplayStore:
    def __init__(self) -> None:
        self._used: set[bytes] = set()
        self._lock = threading.Lock()

    def seen(self, nonce: bytes) -> bool:
        with self._lock:
            return nonce in self._used

    def mark(self, nonce: bytes) -> None:
        with self._lock:
            self._used.add(nonce)

    def check_and_consume(self, nonce: bytes) -> bool:
        """Atomic seen-then-mark. Returns False if nonce was already used."""
        with self._lock:
            if nonce in self._used:
                return False
            self._used.add(nonce)
            return True

    def clear(self) -> None:
        with self._lock:
            self._used.clear()


_default = ReplayStore()


def default_store() -> ReplayStore:
    return _default
