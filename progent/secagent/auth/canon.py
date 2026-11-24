"""Canonical encoding helpers.

The whole approval-integrity argument rests on a single contract:
``H(canon(Req))`` must be byte-identical for every party that signs or
verifies it. We pick deterministic CBOR (RFC 8949 section 4.2) -- it has
the property we need (sorted map keys, shortest int encoding, no float NaN
oddities) and a clean Python implementation in ``cbor2``.

``policy_hash`` collapses a Progent ``security_policy`` dict (whose values
are tuples) into a stable byte string before hashing, so that the
ordering of (priority, effect, condition, fallback) is preserved.
"""
import hashlib
from typing import Any

import cbor2


def canon(obj: Any) -> bytes:
    """Deterministic CBOR encoding."""
    return cbor2.dumps(obj, canonical=True)


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def policy_hash(policy: dict | None) -> str:
    """Stable SHA-256 of a Progent security_policy dict.

    Progent stores each entry as a 4-tuple ``(priority, effect, cond, fb)``;
    CBOR will serialize a tuple as an array of length 4, which is what we
    want. Keys are sorted by ``canon``.
    """
    if policy is None:
        return sha256_hex(b"\x00")
    normalized: dict[str, list[list[Any]]] = {}
    for tool, entries in policy.items():
        normalized[tool] = [list(e) for e in entries]
    return sha256_hex(canon(normalized))
