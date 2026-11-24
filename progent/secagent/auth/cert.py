"""Approval-expansion certificate.

A Cert is just (Req, Sigma, mode_tag). The signed message m is
``H(canon(Req.dump()))``. ``signers`` is a redundant index list for
debugging/audit only -- the gateway re-derives it from Sigma.

CBOR encoding lets us report a real |Cert| number for the paper.
"""
from __future__ import annotations

from dataclasses import dataclass, asdict
from typing import Any

import cbor2

from .canon import canon
from .req import Req
from .threshold_sig import CombinedSig


@dataclass
class Cert:
    req: Req
    sigma: CombinedSig
    mode: str = "A"             # "A" for BLS, "B" for Ed25519 multi-sig

    def to_wire(self) -> dict[str, Any]:
        return {
            "req": self.req.dump(),
            "sigma": self.sigma.to_wire(),
            "mode": self.mode,
        }

    def to_cbor(self) -> bytes:
        return canon(self.to_wire())

    @classmethod
    def from_cbor(cls, blob: bytes) -> "Cert":
        wire = cbor2.loads(blob)
        return cls(
            req=Req.model_validate(wire["req"]),
            sigma=CombinedSig.from_wire(wire["sigma"]),
            mode=wire.get("mode", "B"),
        )

    def size_bytes(self) -> int:
        return len(self.to_cbor())
