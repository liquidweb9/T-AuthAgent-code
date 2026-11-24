"""Approval request structure (Req v2).

Field set matches the paper's `def:req` -- ver, trid, tid, sid, aid, uid,
h_P, h_P_prime, delta_sym, tau, phi, rho, apid, cid, t, pkid, exp, nonce.

``trid`` is the *transition* id used by pi_3 to look the detected expansion
up in the transition log; ``pkid`` is the public-key identifier used by
pi_10 to pin the configuration's key.

`Req` is intentionally a plain Pydantic model: it carries no signing
behavior, only data + canonical hashing. The committee signs
``H(canon(req.dump()))`` and the gateway re-computes that same hash on
the receive side so any tampering breaks pi_1.
"""
from __future__ import annotations

import os
import secrets
import time
from typing import Any

from pydantic import BaseModel, Field

from .canon import canon, sha256


REQ_VERSION = 2


class Req(BaseModel):
    ver: int = REQ_VERSION
    trid: str = ""      # transition id (pi_3 log key)
    tid: str            # task_id
    sid: str            # session_id
    aid: str            # agent_id
    uid: str            # user_id
    h_P: str            # SHA-256 of canon(current policy)
    h_P_prime: str      # SHA-256 of canon(proposed policy)
    delta_sym: dict[str, Any]   # {tool -> [JSON-schema cond, ...]} expansion delta
    tau: str            # tool name being authorized
    phi: dict[str, Any]         # JSON-schema argument constraint (per-arg)
    rho: int = Field(ge=1, le=3)
    apid: str           # approval-policy id (which catalog entry to use)
    cid: str            # committee id
    t: int = Field(ge=1)
    pkid: str = ""      # public-key identifier (pi_10)
    exp: int            # unix seconds
    nonce: bytes        # 16 random bytes

    model_config = {"arbitrary_types_allowed": True}

    def dump(self) -> dict[str, Any]:
        """A plain JSON-able dict used for canonical encoding.

        ``model_dump`` would produce numpy/datetime quirks; this version
        forces primitives only and a fixed key order so canon() is stable.
        """
        return {
            "ver": self.ver,
            "trid": self.trid,
            "tid": self.tid,
            "sid": self.sid,
            "aid": self.aid,
            "uid": self.uid,
            "h_P": self.h_P,
            "h_P_prime": self.h_P_prime,
            "delta_sym": self.delta_sym,
            "tau": self.tau,
            "phi": self.phi,
            "rho": self.rho,
            "apid": self.apid,
            "cid": self.cid,
            "t": self.t,
            "pkid": self.pkid,
            "exp": self.exp,
            "nonce": self.nonce,
        }

    def hash(self) -> bytes:
        return sha256(canon(self.dump()))


def make_nonce() -> bytes:
    return secrets.token_bytes(16)


def default_exp(ttl_seconds: int = 60) -> int:
    return int(time.time()) + ttl_seconds
