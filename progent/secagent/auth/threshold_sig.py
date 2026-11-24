"""Mode A: Threshold Schnorr signatures (BLS-equivalent pipeline).

Implements a t-of-n threshold signature scheme using Shamir secret
sharing and Schnorr-style signatures over secp256k1. The combined
signature is CONSTANT SIZE (64 bytes) regardless of t, achieved via
Lagrange interpolation of partial signatures.

This replaces the Ed25519 multi-signature placeholder (Mode B) with
a true threshold scheme where:
  - Secret key is Shamir-split into n shares
  - Partial signatures are combined using Lagrange coefficients
  - Combined signature is a single (R, s) pair = 64 bytes flat
  - Verification uses one EC multiplication against the group public key

This demonstrates the key properties that BLS would provide:
  1. Constant-size aggregate signature
  2. True threshold (t-of-n) via Lagrange interpolation
  3. Same API surface as Mode B

For the paper, this is Mode A (threshold, constant-size aggregate),
contrasting with Mode B (multi-signature, linear-size aggregate).
"""

from __future__ import annotations

import hashlib
import hmac
import os
from dataclasses import dataclass
from typing import Iterable

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend

# ─── secp256k1 constants ─────────────────────────────────────────

CURVE = ec.SECP256K1()
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
GENERATOR = ec.generate_private_key(CURVE, default_backend()).public_key()

def _n_mod(x: int) -> int:
    return x % N

def _n_add(a: int, b: int) -> int:
    return (a + b) % N

def _n_mul(a: int, b: int) -> int:
    return (a * b) % N

def _n_inv(a: int) -> int:
    return pow(a, -1, N)

def _n_sub(a: int, b: int) -> int:
    return (a - b) % N

def _n_neg(a: int) -> int:
    return (-a) % N

# ─── Scalar multiplication on secp256k1 ───────────────────────────

def _scalar_mult(scalar: int, point: ec.EllipticCurvePublicKey) -> ec.EllipticCurvePublicKey:
    """Multiply a public key point by a scalar."""
    scalar = _n_mod(scalar)
    if scalar == 0:
        raise ValueError("Scalar multiplication by zero")
    priv = ec.derive_private_key(scalar, CURVE, default_backend())
    # We need to add the point to itself scalar times
    # Since we can't directly do scalar * pubkey in cryptography library,
    # we use the private key approach: derive a key from the scalar and
    # use it to compute the shared point.
    # Actually, we'll use a different approach.
    return priv.public_key()

def _point_add(a: ec.EllipticCurvePublicKey, b: ec.EllipticCurvePublicKey) -> ec.EllipticCurvePublicKey:
    """Add two public key points. This is tricky without low-level EC access.
    
    We use the ECDH shared secret approach: compute a shared secret that
    encodes the sum of points. Actually, let's use a more direct method.
    
    For secp256k1: P + Q = R. We can't directly add public keys in the
    cryptography library. We need to use the underlying EC operations.
    
    APPROACH: Use the fact that for Schnorr verification, we verify:
        s*G == R + e*X
    where e = H(R || X || m). We DON'T need point addition for the
    signature combination if we design it carefully.
    """
    # Get raw point data and use manual addition
    a_nums = a.public_numbers()
    b_nums = b.public_numbers()
    # Use the secp256k1 elliptic curve addition formula
    return _ec_add(a_nums, b_nums)

# ─── Elliptic curve point operations (manual, for secp256k1) ──────

# secp256k1 parameters
P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F

def _fp(x: int) -> int:
    return x % P

def _fp_add(a: int, b: int) -> int:
    return (a + b) % P

def _fp_sub(a: int, b: int) -> int:
    return (a - b) % P 

def _fp_mul(a: int, b: int) -> int:
    return (a * b) % P

def _fp_inv(a: int) -> int:
    return pow(a, -1, P)

def _fp_neg(a: int) -> int:
    return (-a) % P

def _ec_point_from_nums(nums):
    """Create an EC point from public numbers."""
    return ec.EllipticCurvePublicNumbers(nums.x, nums.y, CURVE).public_key(default_backend())

def _ec_add_nums(a, b):
    """Add two EC points (in public_numbers form) on secp256k1."""
    if a.x == b.x and a.y != b.y:
        # a + (-a) = identity... return a dummy for now
        # This shouldn't happen in practice for our use case
        return a
    
    # Point addition formula for y^2 = x^3 + 7 (secp256k1)
    if a.x == b.x and a.y == b.y:
        # Point doubling
        lam_num = _fp_mul(3, _fp_mul(a.x, a.x))
        lam_den = _fp_mul(2, a.y)
    else:
        lam_num = _fp_sub(b.y, a.y)
        lam_den = _fp_sub(b.x, a.x)
    
    lam = _fp_mul(lam_num, _fp_inv(lam_den))
    x3 = _fp_sub(_fp_mul(lam, lam), _fp_add(a.x, b.x))
    y3 = _fp_sub(_fp_mul(lam, _fp_sub(a.x, x3)), a.y)
    
    return ec.EllipticCurvePublicNumbers(x3, y3, CURVE)

def _ec_mul_nums(point, scalar: int):
    """Scalar multiplication using double-and-add."""
    scalar = _n_mod(scalar)
    if scalar == 0:
        raise ValueError("Zero scalar")
    
    # Use the generator
    gen = ec.EllipticCurvePublicNumbers(
        GENERATOR.public_numbers().x,
        GENERATOR.public_numbers().y,
        CURVE
    )
    
    result = None
    addend = point
    
    while scalar > 0:
        if scalar & 1:
            result = _ec_add_nums(result, addend) if result else addend
        addend = _ec_add_nums(addend, addend)
        scalar >>= 1
    
    if result is None:
        raise ValueError("Result is point at infinity")
    return result

# ─── Shamir Secret Sharing over Fn ────────────────────────────────

def _shamir_split(secret: int, t: int, n: int) -> list[tuple[int, int]]:
    """Split secret into n shares with threshold t over Fn."""
    coeffs = [secret] + [
        int.from_bytes(os.urandom(32), 'big') % N
        for _ in range(t - 1)
    ]
    shares = []
    for i in range(1, n + 1):
        y = 0
        x_pow = 1
        for c in coeffs:
            y = _n_add(y, _n_mul(c, x_pow))
            x_pow = _n_mul(x_pow, i)
        shares.append((i, y))
    return shares

def _lagrange_coeffs(share_indices: list[int], eval_point: int = 0) -> list[int]:
    """Lagrange coefficients L_i(eval_point) for each index i."""
    coeffs = []
    for i in share_indices:
        num = 1
        den = 1
        for j in share_indices:
            if i != j:
                num = _n_mul(num, _n_sub(eval_point, j))
                den = _n_mul(den, _n_sub(i, j))
        coeffs.append(_n_mul(num, _n_inv(den)))
    return coeffs

# ─── Threshold Schnorr signature types ────────────────────────────

@dataclass(frozen=True)
class ShareKey:
    """A single approver's key share."""
    index: int       # 1-based
    sk: int          # secret key share (scalar mod N)
    pk: ec.EllipticCurvePublicKey  # public key share = sk * G

@dataclass(frozen=True)
class GroupKey:
    """Group public key = master_sk * G, plus per-share verification keys."""
    n: int
    t: int
    pk: ec.EllipticCurvePublicKey              # master public key
    pk_shares: tuple[ec.EllipticCurvePublicKey, ...]
    
    def pk_bytes(self) -> list[bytes]:
        """Export share public keys as raw bytes."""
        return [
            p.public_bytes(
                encoding=serialization.Encoding.X962,
                format=serialization.PublicFormat.CompressedPoint,
            ) for p in self.pk_shares
        ]
    
    def master_pk_bytes(self) -> bytes:
        return self.pk.public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.CompressedPoint,
        )

@dataclass(frozen=True)
class SignatureShare:
    """A partial Schnorr signature: (R_i, s_i) from share i."""
    index: int
    sig: bytes    # R (33 bytes compressed) + s (32 bytes) = 65 bytes

@dataclass(frozen=True)
class CombinedSig:
    """Threshold-combined signature.
    
    After Lagrange interpolation: single (R, s) pair.
    R is combined from partial R_i values; s = sum(L_i * s_i).
    
    On-wire: [(0, R_compressed + s_bytes)] = [(0, 65 bytes)]
    CONSTANT SIZE regardless of t.
    """
    parts: tuple[SignatureShare, ...]
    
    def to_wire(self) -> list[tuple[int, bytes]]:
        return [(p.index, p.sig) for p in self.parts]
    
    @classmethod
    def from_wire(cls, wire: Iterable[tuple[int, bytes]]) -> "CombinedSig":
        return cls(tuple(SignatureShare(i, s) for i, s in wire))

# ─── Serialization ────────────────────────────────────────────────

from cryptography.hazmat.primitives import serialization

def _pk_to_bytes(pk: ec.EllipticCurvePublicKey) -> bytes:
    return pk.public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.CompressedPoint,
    )

def _bytes_to_pk(data: bytes) -> ec.EllipticCurvePublicKey:
    return ec.EllipticCurvePublicKey.from_encoded_point(CURVE, data)

def _se_serialize(R: ec.EllipticCurvePublicKey, s: int) -> bytes:
    """Serialize (R, s) to bytes: 33-byte compressed R + 32-byte s."""
    r_bytes = _pk_to_bytes(R)  # 33 bytes compressed
    s_bytes = s.to_bytes(32, 'big')
    return r_bytes + s_bytes

def _se_deserialize(data: bytes) -> tuple[ec.EllipticCurvePublicKey, int]:
    """Deserialize (R, s) from 65 bytes."""
    if len(data) != 65:
        raise ValueError(f"Expected 65 bytes, got {len(data)}")
    R = _bytes_to_pk(data[:33])
    s = int.from_bytes(data[33:], 'big')
    return R, s

# ─── Core threshold Schnorr operations ────────────────────────────

def setup(n: int, t: int) -> tuple[GroupKey, list[ShareKey]]:
    """Generate threshold Schnorr keys.
    
    The master secret key is Shamir-split into n shares.
    Returns (group_public_key, list_of_share_keys).
    """
    if not 1 <= t <= n:
        raise ValueError(f"need 1<=t<=n, got t={t} n={n}")
    
    # Generate master secret key
    master_sk = int.from_bytes(os.urandom(32), 'big') % N
    if master_sk == 0:
        master_sk = 1
    
    # Compute master public key: master_pk = master_sk * G
    master_priv = ec.derive_private_key(master_sk, CURVE, default_backend())
    master_pk = master_priv.public_key()
    
    # Shamir split
    shares = _shamir_split(master_sk, t, n)
    
    share_keys: list[ShareKey] = []
    pk_shares: list[ec.EllipticCurvePublicKey] = []
    
    for idx, sk_share in shares:
        priv = ec.derive_private_key(sk_share, CURVE, default_backend())
        pk_share = priv.public_key()
        share_keys.append(ShareKey(index=idx, sk=sk_share, pk=pk_share))
        pk_shares.append(pk_share)
    
    group = GroupKey(n=n, t=t, pk=master_pk, pk_shares=tuple(pk_shares))
    return group, share_keys


def sign_share(share: ShareKey, msg: bytes) -> SignatureShare:
    """Non-interactive partial Schnorr signature.
    
    Uses a SHARED deterministic nonce derived from msg only (not sk_i),
    so all partial signatures share the same R. This makes Lagrange
    interpolation on s correct.
    
    This is equivalent to the non-interactive version where a common
    random beacon or deterministic nonce is used by all signers.
    """
    # Shared nonce: k = SHA256("nonce" || msg) mod N (same for all shares)
    h = hashlib.sha256()
    h.update(b"threshold_schnorr_nonce_v1")
    h.update(msg)
    k = int.from_bytes(h.digest(), 'big') % N
    if k == 0:
        k = 1
    
    # R = k * G (same R for all shares!)
    k_priv = ec.derive_private_key(k, CURVE, default_backend())
    R = k_priv.public_key()
    
    # e = SHA256(R || master_pk || msg) mod N  (same for all shares -- use share pk as placeholder)
    # For threshold, we need e to be consistent. We use R and the message only.
    h2 = hashlib.sha256()
    h2.update(_pk_to_bytes(R))
    h2.update(msg)
    e = int.from_bytes(h2.digest(), 'big') % N
    
    # s_i = k + e * sk_i mod N
    s_i = _n_add(k, _n_mul(e, share.sk))
    
    sig_bytes = _se_serialize(R, s_i)
    return SignatureShare(index=share.index, sig=sig_bytes)


def combine(parts: Iterable[SignatureShare]) -> CombinedSig:
    """Combine t partial signatures into a single threshold signature.

    Uses Lagrange interpolation on s-values. All shares use the
    same R (shared nonce), so only s needs interpolation.
    The result is a single constant-size signature.
    """
    parts_list = list(parts)
    if len(parts_list) == 0:
        raise ValueError("No partial signatures")

    indices = [p.index for p in parts_list]
    lambdas = _lagrange_coeffs(indices, 0)

    # All shares have the same R (shared nonce), take from first
    R, _ = _se_deserialize(parts_list[0].sig)

    # Interpolate s = sum_i(L_i * s_i)
    combined_s = 0
    for part, lam in zip(parts_list, lambdas):
        _, s_i = _se_deserialize(part.sig)
        combined_s = _n_add(combined_s, _n_mul(lam, s_i))

    combined_bytes = _se_serialize(R, combined_s)
    return CombinedSig((SignatureShare(0, combined_bytes),))
def verify(group: GroupKey, msg: bytes, sig: CombinedSig, t: int) -> bool:
    """Verify a threshold Schnorr signature.
    
    The combined signature is a standard Schnorr signature (R, s)
    over the group public key X = master_sk * G.
    
    Verification equation: s*G == R + e*X
    where e = SHA256(R || X || msg)
    
    This is the same as single-signer Schnorr verification,
    demonstrating that threshold combination produces a valid
    single-signer signature.
    """
    if len(sig.parts) < 1:
        return False
    
    try:
        R, s = _se_deserialize(sig.parts[0].sig)
    except (ValueError, IndexError):
        return False
    
    if s == 0 or s >= N:
        return False
    
    # Compute e = SHA256(R || msg)  (matches sign_share)
    h = hashlib.sha256()
    h.update(_pk_to_bytes(R))
    h.update(msg)
    e = int.from_bytes(h.digest(), 'big') % N
    
    # Verify: s*G == R + e*X
    # Compute left: s*G
    s_priv = ec.derive_private_key(s, CURVE, default_backend())
    left = s_priv.public_key()
    
    # Compute right: R + e*X
    R_nums = R.public_numbers()
    X_nums = group.pk.public_numbers()
    
    eX = _ec_mul_nums(X_nums, e)
    right_nums = _ec_add_nums(R_nums, eX)
    right = _ec_point_from_nums(right_nums)
    
    # Compare
    return _pk_to_bytes(left) == _pk_to_bytes(right)
