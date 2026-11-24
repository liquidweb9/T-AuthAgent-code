"""Deterministic risk scoring and approval-configuration selection.

This module fixes the risk function that the revised experiment document
(section 6) requires to be concrete and reproducible. It replaces the
ad-hoc ``hook_update._risk_tier`` heuristic with:

    R = 0.30*s + 0.20*b + 0.25*i + 0.15*f + 0.10*c

over five features normalised to [0, 1]:

    s  tool severity            (from the tool's base profile)
    b  parameter breadth        (from the signed predicate Phi)
    i  irreversibility          (from the tool's base profile)
    f  financial / privacy impact
    c  context sensitivity

Tier boundaries:  low  R < 0.33 <= medium R < 0.66 <= high.
The selector S(rho) maps  low -> gamma_low,  medium -> gamma_med,
high -> gamma_high, where each gamma is an *independently keyed* catalog
entry (see catalog.py). The gateway recomputes R from (tau, Phi, context)
in pi_11 and re-derives the configuration in pi_12, so a compromised
request builder cannot claim a weaker tier than the call warrants.

Everything here is pure and deterministic: the same (tool, Phi, context)
always yields the same R, tier and configuration. ``context`` currently
contributes a single flag (``sensitive``); it is part of the signature so
future context sources can be added without changing call sites.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

# ─── Fixed weights and boundaries (spec section 6) ────────────────────

WEIGHTS: dict[str, float] = {
    "s": 0.30,   # tool severity
    "b": 0.20,   # parameter breadth
    "i": 0.25,   # irreversibility
    "f": 0.15,   # financial / privacy impact
    "c": 0.10,   # context sensitivity
}

TIER_LOW_MAX = 0.33    # R <  0.33        -> low
TIER_MED_MAX = 0.66    # 0.33 <= R < 0.66 -> medium ; R >= 0.66 -> high

# Saturating constants for the breadth function.
BREADTH_HALF = 8.0            # total / (total + BREADTH_HALF)
UNCONSTRAINED_BREADTH = 64.0  # a bare {type: object} is maximally broad
STRING_DEFAULT_BREADTH = 4.0  # unbounded string
ARRAY_DEFAULT_ITEMS = 8.0     # unbounded array
NUMERIC_REFERENCE = 1000.0    # numeric interval width normaliser
CONTEXT_SENSITIVE_BUMP = 0.30  # added to the context feature (clamped to 1)

# Fixed per-tool base profiles (severity, irreversibility, impact, context).
# These are part of the reproducible risk model; changing them changes the
# tiers and therefore every risk-adaptive result.
TOOL_BASE: dict[str, dict[str, float]] = {
    "read_email":  {"s": 0.10, "i": 0.05, "f": 0.20, "c": 0.20},
    "send_email":  {"s": 0.60, "i": 0.40, "f": 0.45, "c": 0.35},
    "delete_file": {"s": 0.95, "i": 1.00, "f": 0.35, "c": 0.45},
}
DEFAULT_BASE: dict[str, float] = {"s": 0.50, "i": 0.50, "f": 0.30, "c": 0.30}

# Fixed tier -> configuration-name mapping (the selector S).
TIER_TO_CONFIG: dict[str, str] = {
    "low": "low_risk",
    "medium": "med_risk",
    "high": "high_risk",
}
TIER_INT_TO_NAME: dict[int, str] = {1: "low", 2: "medium", 3: "high"}
TIER_NAME_TO_INT: dict[str, int] = {"low": 1, "medium": 2, "high": 3}


def _clamp01(x: float) -> float:
    return 0.0 if x < 0.0 else (1.0 if x > 1.0 else x)


# ─── Parameter breadth ────────────────────────────────────────────────

def _leaf_schemas(phi: Any) -> list[dict]:
    """Collect leaf schemas of a JSON-schema fragment.

    A leaf is any schema that does not itself declare ``properties``. A
    schema with ``properties`` recurses into them. Non-dict fragments are
    ignored.
    """
    if not isinstance(phi, dict):
        return []
    props = phi.get("properties")
    if isinstance(props, dict) and props:
        leaves: list[dict] = []
        for sub in props.values():
            leaves.extend(_leaf_schemas(sub))
        return leaves
    if phi.get("additionalProperties") and isinstance(phi["additionalProperties"], dict):
        return [phi["additionalProperties"]]
    return [phi]


def _numeric_width(leaf: dict) -> float:
    """Width of a numeric leaf's allowed interval, normalised to [0, 1]."""
    lo = leaf.get("minimum", leaf.get("exclusiveMinimum", 0.0))
    hi = leaf.get("maximum", leaf.get("exclusiveMaximum", NUMERIC_REFERENCE))
    try:
        width = float(hi) - float(lo)
    except (TypeError, ValueError):
        return 1.0
    return _clamp01(width / NUMERIC_REFERENCE)


def _leaf_breadth(leaf: dict) -> float:
    """Breadth contribution of a single leaf schema."""
    if "enum" in leaf and isinstance(leaf["enum"], list):
        # An enum of size k allows k values; k/8 saturates.
        return min(1.0, len(leaf["enum"]) / BREADTH_HALF)
    if "const" in leaf:
        return 1.0 / BREADTH_HALF
    typ = leaf.get("type")
    if typ in ("number", "integer"):
        return max(_numeric_width(leaf), 1.0 / BREADTH_HALF)
    if typ == "string":
        if "maxLength" in leaf:
            return _clamp01(float(leaf["maxLength"]) / 255.0)
        if "pattern" in leaf:
            return 0.25
        return STRING_DEFAULT_BREADTH
    if typ == "array":
        return _clamp01(float(leaf.get("maxItems", ARRAY_DEFAULT_ITEMS))
                        / ARRAY_DEFAULT_ITEMS) * ARRAY_DEFAULT_ITEMS
    if typ == "boolean":
        return 2.0 / BREADTH_HALF
    # Unconstrained (bare {type: object} or {}) is maximally broad.
    return UNCONSTRAINED_BREADTH


def parameter_breadth(phi: Any) -> float:
    """Normalised allowed-domain breadth of predicate ``phi``, in [0, 1].

    Defined as ``total / (total + 8)`` over the per-leaf domain sizes, with
    a bare / unconstrained predicate pinned to 1.0. Deterministic and
    truncated to [0, 1] as the experiment document requires.
    """
    if not phi:
        return 1.0
    leaves = _leaf_schemas(phi)
    if not leaves:
        return 1.0
    if all(_leaf_breadth(leaf) >= UNCONSTRAINED_BREADTH for leaf in leaves):
        return 1.0
    total = sum(_leaf_breadth(leaf) for leaf in leaves)
    return _clamp01(total / (total + BREADTH_HALF))


# ─── Feature vector, score, tier ──────────────────────────────────────

@dataclass(frozen=True)
class RiskFeatures:
    s: float
    b: float
    i: float
    f: float
    c: float

    def as_dict(self) -> dict[str, float]:
        return {"s": self.s, "b": self.b, "i": self.i, "f": self.f, "c": self.c}


@dataclass(frozen=True)
class RiskAssessment:
    features: RiskFeatures
    score: float
    tier: str        # "low" | "medium" | "high"
    tier_int: int    # 1 | 2 | 3  (the rho carried in Req)


def features(tool: str, phi: Any, context: Any = None) -> RiskFeatures:
    """Compute the five-feature vector for (tool, Phi, context)."""
    base = TOOL_BASE.get(tool, DEFAULT_BASE)
    c = base["c"]
    if isinstance(context, dict) and context.get("sensitive"):
        c = _clamp01(c + CONTEXT_SENSITIVE_BUMP)
    return RiskFeatures(
        s=_clamp01(base["s"]),
        b=_clamp01(parameter_breadth(phi)),
        i=_clamp01(base["i"]),
        f=_clamp01(base["f"]),
        c=_clamp01(c),
    )


def score(feat: RiskFeatures) -> float:
    """Weighted risk score R in [0, 1]."""
    d = feat.as_dict()
    return sum(WEIGHTS[k] * d[k] for k in WEIGHTS)


def tier(r: float) -> str:
    if r < TIER_LOW_MAX:
        return "low"
    if r < TIER_MED_MAX:
        return "medium"
    return "high"


def assess(tool: str, phi: Any, context: Any = None) -> RiskAssessment:
    """One-shot (features, score, tier) for a call."""
    feat = features(tool, phi, context)
    r = score(feat)
    t = tier(r)
    return RiskAssessment(features=feat, score=r, tier=t,
                          tier_int=TIER_NAME_TO_INT[t])


def select_config(t: str | int) -> str:
    """Selector S(rho): risk tier -> approval-configuration name."""
    if isinstance(t, int):
        t = TIER_INT_TO_NAME[t]
    return TIER_TO_CONFIG[t]
