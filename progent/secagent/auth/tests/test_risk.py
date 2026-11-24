"""Tests for the fixed risk model (experiment spec section 6)."""
import pytest

from secagent.auth import risk


def _phi_enum(vals):
    return {"type": "object", "properties": {"to": {"enum": list(vals)}},
            "required": ["to"]}


def test_features_in_unit_range():
    for tool in ("read_email", "send_email", "delete_file", "unknown_tool"):
        f = risk.features(tool, {})
        for v in f.as_dict().values():
            assert 0.0 <= v <= 1.0


def test_breadth_is_monotone_in_enum_size():
    narrow = risk.parameter_breadth(_phi_enum(["a@x"]))
    wide = risk.parameter_breadth(_phi_enum([f"u{i}@x" for i in range(8)]))
    assert narrow < wide
    assert 0.0 <= narrow <= 1.0 and 0.0 <= wide <= 1.0


def test_unconstrained_predicate_is_maximally_broad():
    assert risk.parameter_breadth({}) == 1.0
    assert risk.parameter_breadth({"type": "object"}) == 1.0


def test_documented_example_send_email_is_medium():
    """Spec section 8, example 1: send_email with a tight Phi is medium."""
    phi = {"type": "object",
           "properties": {"to": {"enum": ["bob@example.com"]},
                          "subject": {"type": "string"},
                          "body": {"type": "string", "maxLength": 200}},
           "required": ["to"]}
    a = risk.assess("send_email", phi)
    assert a.tier == "medium"
    assert risk.select_config(a.tier) == "med_risk"


def test_irreversible_unbounded_delete_is_high():
    a = risk.assess("delete_file", {"type": "object"})
    assert a.tier == "high"
    assert risk.select_config(a.tier) == "high_risk"


def test_read_only_tool_is_low():
    a = risk.assess("read_email", _phi_enum(["alice@example.com"]))
    assert a.tier == "low"


def test_tier_boundaries():
    assert risk.tier(0.0) == "low"
    assert risk.tier(0.329) == "low"
    assert risk.tier(0.33) == "medium"
    assert risk.tier(0.659) == "medium"
    assert risk.tier(0.66) == "high"
    assert risk.tier(1.0) == "high"


def test_weights_sum_to_one():
    assert abs(sum(risk.WEIGHTS.values()) - 1.0) < 1e-9


def test_score_is_weighted_sum():
    f = risk.RiskFeatures(s=1.0, b=0.0, i=0.0, f=0.0, c=0.0)
    assert abs(risk.score(f) - risk.WEIGHTS["s"]) < 1e-12


def test_determinism():
    phi = _phi_enum(["a@x", "b@x"])
    assert risk.assess("send_email", phi) == risk.assess("send_email", phi)


def test_context_sensitivity_bump():
    base = risk.assess("send_email", _phi_enum(["b@x"]))
    bumped = risk.assess("send_email", _phi_enum(["b@x"]),
                         context={"sensitive": True})
    assert bumped.score >= base.score


def test_selector_rejects_unknown_tier():
    with pytest.raises(KeyError):
        risk.select_config("nonsense")
