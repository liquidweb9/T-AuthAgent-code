"""Risk-adaptive configuration validation (revision spec section 6).

Reviewer 3/R2 asks that the risk mechanism -- not just the downgrade check
-- be evaluated: does the fixed function select the expected configuration
under realistic changes in tool severity, argument breadth, irreversibility
and context, and does the gateway enforce that selection?

This produces a graded table of (tool, Phi, context) -> features -> R ->
tier -> S(rho), plus enforcement checks showing that a certificate issued
for the *wrong* configuration is rejected (pi_11/pi_12).

Usage:
    python -m experiments.risk_validation --out experiments/out/risk.csv
"""
from __future__ import annotations

import argparse
import csv
import json
import sys
from dataclasses import asdict, dataclass
from pathlib import Path

from experiments.authenv import all_indices, ctx_for, make_req, mint
from secagent.auth import risk as risk_mod
from secagent.auth.catalog import make_risk_catalog
from secagent.auth.gateway import accept
from secagent.auth.replay_store import ReplayStore

TIGHT = {"type": "object", "properties": {"to": {"enum": ["bob@example.com"]}},
         "required": ["to"]}
WIDE = {"type": "object", "properties": {
            "to": {"type": "string"},
            "subject": {"type": "string"},
            "body": {"type": "string"}},
        "required": ["to"]}
BARE = {"type": "object"}
MONEY = {"type": "object", "properties": {
             "to": {"enum": ["bob@example.com"]},
             "amount": {"type": "integer", "minimum": 0, "maximum": 100000}},
         "required": ["to", "amount"]}

# (label, tool, phi, context, expected tier)
SCENARIOS: list[tuple[str, str, dict, dict | None, str]] = [
    ("read_email tight", "read_email", TIGHT, None, "low"),
    ("send_email tight", "send_email", TIGHT, None, "medium"),
    ("send_email wide (breadth up)", "send_email", WIDE, None, "medium"),
    ("send_email bare (breadth max)", "send_email", BARE, None, "medium"),
    ("send_email wide + sensitive ctx", "send_email", TIGHT,
     {"sensitive": True}, "medium"),
    ("send_email money range", "send_email", MONEY, None, "medium"),
    ("delete_file tight", "delete_file", TIGHT, None, "medium"),
    ("delete_file bare (irreversible + broad)", "delete_file", BARE, None,
     "high"),
]


@dataclass
class RiskRow:
    scenario: str
    tool: str
    severity: float
    breadth: float
    irreversibility: float
    impact: float
    context: float
    score: float
    tier: str
    selected_config: str
    expected_tier: str
    matches_expectation: bool


@dataclass
class EnforcementRow:
    case: str
    expected: str
    accepted: bool
    clause: str | None
    matches: bool


def _rows() -> list[RiskRow]:
    rows: list[RiskRow] = []
    for label, tool, phi, ctx, expected in SCENARIOS:
        a = risk_mod.assess(tool, phi, ctx)
        cfg = risk_mod.select_config(a.tier)
        rows.append(RiskRow(
            scenario=label, tool=tool,
            severity=a.features.s, breadth=a.features.b,
            irreversibility=a.features.i, impact=a.features.f,
            context=a.features.c, score=a.score, tier=a.tier,
            selected_config=cfg, expected_tier=expected,
            matches_expectation=(a.tier == expected),
        ))
    return rows


def _enforcement() -> list[EnforcementRow]:
    out: list[EnforcementRow] = []
    cat = make_risk_catalog()

    # Correct configuration for a medium-risk call -> accepted.
    req = make_req(cat, "med_risk", tau="send_email", phi=TIGHT, rho=2)
    cert = mint(cat, req, all_indices(5))
    res = accept(cert, "send_email", {"to": "bob@example.com"}, ctx_for(),
                 cat, ReplayStore())
    out.append(EnforcementRow(
        "medium call, med_risk config", "accept", res.accepted,
        res.rejected_clause, res.accepted))

    # Understated tier (claims low for a medium call) -> pi_11.
    req = make_req(cat, "low_risk", tau="send_email", phi=TIGHT, rho=1)
    cert = mint(cat, req, all_indices(5))
    res = accept(cert, "send_email", {"to": "bob@example.com"}, ctx_for(),
                 cat, ReplayStore())
    out.append(EnforcementRow(
        "medium call mislabeled rho=low", "pi_11", res.accepted,
        res.rejected_clause, res.rejected_clause == "pi_11"))

    # High-risk call using the medium configuration -> pi_11 (tier wrong)
    req = make_req(cat, "med_risk", tau="delete_file", phi=BARE, rho=3)
    cert = mint(cat, req, all_indices(5))
    res = accept(cert, "delete_file", {"path": "/x"}, ctx_for(), cat,
                 ReplayStore())
    out.append(EnforcementRow(
        "high call on medium config", "pi_11/pi_12", res.accepted,
        res.rejected_clause, res.rejected_clause in ("pi_11", "pi_12")))

    return out


def render_markdown(rows: list[RiskRow], enf: list[EnforcementRow]) -> str:
    lines = ["# Risk-adaptive configuration validation", "",
             "| scenario | s | b | i | f | c | R | tier | S(rho) | expected | ok |",
             "|---|---|---|---|---|---|---|---|---|---|---|"]
    for r in rows:
        lines.append(
            f"| {r.scenario} | {r.severity:.2f} | {r.breadth:.2f} | "
            f"{r.irreversibility:.2f} | {r.impact:.2f} | {r.context:.2f} | "
            f"{r.score:.3f} | {r.tier} | {r.selected_config} | "
            f"{r.expected_tier} | {'yes' if r.matches_expectation else 'NO'} |")
    lines += ["", "## Gateway enforcement of the selection", "",
              "| case | expected | accepted | clause | ok |",
              "|---|---|---|---|---|"]
    for e in enf:
        lines.append(f"| {e.case} | {e.expected} | {e.accepted} | "
                     f"{e.clause or '-'} | {'yes' if e.matches else 'NO'} |")
    return "\n".join(lines) + "\n"


def _write_all(rows: list[RiskRow], enf: list[EnforcementRow],
               out: Path) -> None:
    out.mkdir(parents=True, exist_ok=True)
    with (out / "risk.csv").open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=list(asdict(rows[0]).keys()))
        w.writeheader()
        for r in rows:
            w.writerow(asdict(r))
    (out / "risk.json").write_text(
        json.dumps({"scenarios": [asdict(r) for r in rows],
                    "enforcement": [asdict(e) for e in enf]}, indent=2),
        encoding="utf-8")
    (out / "risk.md").write_text(render_markdown(rows, enf), encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out-dir", default="experiments/out")
    args = ap.parse_args(argv)

    rows = _rows()
    enf = _enforcement()
    _write_all(rows, enf, Path(args.out_dir))

    for r in rows:
        print(f"  {r.scenario:38s} R={r.score:.3f} {r.tier:6s} "
              f"-> {r.selected_config} "
              f"({'ok' if r.matches_expectation else 'MISMATCH'})",
              file=sys.stderr)
    for e in enf:
        print(f"  [enf] {e.case}: accepted={e.accepted} "
              f"clause={e.clause} {'ok' if e.matches else 'MISMATCH'}",
              file=sys.stderr)
    print(f"Wrote {args.out_dir}/risk.{{csv,json,md}}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
