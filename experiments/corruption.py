"""Approver-corruption experiment (revision spec section 7).

Both reviewers' central objection is that B4/B5/B6 report identical attack
success rates, so the paper never *empirically* shows the advantage of
(3,5) over a single approver. This experiment closes that gap.

For each configuration gamma = (t, n) and each number of corrupted
approvers k = 0..n we run ``--trials`` independent requests under three
adversary behaviours:

  malicious_sign  k compromised approvers sign a request the honest
                  approvers would refuse. An *unauthorized acceptance* is
                  a gateway acceptance (and hence a tool-side effect).
                  Expected: acceptance = 0 while k < t, 1 once k >= t.

  refuse          k approvers are absent/refuse on a *legitimate* request.
                  Availability is the fraction that still completes with
                  the remaining n - k honest signers. Expected: 1 while
                  n - k >= t, 0 once too few honest approvers remain.

  collude_stale   k compromised approvers collude with the agent to
                  resubmit a certificate minted for an earlier context.
                  Expected: 0 for every k -- context binding (pi_2) is not
                  a function of the threshold.

The experiment therefore separates the two curves the paper needs: the
security threshold (first k where unauthorized acceptance appears) and the
availability threshold (first k where legitimate completion collapses).

Usage:
    python -m experiments.corruption --trials 120 \
        --out experiments/out/corruption.csv
"""
from __future__ import annotations

import argparse
import csv
import json
import random
import sys
from dataclasses import dataclass, asdict
from pathlib import Path

from experiments.authenv import (
    BENIGN_RECIPIENT, SESSION, all_indices, attack_phi, benign_phi, ctx_for,
    fixed_catalog, make_req, mint,
)
from experiments.stats import wilson_interval
from secagent.auth.gateway import accept
from secagent.auth.replay_store import ReplayStore

# Configurations from the paper: B4 single approver, B5 fixed (3,5),
# B6 risk-adaptive whose high-risk configuration is (4,5).
CONFIGS: list[tuple[str, int, int]] = [
    ("B4_single", 1, 1),
    ("B5_fixed35", 3, 5),
    ("B6_high45", 4, 5),
]

TOOL = "send_email"


@dataclass
class CorruptRow:
    config: str
    t: int
    n: int
    k: int
    trials: int
    unauthorized_accept: float
    unauthorized_ci_low: float
    unauthorized_ci_high: float
    availability: float
    availability_ci_low: float
    availability_ci_high: float
    stale_accept: float
    mean_signers_malicious: float
    mean_signers_available: float


def _one_k(config: str, t: int, n: int, k: int, trials: int,
           rng: random.Random) -> CorruptRow:
    compromised = set(range(1, k + 1))
    unauth = avail = stale = 0
    signers_mal: list[int] = []
    signers_avail: list[int] = []

    for _ in range(trials):
        # --- malicious: compromised shares sign an unapproved request ---
        cat = fixed_catalog(t, n)
        attack_req = make_req(cat, "cfg", phi=attack_phi(),
                              nonce=rng.randbytes(16))
        ctx = ctx_for()
        if k > 0:
            bad_cert = mint(cat, attack_req, sorted(compromised))
            res = accept(bad_cert, TOOL, {"to": "eve@evil.example"},
                         ctx, cat, ReplayStore())
            if res.accepted:
                unauth += 1
            signers_mal.append(k)
        else:
            # Nothing to submit: zero compromised shares cannot certify.
            signers_mal.append(0)

        # --- refuse: k approvers absent on a legitimate request ---------
        cat = fixed_catalog(t, n)
        legit = make_req(cat, "cfg", phi=benign_phi(), nonce=rng.randbytes(16))
        honest = [i for i in all_indices(n) if i not in compromised]
        if honest:
            cert = mint(cat, legit, honest)
            res = accept(cert, TOOL, {"to": BENIGN_RECIPIENT},
                         ctx_for(), cat, ReplayStore())
            if res.accepted:
                avail += 1
            signers_avail.append(len(honest))
        else:
            signers_avail.append(0)

        # --- collude_stale: replay a certificate from an old context ----
        cat = fixed_catalog(t, n)
        old_session = dict(SESSION, sid="s_old")
        stale_req = make_req(cat, "cfg", phi=benign_phi(),
                             session=old_session, nonce=rng.randbytes(16))
        stale_cert = mint(cat, stale_req, all_indices(n))
        res = accept(stale_cert, TOOL, {"to": BENIGN_RECIPIENT},
                     ctx_for(), cat, ReplayStore())
        if res.accepted:
            stale += 1

    ul, uh = wilson_interval(unauth, trials)
    al, ah = wilson_interval(avail, trials)
    return CorruptRow(
        config=config, t=t, n=n, k=k, trials=trials,
        unauthorized_accept=unauth / trials,
        unauthorized_ci_low=ul, unauthorized_ci_high=uh,
        availability=avail / trials,
        availability_ci_low=al, availability_ci_high=ah,
        stale_accept=stale / trials,
        mean_signers_malicious=(sum(signers_mal) / len(signers_mal)
                                if signers_mal else 0.0),
        mean_signers_available=(sum(signers_avail) / len(signers_avail)
                                if signers_avail else 0.0),
    )


def run(trials: int = 120, seed: int = 20251014) -> list[CorruptRow]:
    rng = random.Random(seed)
    rows: list[CorruptRow] = []
    for config, t, n in CONFIGS:
        for k in range(n + 1):
            row = _one_k(config, t, n, k, trials, rng)
            rows.append(row)
            print(f"  {config:11s} k={k}  unauth={row.unauthorized_accept:.2f} "
                  f"avail={row.availability:.2f} stale={row.stale_accept:.2f}",
                  file=sys.stderr)
    return rows


# ─── Reporting ────────────────────────────────────────────────────────

def render_markdown(rows: list[CorruptRow]) -> str:
    lines = ["# Approver Corruption (unauthorized acceptance vs. k)",
             "",
             "`unauth` = fraction of unapproved requests the gateway accepted;",
             "`avail` = fraction of legitimate requests completed;",
             "`stale` = fraction of old-context certificates accepted.",
             "",
             "| config | (t,n) | k | unauthorized accept | availability | stale |",
             "|---|---|---|---|---|---|"]
    for r in rows:
        lines.append(
            f"| {r.config} | ({r.t},{r.n}) | {r.k} | "
            f"{r.unauthorized_accept:.2f} "
            f"[{r.unauthorized_ci_low:.2f},{r.unauthorized_ci_high:.2f}] | "
            f"{r.availability:.2f} | {r.stale_accept:.2f} |")
    return "\n".join(lines) + "\n"


def render_latex(rows: list[CorruptRow]) -> str:
    out = [
        r"\begin{table}[t]",
        r"\centering",
        r"\caption{Approver corruption: unauthorized acceptance rate and "
        r"availability as a function of corrupted approvers $k$ "
        r"($N=" + str(rows[0].trials if rows else 0) + r"$ per cell).}",
        r"\label{tab:corruption}",
        r"\small",
        r"\begin{tabular}{@{}llccc@{}}",
        r"\toprule",
        r"\textbf{Config} & $\gamma$ & $k$ & \textbf{Unauth. accept} & "
        r"\textbf{Avail.} \\",
        r"\midrule",
    ]
    for r in rows:
        cfg = r.config.replace("_", r"\_")
        out.append(
            f"{cfg} & $({r.t},{r.n})$ & {r.k} & "
            f"{r.unauthorized_accept:.2f} & {r.availability:.2f} " + r"\\")
    out += [r"\bottomrule", r"\end{tabular}", r"\end{table}", ""]
    return "\n".join(out)


def _write_all(rows: list[CorruptRow], out: Path) -> None:
    out.mkdir(parents=True, exist_ok=True)
    with (out / "corruption.csv").open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=list(asdict(rows[0]).keys()))
        w.writeheader()
        for r in rows:
            w.writerow(asdict(r))
    (out / "corruption.md").write_text(render_markdown(rows), encoding="utf-8")
    (out / "corruption.tex").write_text(render_latex(rows), encoding="utf-8")
    (out / "corruption.json").write_text(
        json.dumps([asdict(r) for r in rows], indent=2), encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--trials", type=int, default=120)
    ap.add_argument("--seed", type=int, default=20251014)
    ap.add_argument("--out-dir", default="experiments/out")
    args = ap.parse_args(argv)

    rows = run(trials=args.trials, seed=args.seed)
    _write_all(rows, Path(args.out_dir))
    print(f"Wrote {args.out_dir}/corruption.{{csv,md,tex,json}}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
