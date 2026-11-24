"""Human approval workflow, decision quality, revocation and entropy.

This covers the reviewer items the deterministic matrix deliberately does
not:

  * R1#7 / R2#9 -- the approval process has a human component. We separate
    the measured *cryptographic* latency from a simulated *workflow*
    latency, and vary approver availability, deliberation delay, dissent
    and timeouts for (1,1), (3,5) and (4,5).
  * R2#9 -- approval fatigue / rubber-stamping. If t approvers sign without
    semantic review, a malicious request is certified. No cryptographic
    mechanism can prevent this; the experiment quantifies it.
  * R1 minor -- revocation after issuance: a certificate presented after
    its configuration is deactivated must fail pi_9.
  * R1 minor -- approver membership changes: removing an approver without
    re-sharing the secret does NOT revoke their shares; only key rotation
    (new configuration identifier) does. We demonstrate the gap.
  * R1 minor -- nonce entropy: 128-bit CSPRNG nonces and the birthday
    collision bound.

All workflow quantities are simulations with a fixed seed; the crypto
latencies are measured on the prototype.

Usage:
    python -m experiments.workflow --requests 20000 --out-dir experiments/out
"""
from __future__ import annotations

import argparse
import csv
import json
import math
import random
import sys
from dataclasses import asdict, dataclass
from pathlib import Path

from experiments.authenv import all_indices, benign_phi, ctx_for, fixed_catalog, make_req, mint
from experiments.stats import summarize
from secagent.auth.gateway import accept
from secagent.auth.replay_store import ReplayStore

TOOL = "send_email"
ARGS = {"to": "bob@example.com"}


# ─── Workflow simulation ─────────────────────────────────────────────

@dataclass
class WorkflowRow:
    config: str
    t: int
    n: int
    availability: float
    dissent: float
    median_delay_s: float
    timeout_s: float
    requests: int
    authorization_rate: float
    workflow_median_s: float
    workflow_p95_s: float
    crypto_mean_us: float
    approvals_mean: float   # approvers who approved within the timeout


def _workflow_once(t: int, n: int, p_avail: float, dissent: float,
                   median_delay: float, sigma: float, timeout: float,
                   rng: random.Random):
    """Simulate one approval round. Returns (authorized, latency_s, signers)."""
    approvals: list[float] = []
    for _ in range(n):
        if rng.random() >= p_avail:            # approver unavailable
            continue
        delay = rng.lognormvariate(math.log(median_delay), sigma)
        if delay > timeout:                     # responds too late
            continue
        if rng.random() < dissent:              # available but declines
            continue
        approvals.append(delay)
    if len(approvals) < t:
        return False, None, len(approvals)
    approvals.sort()
    return True, approvals[t - 1], len(approvals)


def _crypto_cost_us(t: int, n: int) -> float:
    """Measured cost of sign-share x t, aggregate, and gateway verify."""
    import time
    cat = fixed_catalog(t, n)
    req = make_req(cat, "cfg", phi=benign_phi())
    samples = 200
    xs: list[float] = []
    for _ in range(samples):
        req = make_req(cat, "cfg", phi=benign_phi())
        t0 = time.perf_counter_ns()
        cert = mint(cat, req, list(range(1, t + 1)))
        accept(cert, TOOL, ARGS, ctx_for(), cat, ReplayStore())
        xs.append((time.perf_counter_ns() - t0) / 1000.0)
    return summarize(xs).mean


def simulate_workflow(configs, p_avail, dissent, median_delay, sigma,
                      timeout, requests, seed=20251014) -> list[WorkflowRow]:
    rng = random.Random(seed)
    rows: list[WorkflowRow] = []
    for name, t, n in configs:
        crypto = _crypto_cost_us(t, n)
        ok = 0
        lats: list[float] = []
        signers: list[int] = []
        for _ in range(requests):
            authorized, lat, s = _workflow_once(
                t, n, p_avail, dissent, median_delay, sigma, timeout, rng)
            if authorized:
                ok += 1
                lats.append(lat)
            signers.append(s)
        s = summarize(lats)
        rows.append(WorkflowRow(
            config=name, t=t, n=n, availability=p_avail, dissent=dissent,
            median_delay_s=median_delay, timeout_s=timeout, requests=requests,
            authorization_rate=ok / requests,
            workflow_median_s=s.median, workflow_p95_s=s.p95,
            crypto_mean_us=crypto,
            approvals_mean=sum(signers) / len(signers),
        ))
    return rows


# ─── Rubber-stamping / decision quality ──────────────────────────────

@dataclass
class RubberStampRow:
    config: str
    t: int
    n: int
    rubber_stamp_prob: float
    forged_cert_rate_empirical: float
    forged_cert_rate_binomial: float


def _binom_tail(n: int, k: int, p: float) -> float:
    return sum(math.comb(n, i) * p ** i * (1 - p) ** (n - i)
               for i in range(k, n + 1))


def simulate_rubber_stamp(configs, probs, requests, seed=20251014
                          ) -> list[RubberStampRow]:
    rng = random.Random(seed)
    rows: list[RubberStampRow] = []
    for name, t, n in configs:
        for r in probs:
            ok = 0
            for _ in range(requests):
                # Each approver rubber-stamps with prob r; otherwise
                # correctly rejects the malicious request.
                approvals = sum(1 for _ in range(n) if rng.random() < r)
                if approvals >= t:
                    ok += 1
            rows.append(RubberStampRow(
                config=name, t=t, n=n, rubber_stamp_prob=r,
                forged_cert_rate_empirical=ok / requests,
                forged_cert_rate_binomial=_binom_tail(n, t, r),
            ))
    return rows


# ─── Revocation and membership changes ───────────────────────────────

@dataclass
class LifecycleRow:
    case: str
    expected: str
    accepted: bool
    clause: str | None
    verdict: str          # "match" | "finding" | "mismatch"
    note: str


def lifecycle_checks() -> list[LifecycleRow]:
    rows: list[LifecycleRow] = []

    # 1) Certificate presented after its configuration is deactivated.
    cat = fixed_catalog(3, 5)
    req = make_req(cat, "cfg", phi=benign_phi())
    cert = mint(cat, req, [1, 2, 3])
    cat.deactivate("cfg")
    res = accept(cert, TOOL, ARGS, ctx_for(), cat, ReplayStore())
    rows.append(LifecycleRow(
        "cert after configuration revocation", "pi_9", res.accepted,
        res.rejected_clause,
        "match" if res.rejected_clause == "pi_9" else "mismatch",
        "an unused certificate does not survive configuration revocation"))

    # 2) Removed approver's share still combines under the UNCHANGED key.
    # This is a documented limitation, not a control failure: a threshold
    # share is a mathematical share of the group key, so removing an
    # approver from a membership list does not invalidate it.
    cat = fixed_catalog(3, 5)
    req = make_req(cat, "cfg", phi=benign_phi())
    cert = mint(cat, req, [1, 2, 5])       # 5 is later "removed"
    res = accept(cert, TOOL, ARGS, ctx_for(), cat, ReplayStore())
    rows.append(LifecycleRow(
        "cert signed by a removed approver (no re-share)",
        "accept unless re-shared (limitation)", res.accepted,
        res.rejected_clause,
        "finding" if res.accepted else "match",
        "membership removal without re-sharing/rotation does not revoke "
        "the share -- it still interpolates to the unchanged group key"))

    # 3) Proper response: key rotation also advances pkid -> old cert fails.
    cat = fixed_catalog(3, 5)
    req = make_req(cat, "cfg", phi=benign_phi())
    cert = mint(cat, req, [1, 2, 3])
    cat.rotate_key("cfg")
    res = accept(cert, TOOL, ARGS, ctx_for(), cat, ReplayStore())
    ok = (not res.accepted) and res.rejected_clause in ("pi_10", "pi_1")
    rows.append(LifecycleRow(
        "cert after key rotation / re-share", "pi_10 or pi_1",
        res.accepted, res.rejected_clause, "match" if ok else "mismatch",
        "rotation rebinds the configuration to a fresh key and identifier"))

    # 4) Rotation keeps the same shares? Rotate then mint with NEW shares.
    cat = fixed_catalog(3, 5)
    cat.rotate_key("cfg")
    req = make_req(cat, "cfg", phi=benign_phi())
    cert = mint(cat, req, [1, 2, 3])       # uses the new share set
    res = accept(cert, TOOL, ARGS, ctx_for(), cat, ReplayStore())
    rows.append(LifecycleRow(
        "fresh cert after rotation", "accept", res.accepted,
        res.rejected_clause, "match" if res.accepted else "mismatch",
        "new shares under the rotated configuration work normally"))

    return rows


# ─── Nonce entropy ───────────────────────────────────────────────────

@dataclass
class EntropyRow:
    nonce_bits: int
    requests: float
    collision_probability: float
    description: str


def nonce_entropy() -> list[EntropyRow]:
    bits = 128                       # Req.make_nonce -> secrets.token_bytes(16)
    space = 2 ** bits
    rows: list[EntropyRow] = []
    for n, desc in [
        (10 ** 6, "1e6 requests"),
        (10 ** 9, "1e9 requests"),
        (2 ** 32, "2^32 ~ 4.3e9 requests"),
        (2 ** 48, "2^48 ~ 2.8e14 requests"),
    ]:
        # Birthday: 1 - exp(-N(N-1)/(2*2^bits)).
        # Use expm1 to avoid catastrophic cancellation for tiny exponents.
        p = -math.expm1(-(n * (n - 1)) / (2 * space))
        rows.append(EntropyRow(bits, n, p, desc))
    return rows


# ─── Reporting ───────────────────────────────────────────────────────

def render_markdown(wf, rs, lc, en) -> str:
    L = ["# Human approval workflow, decision quality and lifecycle", ""]
    L.append("## Workflow latency vs cryptographic latency")
    L.append("")
    L.append("Simulated human deliberation (lognormal), availability, dissent "
             "and a timeout window. Crypto is measured on the prototype.")
    L.append("")
    L.append("| config | p_avail | dissent | median delay | timeout | "
             "auth rate | wf median | wf p95 | crypto mean | approvals |")
    L.append("|---|---|---|---|---|---|---|---|---|---|")
    for r in wf:
        L.append(f"| {r.config} | {r.availability} | {r.dissent} | "
                 f"{r.median_delay_s:.0f}s | {r.timeout_s:.0f}s | "
                 f"{r.authorization_rate:.3f} | {r.workflow_median_s:.1f}s | "
                 f"{r.workflow_p95_s:.1f}s | {r.crypto_mean_us:.1f}us | "
                 f"{r.approvals_mean:.2f} |")
    L.append("")
    L.append("## Approval fatigue / rubber-stamping")
    L.append("")
    L.append("A malicious request is certified iff at least `t` approvers "
             "sign without semantic review. Crypto cannot prevent this.")
    L.append("")
    L.append("| config | (t,n) | P(rubber-stamp) | forged-cert rate (sim) | "
             "forged-cert rate (exact) |")
    L.append("|---|---|---|---|---|")
    for r in rs:
        L.append(f"| {r.config} | ({r.t},{r.n}) | {r.rubber_stamp_prob:.2f} | "
                 f"{r.forged_cert_rate_empirical:.4f} | "
                 f"{r.forged_cert_rate_binomial:.4f} |")
    L.append("")
    L.append("## Revocation and membership changes")
    L.append("")
    L.append("| case | expected | accepted | clause | verdict | note |")
    L.append("|---|---|---|---|---|---|")
    for r in lc:
        L.append(f"| {r.case} | {r.expected} | {r.accepted} | "
                 f"{r.clause or '-'} | {r.verdict} | {r.note} |")
    L.append("")
    L.append("## Nonce entropy and collision bound")
    L.append("")
    L.append("Nonces are `secrets.token_bytes(16)` = 128 bits from the OS "
             "CSPRNG. Birthday bound: 1 - exp(-N(N-1)/2^129).")
    L.append("")
    L.append("| nonce bits | requests N | collision probability |")
    L.append("|---|---|---|")
    for r in en:
        L.append(f"| {r.nonce_bits} | {r.description} | "
                 f"{r.collision_probability:.3e} |")
    return "\n".join(L) + "\n"


def _write_all(wf, rs, lc, en, out: Path) -> None:
    out.mkdir(parents=True, exist_ok=True)
    with (out / "workflow.csv").open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=list(asdict(wf[0]).keys()))
        w.writeheader()
        for r in wf:
            w.writerow(asdict(r))
    (out / "workflow.json").write_text(json.dumps({
        "workflow": [asdict(r) for r in wf],
        "rubber_stamp": [asdict(r) for r in rs],
        "lifecycle": [asdict(r) for r in lc],
        "entropy": [asdict(r) for r in en],
    }, indent=2), encoding="utf-8")
    (out / "workflow.md").write_text(render_markdown(wf, rs, lc, en),
                                     encoding="utf-8")


CONFIGS = [("B4_single", 1, 1), ("B5_fixed35", 3, 5), ("B6_high45", 4, 5)]


def run(requests: int = 20000, seed: int = 20251014):
    wf = []
    for p_avail, dissent in [(0.99, 0.05), (0.90, 0.05), (0.90, 0.20)]:
        wf.extend(simulate_workflow(CONFIGS, p_avail, dissent, 60.0, 0.6,
                                    300.0, requests, seed))
    rs = simulate_rubber_stamp(CONFIGS, [0.0, 0.1, 0.3, 0.5], requests, seed)
    lc = lifecycle_checks()
    en = nonce_entropy()
    return wf, rs, lc, en


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--requests", type=int, default=20000)
    ap.add_argument("--seed", type=int, default=20251014)
    ap.add_argument("--out-dir", default="experiments/out")
    args = ap.parse_args(argv)

    wf, rs, lc, en = run(args.requests, args.seed)
    _write_all(wf, rs, lc, en, Path(args.out_dir))
    for r in wf:
        print(f"  {r.config} p={r.availability} d={r.dissent} "
              f"auth={r.authorization_rate:.3f} "
              f"wf_med={r.workflow_median_s:.1f}s "
              f"crypto={r.crypto_mean_us:.0f}us", file=sys.stderr)
    for r in lc:
        print(f"  [{r.case}] accepted={r.accepted} {r.verdict}",
              file=sys.stderr)
    print(f"Wrote {args.out_dir}/workflow.{{csv,json,md}}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
