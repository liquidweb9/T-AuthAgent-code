"""Gateway and cryptographic component latency, with full distributions.

Reviewers require more than a mean: median, standard deviation, p95, p99
and a 95% confidence interval, reported *per component* plus platform
information (spec section 9). This module microbenchmarks each stage of
the acceptance path separately so that the cost of share verification,
aggregation, catalog lookup and replay update is visible on its own.

Important: the prototype uses threshold Schnorr over secp256k1 with a
pure-Python point arithmetic backend. Its absolute latencies are NOT BLS
latencies and must be reported in a separate table (the paper's BLS
numbers come from a different implementation).

Usage:
    python -m experiments.latency --samples 10000 --warmup 1000 \\n        --out experiments/out/latency.csv
"""
from __future__ import annotations

import argparse
import csv
import json
import os
import platform
import sys
import time
from dataclasses import asdict, dataclass
from pathlib import Path

from experiments.authenv import all_indices, benign_phi, ctx_for, fixed_catalog, make_req, mint
from experiments.stats import summarize
from secagent.auth.cert import Cert
from secagent.auth.gateway import accept
from secagent.auth.replay_store import ReplayStore
from secagent.auth.req import make_nonce
from secagent.auth.threshold_sig import combine, sign_share, verify as verify_sig

TOOL = "send_email"
ARGS = {"to": "bob@example.com"}


@dataclass
class LatencyRow:
    component: str
    n: int
    mean_us: float
    median_us: float
    stdev_us: float
    p95_us: float
    p99_us: float
    ci95_low_us: float
    ci95_high_us: float
    min_us: float
    max_us: float


def _bench(name: str, fn, samples: int, warmup: int) -> LatencyRow:
    for _ in range(warmup):
        fn()
    xs: list[float] = []
    for _ in range(samples):
        t0 = time.perf_counter_ns()
        fn()
        xs.append((time.perf_counter_ns() - t0) / 1000.0)  # us
    s = summarize(xs)
    return LatencyRow(
        component=name, n=s.n, mean_us=s.mean, median_us=s.median,
        stdev_us=s.stdev, p95_us=s.p95, p99_us=s.p99,
        ci95_low_us=s.ci95_low, ci95_high_us=s.ci95_high,
        min_us=s.minimum, max_us=s.maximum,
    )


def _platform_info() -> dict:
    info = {
        "platform": platform.platform(),
        "machine": platform.machine(),
        "processor": platform.processor(),
        "cpu_count": os.cpu_count(),
        "python": platform.python_version(),
        "curve": "secp256k1",
        "signature": "threshold Schnorr (Shamir + Lagrange), pure-Python EC",
        "threads": 1,
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
    }
    try:
        import cryptography
        info["cryptography"] = cryptography.__version__
    except Exception:
        pass
    try:
        import cbor2
        info["cbor2"] = getattr(cbor2, "__version__", "unknown")
    except Exception:
        pass
    try:
        from importlib.metadata import version as _v
        info["jsonschema"] = _v("jsonschema")
        info["pydantic"] = _v("pydantic")
    except Exception:
        pass
    try:
        with open("/proc/meminfo") as fh:  # linux only
            for line in fh:
                if line.startswith("MemTotal"):
                    info["mem_total"] = line.split(":")[1].strip()
                    break
    except Exception:
        pass
    return info


def run(samples: int = 10000, warmup: int = 1000,
        t: int = 3, n: int = 5) -> list[LatencyRow]:
    cat = fixed_catalog(t, n)
    req = make_req(cat, "cfg", phi=benign_phi())
    cert = mint(cat, req, all_indices(n))
    blob = cert.to_cbor()
    ctx = ctx_for()
    store = ReplayStore()
    shares = cat.shares("cfg")
    msg = req.hash()
    parts = [sign_share(s, msg) for s in shares[:t]]

    rows: list[LatencyRow] = []

    # --- cheap, high-sample components --------------------------------
    rows.append(_bench("canon_hash_req", lambda: req.hash(), samples, warmup))
    rows.append(_bench("cbor_serialize_cert", lambda: cert.to_cbor(),
                       samples, warmup))
    rows.append(_bench("cbor_parse_cert", lambda: Cert.from_cbor(blob),
                       samples, warmup))
    rows.append(_bench("catalog_lookup", lambda: cat.entry("cfg"),
                       samples, warmup))

    def _replay():
        store.check_and_consume(make_nonce())

    rows.append(_bench("replay_update", _replay, samples, warmup))

    # --- EC-heavy components (fewer samples keeps the run bounded) -----
    heavy = max(200, samples // 5)
    rows.append(_bench("single_share_sign",
                       lambda: sign_share(shares[0], msg), heavy, warmup))
    rows.append(_bench("share_aggregate",
                       lambda: combine(parts), heavy, warmup))
    rows.append(_bench("signature_verify",
                       lambda: verify_sig(cat.entry("cfg").group, msg,
                                          cert.sigma, t), heavy, warmup))

    def _gateway():
        store.clear()
        accept(cert, TOOL, ARGS, ctx, cat, store)

    rows.append(_bench("gateway_accept_full", _gateway, heavy, warmup))
    return rows


def render_markdown(rows: list[LatencyRow], info: dict) -> str:
    lines = ["# Latency by component (threshold Schnorr prototype)", "",
             "All values in microseconds. Warm-up discarded; 95% CI of the mean.",
             "",
             "| component | n | mean | median | std | p95 | p99 | 95% CI |",
             "|---|---|---|---|---|---|---|---|"]
    for r in rows:
        lines.append(
            f"| {r.component} | {r.n} | {r.mean_us:.1f} | {r.median_us:.1f} | "
            f"{r.stdev_us:.1f} | {r.p95_us:.1f} | {r.p99_us:.1f} | "
            f"[{r.ci95_low_us:.1f}, {r.ci95_high_us:.1f}] |")
    lines += ["", "## Platform", ""]
    for k, v in info.items():
        lines.append(f"- {k}: {v}")
    return "\n".join(lines) + "\n"


def render_latex(rows: list[LatencyRow]) -> str:
    out = [
        r"\begin{table}[t]", r"\centering",
        r"\caption{Gateway and signature component latency ($\mu$s), "
        r"threshold Schnorr prototype.}",
        r"\label{tab:latency}", r"\small",
        r"\begin{tabular}{@{}lrrrrrr@{}}", r"\toprule",
        r"\textbf{Component} & \textbf{Mean} & \textbf{Med.} & \textbf{Std} & "
        r"\textbf{p95} & \textbf{p99} & \textbf{$n$} \\", r"\midrule",
    ]
    for r in rows:
        comp = r.component.replace("_", r"\_")
        out.append(f"{comp} & {r.mean_us:.1f} & "
                   f"{r.median_us:.1f} & {r.stdev_us:.1f} & {r.p95_us:.1f} & "
                   f"{r.p99_us:.1f} & {r.n} " + r"\\")
    out += [r"\bottomrule", r"\end{tabular}", r"\end{table}", ""]
    return "\n".join(out)


def _write_all(rows: list[LatencyRow], info: dict, out: Path) -> None:
    out.mkdir(parents=True, exist_ok=True)
    with (out / "latency.csv").open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=list(asdict(rows[0]).keys()))
        w.writeheader()
        for r in rows:
            w.writerow(asdict(r))
    (out / "latency.json").write_text(
        json.dumps({"platform": info, "rows": [asdict(r) for r in rows]},
                   indent=2), encoding="utf-8")
    (out / "latency.md").write_text(render_markdown(rows, info),
                                    encoding="utf-8")
    (out / "latency.tex").write_text(render_latex(rows), encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--samples", type=int, default=10000)
    ap.add_argument("--warmup", type=int, default=1000)
    ap.add_argument("--t", type=int, default=3)
    ap.add_argument("--n", type=int, default=5)
    ap.add_argument("--out-dir", default="experiments/out")
    args = ap.parse_args(argv)

    print(f"== Latency: warmup={args.warmup} samples={args.samples} "
          f"gamma=({args.t},{args.n}) ==", file=sys.stderr)
    rows = run(samples=args.samples, warmup=args.warmup, t=args.t, n=args.n)
    info = _platform_info()
    _write_all(rows, info, Path(args.out_dir))

    for r in rows:
        print(f"  {r.component:22s} mean={r.mean_us:8.1f}us "
              f"p99={r.p99_us:8.1f}us n={r.n}", file=sys.stderr)
    print(f"Wrote {args.out_dir}/latency.{{csv,json,md,tex}}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
