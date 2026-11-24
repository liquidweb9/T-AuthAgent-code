"""Distributed replay store and clock skew (revision spec section 10).

The prototype's in-process ``ReplayStore`` gives exactly-once behaviour
within one process, and ``scaling.py`` already shows that independent
gateway *processes* each accept the same certificate. Reviewers asked for
at least one strongly-consistent backend and for the clock assumptions to
be made explicit.

This module provides:

  SqliteReplayStore -- a cross-process replay store that is atomic by
  construction: consumption is a single ``INSERT OR IGNORE`` against a
  PRIMARY KEY, so exactly one racer inserts the row and every other racer
  sees ``rowcount == 0``. SQLite serialises the writes, so the guarantee
  holds across processes, not just threads.

  skew_window -- quantifies the clock-skew assumption behind pi_7. Two
  replicas whose clocks differ by delta disagree about a certificate for
  exactly the delta-long window straddling ``exp``; the experiment reports
  that window and the resulting maximum tolerable skew for a given TTL.

Usage:
    python -m experiments.distributed --procs 8 --sizes 1000,10000,100000 \\n        --out-dir experiments/out
"""
from __future__ import annotations

import argparse
import csv
import json
import multiprocessing as mp
import os
import sqlite3
import sys
import tempfile
import time
from dataclasses import asdict, dataclass
from pathlib import Path

from experiments.authenv import all_indices, benign_phi, ctx_for, fixed_catalog, make_req, mint
from experiments.stats import summarize
from secagent.auth.gateway import accept
from secagent.auth.replay_store import ReplayStore
from secagent.auth.req import make_nonce

TOOL = "send_email"
ARGS = {"to": "bob@example.com"}


# ─── Strongly-consistent, cross-process replay store ─────────────────

class SqliteReplayStore:
    """Atomic check-and-consume backed by a SQLite PRIMARY KEY.

    ``INSERT OR IGNORE`` is a single atomic statement; the unique
    constraint means exactly one process can insert a given nonce. This is
    the "strongly consistent backend" the paper's atomicity assumption
    requires, and it is shared across OS processes.
    """

    def __init__(self, path: str) -> None:
        self.path = path
        self._conn = sqlite3.connect(path, timeout=60.0,
                                     isolation_level=None,
                                     check_same_thread=False)
        self._conn.execute("PRAGMA busy_timeout=60000")
        # Concurrent openers can briefly contend on the journal-mode switch;
        # it is a one-time, best-effort setting, so a lock error is benign.
        try:
            self._conn.execute("PRAGMA journal_mode=WAL")
        except sqlite3.OperationalError:
            pass
        self._conn.execute("PRAGMA synchronous=NORMAL")
        self._conn.execute(
            "CREATE TABLE IF NOT EXISTS consumed "
            "(nonce BLOB PRIMARY KEY, ts REAL)")

    def check_and_consume(self, nonce: bytes) -> bool:
        cur = self._conn.execute(
            "INSERT OR IGNORE INTO consumed(nonce, ts) VALUES (?, ?)",
            (nonce, time.time()))
        return cur.rowcount == 1

    def size(self) -> int:
        return self._conn.execute(
            "SELECT COUNT(*) FROM consumed").fetchone()[0]

    def mark(self, nonce: bytes) -> None:
        self._conn.execute(
            "INSERT OR IGNORE INTO consumed(nonce, ts) VALUES (?, ?)",
            (nonce, time.time()))

    def populate(self, n: int) -> None:
        """Bulk-fill the store (single transaction) for size sweeps."""
        now = time.time()
        self._conn.execute("BEGIN")
        self._conn.executemany(
            "INSERT OR IGNORE INTO consumed(nonce, ts) VALUES (?, ?)",
            ((make_nonce(), now) for _ in range(n)))
        self._conn.execute("COMMIT")

    def close(self) -> None:
        self._conn.close()


def _proc_race(db_path: str, nonce_hex: str, out_path: str) -> None:
    store = SqliteReplayStore(db_path)
    try:
        won = store.check_and_consume(bytes.fromhex(nonce_hex))
    finally:
        store.close()
    # Result is written to a file rather than a Queue: a file is
    # deterministic and cannot deadlock on pipe-buffer limits.
    with open(out_path, "w", encoding="utf-8") as fh:
        fh.write("1" if won else "0")


def multiprocess_exactly_once(db_path: str, procs: int = 8) -> dict:
    """Race N processes on one nonce against the shared store."""
    nonce = make_nonce()
    outdir = tempfile.mkdtemp(prefix="tauth_race_")
    paths = [os.path.join(outdir, f"r{i}.txt") for i in range(procs)]
    workers = [mp.Process(target=_proc_race,
                          args=(db_path, nonce.hex(), p))
               for p in paths]
    for w in workers:
        w.start()
    for w in workers:
        w.join()
    wins = 0
    for p in paths:
        try:
            with open(p, encoding="utf-8") as fh:
                wins += 1 if fh.read().strip() == "1" else 0
        except FileNotFoundError:
            pass
    return {"backend": "sqlite", "processes": procs, "winners": wins,
            "duplicate_effects": max(0, wins - 1)}


# ─── Throughput / tail latency at scale, across processes ────────────

@dataclass
class DistRow:
    store_size: int
    processes: int
    ops: int
    throughput_ops_s: float
    mean_us: float
    median_us: float
    p95_us: float
    p99_us: float


def _proc_burn(db_path: str, count: int, out_path: str) -> None:
    store = SqliteReplayStore(db_path)
    lat: list[float] = []
    try:
        for _ in range(count):
            n = make_nonce()
            t0 = time.perf_counter_ns()
            store.check_and_consume(n)
            lat.append((time.perf_counter_ns() - t0) / 1000.0)
    finally:
        store.close()
    with open(out_path, "w", encoding="utf-8") as fh:
        json.dump(lat, fh)


def bench(path: str, size: int, procs: int, ops_per_proc: int) -> DistRow:
    db = os.path.join(path, f"replay_{size}_{procs}.sqlite")
    store = SqliteReplayStore(db)
    store.populate(size)
    store.close()

    outdir = tempfile.mkdtemp(prefix="tauth_lat_", dir=path)
    paths = [os.path.join(outdir, f"p{i}.json") for i in range(procs)]
    workers = [mp.Process(target=_proc_burn, args=(db, ops_per_proc, p))
               for p in paths]
    t0 = time.perf_counter()
    for w in workers:
        w.start()
    for w in workers:
        w.join()
    elapsed = time.perf_counter() - t0

    lat: list[float] = []
    for p in paths:
        try:
            with open(p, encoding="utf-8") as fh:
                lat.extend(json.load(fh))
        except FileNotFoundError:
            pass
    s = summarize(lat)
    total = ops_per_proc * procs
    try:
        os.remove(db)
    except OSError:
        pass
    return DistRow(store_size=size, processes=procs, ops=total,
                   throughput_ops_s=total / elapsed if elapsed else 0.0,
                   mean_us=s.mean, median_us=s.median,
                   p95_us=s.p95, p99_us=s.p99)


# ─── Clock skew vs pi_7 ──────────────────────────────────────────────

@dataclass
class SkewRow:
    ttl_seconds: int
    skew_seconds: int
    replica_a_accepts: bool
    replica_b_accepts: bool
    replicas_disagree: bool


def skew_window(skews=(0, 1, 2, 5, 10, 30), ttl: int = 60) -> list[SkewRow]:
    """Two replicas with clocks delta apart evaluate one near-expiry cert.

    Replica A's clock is ``exp - delta`` (fast/fresh), replica B's is
    ``exp + delta`` (slow). They disagree on the certificate exactly when
    A accepts and B rejects, which is the window an attacker can exploit
    to have a certificate accepted by one replica after wall-clock expiry.
    """
    cat = fixed_catalog(3, 5)
    rows: list[SkewRow] = []
    for delta in skews:
        req = make_req(cat, "cfg", phi=benign_phi(), ttl=ttl)
        cert = mint(cat, req, all_indices(5))
        a = accept(cert, TOOL, ARGS, ctx_for(), cat, ReplayStore(),
                   now=req.exp - delta)
        b = accept(cert, TOOL, ARGS, ctx_for(), cat, ReplayStore(),
                   now=req.exp + delta)
        rows.append(SkewRow(ttl_seconds=ttl, skew_seconds=delta,
                            replica_a_accepts=a.accepted,
                            replica_b_accepts=b.accepted,
                            replicas_disagree=(a.accepted != b.accepted)))
    return rows


# ─── Reporting ───────────────────────────────────────────────────────

def render_markdown(rows: list[DistRow], mp: dict, skew: list[SkewRow]) -> str:
    lines = ["# Distributed replay store and clock skew", "",
             "## Strongly-consistent (SQLite) replay store", "",
             f"- {mp['processes']} processes raced on one nonce: "
             f"**{mp['winners']} winner(s)**, "
             f"{mp['duplicate_effects']} duplicate effect(s).", "",
             "| store size | processes | ops | throughput (ops/s) | "
             "mean us | p95 us | p99 us |",
             "|---|---|---|---|---|---|---|"]
    for r in rows:
        lines.append(f"| {r.store_size} | {r.processes} | {r.ops} | "
                     f"{r.throughput_ops_s:,.0f} | {r.mean_us:.1f} | "
                     f"{r.p95_us:.1f} | {r.p99_us:.1f} |")
    lines += ["", "## Clock skew vs pi_7 (certificate expiry)", "",
              "Two replicas whose clocks differ by delta evaluate the same "
              "certificate; they disagree exactly on the delta-long window "
              "straddling exp.", "",
              "| TTL (s) | skew delta (s) | replica A | replica B | disagree |",
              "|---|---|---|---|---|"]
    for s in skew:
        lines.append(f"| {s.ttl_seconds} | {s.skew_seconds} | "
                     f"{s.replica_a_accepts} | {s.replica_b_accepts} | "
                     f"{s.replicas_disagree} |")
    return "\n".join(lines) + "\n"


def _write_all(rows, mp_demo, skew, out: Path) -> None:
    out.mkdir(parents=True, exist_ok=True)
    with (out / "distributed.csv").open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=list(asdict(rows[0]).keys()))
        w.writeheader()
        for r in rows:
            w.writerow(asdict(r))
    (out / "distributed.json").write_text(
        json.dumps({"throughput": [asdict(r) for r in rows],
                    "exactly_once": mp_demo,
                    "clock_skew": [asdict(s) for s in skew]}, indent=2),
        encoding="utf-8")
    (out / "distributed.md").write_text(render_markdown(rows, mp_demo, skew),
                                        encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--sizes", default="1000,10000,100000")
    ap.add_argument("--procs", default="1,4,8")
    ap.add_argument("--ops", type=int, default=400)
    ap.add_argument("--out-dir", default="experiments/out")
    args = ap.parse_args(argv)

    tmp = tempfile.mkdtemp(prefix="tauth_dist_")
    rows: list[DistRow] = []
    for size in [int(x) for x in args.sizes.split(",")]:
        for p in [int(x) for x in args.procs.split(",")]:
            row = bench(tmp, size, p, args.ops)
            rows.append(row)
            print(f"  size={size:>7} procs={p} "
                  f"throughput={row.throughput_ops_s:,.0f}/s "
                  f"p99={row.p99_us:.1f}us", file=sys.stderr)

    db = os.path.join(tmp, "exactly_once.sqlite")
    mp_demo = multiprocess_exactly_once(db, procs=8)
    print(f"  [exactly-once] winners={mp_demo['winners']} "
          f"dup={mp_demo['duplicate_effects']}", file=sys.stderr)

    skew = skew_window()
    _write_all(rows, mp_demo, skew, Path(args.out_dir))
    print(f"Wrote {args.out_dir}/distributed.{{csv,json,md}}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
