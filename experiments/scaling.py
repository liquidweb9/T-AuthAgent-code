"""Replay-store scaling and concurrency (revision spec section 10).

Reviewers ask for: increasing replay-store size, concurrent requests,
throughput / tail latency, duplicate side effects, and behaviour across
gateway replicas. This module measures all of them against the
prototype's in-process ``ReplayStore`` and, critically, demonstrates the
*negative* cross-process result: two gateway processes with independent
stores each accept the same certificate, because each has a separate
consumed-nonce set. That is the concrete evidence for the paper's claim
that a strongly-consistent backend is required.

Usage:
    python -m experiments.scaling --sizes 1000,10000,100000,1000000 \\n        --concurrency 1,8,32,128 --out experiments/out/scaling.csv
"""
from __future__ import annotations

import argparse
import csv
import json
import multiprocessing as mp
import statistics
import sys
import threading
import time
import tracemalloc
from dataclasses import asdict, dataclass
from pathlib import Path

from experiments.stats import summarize
from secagent.auth.replay_store import ReplayStore
from secagent.auth.req import make_nonce


class InstrumentedStore(ReplayStore):
    """ReplayStore that also accumulates lock-acquisition wait time."""

    def __init__(self) -> None:
        super().__init__()
        self.lock_wait_ns = 0
        self._wl_lock = threading.Lock()

    def check_and_consume(self, nonce: bytes) -> bool:
        t0 = time.perf_counter_ns()
        acquired = self._lock.acquire()
        wait = time.perf_counter_ns() - t0
        try:
            with self._wl_lock:
                self.lock_wait_ns += wait
            if nonce in self._used:
                return False
            self._used.add(nonce)
            return True
        finally:
            if acquired:
                self._lock.release()


@dataclass
class ScaleRow:
    store_size: int
    concurrency: int
    ops: int
    throughput_ops_s: float
    mean_us: float
    median_us: float
    p95_us: float
    p99_us: float
    duplicate_effects: int
    lock_wait_mean_us: float
    mem_peak_kib: float


def _populate(store: ReplayStore, size: int) -> None:
    for _ in range(size):
        store.mark(make_nonce())


def _bench_one(size: int, concurrency: int, ops: int) -> ScaleRow:
    store = InstrumentedStore()
    _populate(store, size)

    # Each operation consumes a *fresh* nonce -> the insert path, which is
    # the path that contends on the lock in a real gateway.
    barrier = threading.Barrier(concurrency)
    lat: list[float] = []
    lat_lock = threading.Lock()
    per_thread = max(1, ops // concurrency)

    def worker():
        local: list[float] = []
        barrier.wait()
        for _ in range(per_thread):
            n = make_nonce()
            t0 = time.perf_counter_ns()
            store.check_and_consume(n)
            local.append((time.perf_counter_ns() - t0) / 1000.0)
        with lat_lock:
            lat.extend(local)

    tracemalloc.start()
    threads = [threading.Thread(target=worker) for _ in range(concurrency)]
    t0 = time.perf_counter()
    for th in threads:
        th.start()
    for th in threads:
        th.join()
    elapsed = time.perf_counter() - t0
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    # Duplicate-effect probe: fire the SAME nonce from every thread; the
    # number of extra winners is the duplicate-effect count.
    same = make_nonce()
    results: list[bool] = []
    rlock = threading.Lock()
    b2 = threading.Barrier(concurrency)

    def dup_worker():
        b2.wait()
        ok = store.check_and_consume(same)
        with rlock:
            results.append(ok)

    dts = [threading.Thread(target=dup_worker) for _ in range(concurrency)]
    for th in dts:
        th.start()
    for th in dts:
        th.join()
    duplicate_effects = max(0, sum(results) - 1)

    s = summarize(lat)
    total_ops = per_thread * concurrency
    return ScaleRow(
        store_size=size, concurrency=concurrency, ops=total_ops,
        throughput_ops_s=total_ops / elapsed if elapsed > 0 else 0.0,
        mean_us=s.mean, median_us=s.median, p95_us=s.p95, p99_us=s.p99,
        duplicate_effects=duplicate_effects,
        lock_wait_mean_us=(store.lock_wait_ns / total_ops / 1000.0
                           if total_ops else 0.0),
        mem_peak_kib=peak / 1024.0,
    )


# ─── Cross-process duplicate demonstration ────────────────────────────

def _proc_worker(nonce: bytes, out: "mp.Queue") -> None:
    store = ReplayStore()          # each process has its OWN store
    out.put(store.check_and_consume(nonce))


def multiprocess_duplicate_demo(procs: int = 4) -> dict:
    """Show that independent gateway processes both accept one nonce.

    With a process-local store, N gateway replicas each see a fresh set and
    each accept the same certificate -> N side effects for one
    single-use authorization. A strongly consistent backend is required.
    """
    nonce = make_nonce()
    q: mp.Queue = mp.Queue()
    workers = [mp.Process(target=_proc_worker, args=(nonce, q))
               for _ in range(procs)]
    for w in workers:
        w.start()
    for w in workers:
        w.join()
    accepts = []
    while not q.empty():
        accepts.append(q.get())
    return {
        "processes": procs,
        "accepts": sum(1 for a in accepts if a),
        "duplicate_effects": max(0, sum(1 for a in accepts if a) - 1),
        "note": "process-local replay store => no cross-replica protection",
    }


def render_markdown(rows: list[ScaleRow], mp_demo: dict) -> str:
    lines = ["# Replay-store scaling and concurrency", "",
             "| store size | concurrency | ops | throughput (ops/s) | "
             "mean us | p95 us | p99 us | dup effects | lock wait us | "
             "peak MiB |",
             "|---|---|---|---|---|---|---|---|---|---|"]
    for r in rows:
        lines.append(
            f"| {r.store_size} | {r.concurrency} | {r.ops} | "
            f"{r.throughput_ops_s:,.0f} | {r.mean_us:.2f} | {r.p95_us:.2f} | "
            f"{r.p99_us:.2f} | {r.duplicate_effects} | "
            f"{r.lock_wait_mean_us:.3f} | {r.mem_peak_kib/1024:.1f} |")
    lines += ["", "## Cross-process (multi-replica) probe", "",
              f"- processes: {mp_demo['processes']}",
              f"- accepts for one certificate: {mp_demo['accepts']}",
              f"- duplicate effects: {mp_demo['duplicate_effects']}",
              f"- {mp_demo['note']}"]
    return "\n".join(lines) + "\n"


def _write_all(rows: list[ScaleRow], mp_demo: dict, out: Path) -> None:
    out.mkdir(parents=True, exist_ok=True)
    with (out / "scaling.csv").open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=list(asdict(rows[0]).keys()))
        w.writeheader()
        for r in rows:
            w.writerow(asdict(r))
    (out / "scaling.json").write_text(
        json.dumps({"rows": [asdict(r) for r in rows], "multiprocess": mp_demo},
                   indent=2), encoding="utf-8")
    (out / "scaling.md").write_text(render_markdown(rows, mp_demo),
                                    encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--sizes", default="1000,10000,100000")
    ap.add_argument("--concurrency", default="1,8,32,128")
    ap.add_argument("--ops", type=int, default=2000)
    ap.add_argument("--out-dir", default="experiments/out")
    ap.add_argument("--mp-procs", type=int, default=4)
    args = ap.parse_args(argv)

    sizes = [int(x) for x in args.sizes.split(",")]
    conc = [int(x) for x in args.concurrency.split(",")]

    rows: list[ScaleRow] = []
    for size in sizes:
        for c in conc:
            row = _bench_one(size, c, args.ops)
            rows.append(row)
            print(f"  size={size:>7} conc={c:>3} "
                  f"throughput={row.throughput_ops_s:,.0f}/s "
                  f"p99={row.p99_us:.1f}us dup={row.duplicate_effects}",
                  file=sys.stderr)

    mp_demo = multiprocess_duplicate_demo(args.mp_procs)
    print(f"  [mp] accepts={mp_demo['accepts']} "
          f"dup={mp_demo['duplicate_effects']}", file=sys.stderr)

    _write_all(rows, mp_demo, Path(args.out_dir))
    print(f"Wrote {args.out_dir}/scaling.{{csv,json,md}}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
