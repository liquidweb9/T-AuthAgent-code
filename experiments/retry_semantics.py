"""Failure, retry and idempotency semantics (revision spec section 10).

Reviewers ask what happens when the nonce is consumed but the downstream
tool invocation subsequently fails. The paper's position is:

  * the gateway consumes the nonce *before* forwarding, so a consumed
    certificate can never be retried (pi_8 rejects it);
  * a client that needs to retry must obtain a **new** certificate; the
    one-shot property is preserved;
  * exactly-once **authorization** does not imply exactly-once
    **execution** -- that requires a business idempotency key the backend
    deduplicates on.

This experiment demonstrates all four states (clean, failed, unknown
result, duplicate submission) with and without an idempotency key, and
counts tool-side effects. The headline is the contrast between the two
controls:

    lost-acknowledgement, NO idempotency key -> 2 effects from 1 intent
    lost-acknowledgement, WITH idempotency key -> 1 effect from 1 intent

Usage:
    python -m experiments.retry_semantics --out-dir experiments/out
"""
from __future__ import annotations

import argparse
import csv
import json
import sys
from dataclasses import asdict, dataclass
from pathlib import Path

from experiments.authenv import benign_phi, ctx_for, fixed_catalog, make_req, mint
from secagent.auth.gateway import accept
from secagent.auth.replay_store import ReplayStore

TOOL = "send_email"
ARGS = {"to": "bob@example.com"}


class DownstreamError(Exception):
    """The backend rejected the operation before any effect."""


class UnknownResult(Exception):
    """The effect was applied but the acknowledgement was lost."""


@dataclass
class Backend:
    """A tool backend with an idempotency-key dedup table."""
    effects: list
    seen: dict

    def __init__(self) -> None:
        self.effects = []
        self.seen = {}

    def execute(self, idem_key: str | None, args: dict,
                mode: str = "ok") -> str:
        # Replay of a known idempotency key: return the original outcome,
        # apply no second effect.
        if idem_key is not None and idem_key in self.seen:
            return self.seen[idem_key]

        if mode == "fail_before_effect":
            # No effect happened; the client may safely retry.
            raise DownstreamError("backend rejected before applying")

        # The effect happens here, once.
        self.effects.append(dict(args))
        outcome = "applied"
        if idem_key is not None:
            self.seen[idem_key] = outcome

        if mode == "lost_ack":
            raise UnknownResult("effect applied; acknowledgement lost")
        return outcome

    def effect_count(self) -> int:
        return len(self.effects)


@dataclass
class RetryRow:
    scenario: str
    idempotency_key: bool
    first_authorized: bool
    retry_same_cert_rejected: bool
    retry_new_cert_authorized: bool
    effects: int
    duplicate_effects: int
    note: str


def _new_cert(cat):
    req = make_req(cat, "cfg", phi=benign_phi())
    return mint(cat, req, [1, 2, 3])


def run_scenario(scenario: str, first_mode: str, retry_mode: str | None,
                 use_idem: bool) -> RetryRow:
    cat = fixed_catalog(3, 5)
    store = ReplayStore()
    backend = Backend()
    idem = f"tx-{scenario}" if use_idem else None

    # --- first attempt: authorize then execute ------------------------
    cert1 = _new_cert(cat)
    a1 = accept(cert1, TOOL, ARGS, ctx_for(), cat, store)
    try:
        backend.execute(idem, ARGS, first_mode)
    except (DownstreamError, UnknownResult):
        pass

    # --- is retrying the *same* certificate possible? -----------------
    a1b = accept(cert1, TOOL, ARGS, ctx_for(), cat, store)
    same_rejected = (not a1b.accepted) and a1b.rejected_clause == "pi_8"

    # --- optional retry with a NEW certificate, same idempotency key --
    retry_authorized = False
    if retry_mode is not None:
        cert2 = _new_cert(cat)
        a2 = accept(cert2, TOOL, ARGS, ctx_for(), cat, store)
        retry_authorized = a2.accepted
        try:
            backend.execute(idem, ARGS, retry_mode)
        except (DownstreamError, UnknownResult):
            pass

    effects = backend.effect_count()
    note = {
        "clean": "single authorization, single execution, no retry",
        "fail_before_effect": ("no effect on the failed attempt; "
                               "the retry applies exactly once"),
        "lost_ack": ("the retry is deduplicated by the idempotency key"
                     if use_idem else
                     "no key -> the retry applies a SECOND effect"),
    }.get(scenario.split("_no_key")[0].split("_with_key")[0], "")

    return RetryRow(
        scenario=scenario, idempotency_key=use_idem,
        first_authorized=a1.accepted,
        retry_same_cert_rejected=same_rejected,
        retry_new_cert_authorized=retry_authorized,
        effects=effects,
        duplicate_effects=max(0, effects - 1),
        note=note,
    )


# (scenario, first-attempt mode, retry mode or None, idempotency key)
SCENARIOS = [
    ("clean", "ok", None, False),
    ("failed_before_effect", "fail_before_effect", "ok", True),
    ("lost_ack_no_key", "lost_ack", "ok", False),
    ("lost_ack_with_key", "lost_ack", "ok", True),
    ("duplicate_submission_no_key", "ok", None, False),
    ("duplicate_submission_with_key", "ok", None, True),
]


def run() -> list[RetryRow]:
    rows: list[RetryRow] = []
    for name, first_mode, retry_mode, use_idem in SCENARIOS:
        if name.startswith("duplicate_submission"):
            rows.append(_duplicate(name, use_idem))
        else:
            rows.append(run_scenario(name, first_mode, retry_mode, use_idem))
    return rows


def _duplicate(name: str, use_idem: bool) -> RetryRow:
    """Two independently authorized submissions for one business intent."""
    cat = fixed_catalog(3, 5)
    store = ReplayStore()
    backend = Backend()
    idem = f"tx-{name}" if use_idem else None

    a1 = accept(_new_cert(cat), TOOL, ARGS, ctx_for(), cat, store)
    backend.execute(idem, ARGS, "ok")
    a2 = accept(_new_cert(cat), TOOL, ARGS, ctx_for(), cat, store)
    backend.execute(idem, ARGS, "ok")

    effects = backend.effect_count()
    return RetryRow(
        scenario=name, idempotency_key=use_idem,
        first_authorized=a1.accepted, retry_same_cert_rejected=False,
        retry_new_cert_authorized=a2.accepted, effects=effects,
        duplicate_effects=max(0, effects - 1),
        note=("backend deduplicates the second submission"
              if use_idem else "no key -> two effects for one intent"),
    )


# ─── Reporting ───────────────────────────────────────────────────────

def render_markdown(rows: list[RetryRow]) -> str:
    lines = ["# Failure, retry and idempotency semantics", "",
             "The gateway consumes the nonce before forwarding, so a",
             "consumed certificate is never retryable (`same cert rejected`",
             "= pi_8). Retries require a new certificate; duplicate",
             "business effects are prevented only by the backend's",
             "idempotency key.", "",
             "| scenario | idemp. key | first auth | same cert rejected | "
             "retry auth | effects | duplicate effects |",
             "|---|---|---|---|---|---|---|"]
    for r in rows:
        lines.append(
            f"| {r.scenario} | {r.idempotency_key} | {r.first_authorized} | "
            f"{r.retry_same_cert_rejected} | {r.retry_new_cert_authorized} | "
            f"{r.effects} | {r.duplicate_effects} |")
    return "\n".join(lines) + "\n"


def _write_all(rows: list[RetryRow], out: Path) -> None:
    out.mkdir(parents=True, exist_ok=True)
    with (out / "retry.csv").open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=list(asdict(rows[0]).keys()))
        w.writeheader()
        for r in rows:
            w.writerow(asdict(r))
    (out / "retry.json").write_text(
        json.dumps([asdict(r) for r in rows], indent=2), encoding="utf-8")
    (out / "retry.md").write_text(render_markdown(rows), encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out-dir", default="experiments/out")
    args = ap.parse_args(argv)
    rows = run()
    _write_all(rows, Path(args.out_dir))
    for r in rows:
        print(f"  {r.scenario:30s} idem={r.idempotency_key!s:5s} "
              f"effects={r.effects} dup={r.duplicate_effects}", file=sys.stderr)
    print(f"Wrote {args.out_dir}/retry.{{csv,json,md}}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
