"""Distribution statistics with confidence intervals.

The revised experiment document (section 9) requires latency to be
reported as median, standard deviation, p95, p99 and a 95% confidence
interval -- not just a mean. Also used by the corruption curves.
"""
from __future__ import annotations

import math
import statistics
from dataclasses import dataclass, asdict


@dataclass
class Summary:
    n: int
    mean: float
    median: float
    stdev: float
    p95: float
    p99: float
    ci95_low: float
    ci95_high: float
    minimum: float
    maximum: float

    def as_dict(self) -> dict:
        return asdict(self)


def _percentile(sorted_vals: list[float], q: float) -> float:
    """Linear-interpolation percentile (q in [0,1])."""
    if not sorted_vals:
        return 0.0
    if len(sorted_vals) == 1:
        return sorted_vals[0]
    pos = q * (len(sorted_vals) - 1)
    lo = math.floor(pos)
    hi = math.ceil(pos)
    if lo == hi:
        return sorted_vals[int(pos)]
    frac = pos - lo
    return sorted_vals[lo] * (1 - frac) + sorted_vals[hi] * frac


def summarize(values: list[float], confidence: float = 0.95) -> Summary:
    """Full distribution summary. ``values`` are raw samples."""
    vals = [float(v) for v in values]
    if not vals:
        return Summary(0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
    sv = sorted(vals)
    n = len(vals)
    mean = statistics.fmean(vals)
    sd = statistics.stdev(vals) if n >= 2 else 0.0
    # 95% CI of the mean: normal approximation, z = 1.96.
    z = 1.959963984540054
    half = z * sd / math.sqrt(n) if n >= 2 else 0.0
    return Summary(
        n=n, mean=mean, median=statistics.median(vals), stdev=sd,
        p95=_percentile(sv, 0.95), p99=_percentile(sv, 0.99),
        ci95_low=mean - half, ci95_high=mean + half,
        minimum=sv[0], maximum=sv[-1],
    )


def wilson_interval(successes: int, n: int, confidence: float = 0.95
                    ) -> tuple[float, float]:
    """Wilson score interval for a binomial proportion.

    Used for attack/corruption *rates*, where the normal approximation is
    unreliable at 0.0 and 1.0. Returns (low, high).
    """
    if n == 0:
        return (0.0, 0.0)
    z = 1.959963984540054 if abs(confidence - 0.95) < 1e-9 else 2.5758293035489004
    p = successes / n
    denom = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / denom
    margin = (z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n))) / denom
    return (max(0.0, centre - margin), min(1.0, centre + margin))
