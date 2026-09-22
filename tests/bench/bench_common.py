"""Shared helper for the JSON-exporting benchmark scripts in this directory
(bench_sign_verify.py, bench_vote.py, bench_ballot_size.py). Not a benchmark
by itself. For the older CSV-based election benchmarks, see
election_bench_common.py instead.
"""

import json
import math
import os
import platform
import sys
from datetime import datetime, timezone
from statistics import NormalDist, mean, stdev
from typing import Any, Dict, List, Union

import gmpy2

from electionguard.scheduler import Scheduler

Z_95 = NormalDist().inv_cdf(0.975)
RELATIVE_ACCURACY = 0.01

def identity(x: int) -> int:
    """Placeholder function used just to warm up the parallel mapper prior to benchmarking."""
    return x

def is_stable(timings: List[float], relative_precision: float = 0.01) -> bool:
    return _sem(timings) < relative_precision * mean(timings) / Z_95

def required_repeats(
    timings: List[float], relative_precision: float = 0.01
) -> int:
    """Sample size needed so a 95% CI on the mean is within
    `relative_precision` of the mean, extrapolated from a pilot sample's
    mean/stdev. Rounded up to the nearest multiple of `round_to`."""
    n_needed = (Z_95 * _stdev(timings) / (relative_precision * mean(timings))) ** 2
    return math.ceil(n_needed)

def _stdev(timings: List[float]) -> float:
    return stdev(timings) if len(timings) > 1 else 0.0

def _sem(timings: List[float]) -> float:
    return _stdev(timings) / (len(timings) ** 0.5) if len(timings) > 1 else 0.0

def stats(timings: List[float]) -> Dict[str, Any]:
    """avg/stdev/duration of a series of timings - the measured values every
    JSON-exporting benchmark reports for a given condition. duration_seconds
    is just sum(timings); callers whose timings run concurrently (e.g. a
    parallel batch) should overwrite it with an actual wall-clock
    measurement instead, since the naive sum overcounts there."""
    return {
        "repeats": len(timings),
        "avg_seconds": mean(timings),
        "stdev_seconds": _stdev(timings),
        "duration_seconds": sum(timings),
        "sem_seconds": _sem(timings),
    }

def print_stats(label: str, timings: List[float]) -> None:
    s = stats(timings)
    print(f"  {label}: (n={s['repeats']})")
    print(f"    Avg            = {s['avg_seconds']:.6f} sec")
    print(f"    Stddev         = {s['stdev_seconds']:.6f} sec")
    print(f"    Duration       = {s['duration_seconds']:.6f} sec")
    print(f"    SEM            = {s['sem_seconds']:.6f} sec")
    if not is_stable(timings):
        print(f"    Target Repeats = {required_repeats(timings)}")

def meta() -> Dict[str, Any]:
    return {
        "date": datetime.now(timezone.utc).isoformat(),
        "cpu": platform.processor(),
        "cores_physical": Scheduler.cpu_count(),
        "cores_logical": os.cpu_count(),
        "os": platform.platform(),
        "python": sys.version.split()[0],
        "gmpy2": gmpy2.version(),
    }


def write_json_results(results: Union[Dict[str, Any], List[Dict[str, Any]]], output_path: str) -> None:
    """Write {"meta": ..., "results": results} to output_path (creating its
    directory if needed), then print just the path."""
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump({"meta": meta(), "results": results}, f, indent=2)
    print()
    print(output_path)
