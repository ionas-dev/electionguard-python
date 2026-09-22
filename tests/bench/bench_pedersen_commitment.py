import argparse
import os
import sys
from timeit import default_timer as timer
from typing import List

sys.path.insert(0, os.path.join(os.path.dirname(__file__), os.pardir))

from bench_common import (
    print_stats,
    stats,
    write_json_results,
)

from electionguard.group import rand_q
from electionguard.hash import CryptoHashableAll
from electionguard.manifest import ContactInformation
from electionguard.pedersen import (
    PedersenCommitment,
    PedersenOpening,
    pedersen_commit,
    pedersen_open,
)
from electionguard.voter import Voter

ROLL_SIZES = (10, 100, 1000, 1000)
REPEATS = 250

DEFAULT_OUTPUT = os.path.join(
    os.path.dirname(__file__), "results", "pedersen_commitment_benchmark.json"
)

def make_voters(count: int) -> List[Voter]:
    """A synthetic electoral roll of `count` voters, reused across every commit/open call."""
    return [
        Voter(
            f"voter-{i}",
            f"Voter {i}",
            ContactInformation(email=[f"voter{i}@example.com"]),
            "some-ballot-style-id",
        )
        for i in range(count)
    ]

def commit_bench(message: List[CryptoHashableAll]) -> float:
    """Commit to the message once, return elapsed seconds."""
    start = timer()
    _ = pedersen_commit(*message)
    end = timer()
    return end - start

def open_bench(
    message: List[CryptoHashableAll],
    commitment: PedersenCommitment,
    opening: PedersenOpening,
) -> float:
    """Open the commitment to the message once, return elapsed seconds."""
    start = timer()
    valid = pedersen_open(*message, commitment=commitment, opening=opening)
    end = timer()
    if not valid:
        raise Exception("Wasn't expecting an invalid opening during a benchmark!")
    return end - start

def bench_message(message: List[CryptoHashableAll]) -> dict:
    print(f"  Benchmarking Commit ({REPEATS} repetitions)")
    commit_timings = [commit_bench(message) for _ in range(REPEATS)]
    print_stats("Commit", commit_timings)

    print(f"  Benchmarking Open ({REPEATS} repetitions)")
    commitment, opening = pedersen_commit(*message)
    open_timings = [open_bench(message, commitment, opening) for _ in range(REPEATS)]
    print_stats("Open", open_timings)

    return {"commit": stats(commit_timings), "open": stats(open_timings)}

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    _ = parser.add_argument(
        "--output", default=DEFAULT_OUTPUT, help="JSON file to write results to."
    )
    args = parser.parse_args()

    results = {}

    print("\nBenchmarking on a single element")
    results["element"] = bench_message([rand_q()])

    for size in ROLL_SIZES:
        print(f"\nBenchmarking on electoral roll size: {size}")
        results[str(size)] = bench_message(make_voters(size))

    write_json_results(results, args.output)
