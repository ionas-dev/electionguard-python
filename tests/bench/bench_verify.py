import argparse
import logging
import os
import sys
from timeit import default_timer as timer

sys.path.insert(0, os.path.join(os.path.dirname(__file__), os.pardir))
sys.path.insert(0, os.path.dirname(__file__))

from bench_common import (
    print_stats,
    stats,
    write_json_results,
)
from bench_vote import (
    BALLOT_STYLES,
    make_manifest,
    make_plaintext_ballot,
    register_voters,
)

from electionguard.ballot import CiphertextBallot, SignedBallot
from electionguard.credential_registry import CredentialRegistry
from electionguard.election import CiphertextElectionContext
from electionguard.elgamal import elgamal_keypair_from_secret
from electionguard.encrypt import encrypt_ballot
from electionguard.group import TWO_MOD_Q
from electionguard.logs import LOG
from electionguard.manifest import Manifest
from electionguard.sign import sign
from electionguard.utils import get_optional
from electionguard_tools.factories.election_factory import ElectionFactory
from electionguard_verify.verify import verify_ballot, verify_ballot_eligibility

REPEATS = 100

DEFAULT_OUTPUT = os.path.join(
    os.path.dirname(__file__), "results", "verify_benchmark.json"
)

def verify_ballot_bench(
    ballot: CiphertextBallot, manifest: Manifest, context: CiphertextElectionContext
) -> float:
    start = timer()
    verification = verify_ballot(ballot, manifest, context)
    end = timer()
    if not verification.verified:
        raise Exception("Wasn't expecting an invalid ballot during a benchmark!")
    return end - start

def verify_ballot_eligibility_bench(
    ballot: SignedBallot, registry: CredentialRegistry
) -> float:
    start = timer()
    verification = verify_ballot_eligibility(ballot, registry)
    end = timer()
    if not verification.verified:
        raise Exception("Wasn't expecting an ineligible ballot during a benchmark!")
    return end - start

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    _ = parser.add_argument(
        "--output", default=DEFAULT_OUTPUT, help="JSON file to write results to."
    )
    args = parser.parse_args()
    LOG.set_stream_log_level(logging.WARNING)

    results = {}
    for num_contests, candidates_per_contest in BALLOT_STYLES:
        label = f"{num_contests}x{candidates_per_contest}"
        print(f"\nBenchmarking ballot style: {label}")

        manifest = make_manifest(num_contests, candidates_per_contest)
        style_id = manifest.ballot_styles[0].object_id
        keypair = get_optional(elgamal_keypair_from_secret(TWO_MOD_Q))
        internal_manifest, context = ElectionFactory.get_fake_ciphertext_election(
            manifest, keypair.public_key
        )
        seed = ElectionFactory.get_encryption_device().get_hash()

        plaintext_ballot = make_plaintext_ballot(manifest, style_id, f"verify-{label}")
        ciphertext_ballot = get_optional(
            encrypt_ballot(plaintext_ballot, internal_manifest, context, seed)
        )
        _, key_pairs, credential_registry = register_voters(style_id, 1)
        signed_ballot = sign(ciphertext_ballot, next(iter(key_pairs.values())))

        # --- unsigned election ---
        print(f"  Benchmarking Verify, unsigned ({REPEATS} repetitions | {num_contests} contests | {candidates_per_contest} candidates)")
        verify_timings = [
            verify_ballot_bench(ciphertext_ballot, manifest, context)
            for _ in range(REPEATS)
        ]
        print_stats("Verify Ballot", verify_timings)

        # --- signed election ---
        print(f"  Benchmarking Verify, signed ({REPEATS} repetitions | {num_contests} contests | {candidates_per_contest} candidates)")
        eligibility_timings = [
            verify_ballot_eligibility_bench(signed_ballot, credential_registry)
            for _ in range(REPEATS)
        ]
        print_stats("Verify Eligibility", eligibility_timings)

        results[label] = {
            "verify_ballot": stats(verify_timings),
            "verify_ballot_eligibility": stats(eligibility_timings),
        }

    write_json_results(results, args.output)
