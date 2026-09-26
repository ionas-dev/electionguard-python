import argparse
import os
import sys
from timeit import default_timer as timer

sys.path.insert(0, os.path.join(os.path.dirname(__file__), os.pardir))

from bench_common import (
    print_stats,
    stats,
    write_json_results,
)

from electionguard.ballot import CiphertextBallot, SignedBallot
from electionguard.elgamal import elgamal_keypair_from_secret
from electionguard.encrypt import encrypt_ballot
from electionguard.group import TWO_MOD_Q, rand_q
from electionguard.schnorr_signature import schnorr_keypair_random
from electionguard.sign import sign
from electionguard.utils import get_optional
from electionguard_tools.factories.election_factory import ElectionFactory

SIGN_REPEATS = 100
VERIFY_REPEATS = 100
KEYGEN_REPEATS = 100

DEFAULT_OUTPUT = os.path.join(
    os.path.dirname(__file__), "results", "sign_verify_benchmark.json"
)


def make_ballot() -> CiphertextBallot:
    """One encrypted ballot, reused across every sign/verify call."""
    election_factory = ElectionFactory()
    seed = election_factory.get_encryption_device().get_hash()
    keypair = get_optional(elgamal_keypair_from_secret(TWO_MOD_Q))
    manifest = election_factory.get_fake_manifest()
    internal_manifest, context = election_factory.get_fake_ciphertext_election(
        manifest, keypair.public_key
    )
    plaintext_ballot = election_factory.get_fake_ballot(manifest)
    return get_optional(
        encrypt_ballot(plaintext_ballot, internal_manifest, context, seed)
    )


def keygen_bench() -> float:
    """KeyGen once, return elapsed seconds."""
    start = timer()
    _ = schnorr_keypair_random()
    end = timer()
    return end - start


def sign_bench(ballot: CiphertextBallot) -> float:
    """Sign the ballot once with a fresh key pair/nonce, return elapsed seconds."""
    key_pair = schnorr_keypair_random()
    nonce = rand_q()
    start = timer()
    _ = sign(ballot, key_pair, nonce)
    end = timer()
    return end - start


def verify_bench(signed_ballot: SignedBallot) -> float:
    """Verify the ballot once, return elapsed seconds."""
    start = timer()
    _ = signed_ballot.verify_signature()
    end = timer()
    return end - start


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    _ = parser.add_argument(
        "--output", default=DEFAULT_OUTPUT, help="JSON file to write results to."
    )
    args = parser.parse_args()

    ballot = make_ballot()

    print(f"\nBenchmarking KeyGen ({KEYGEN_REPEATS} repetitions)")
    keygen_timings = [keygen_bench() for _ in range(KEYGEN_REPEATS)]
    print_stats("KeyGen", keygen_timings)

    print(f"\nBenchmarking Sign ({SIGN_REPEATS} repetitions)")
    sign_timings = [sign_bench(ballot) for _ in range(SIGN_REPEATS)]
    print_stats("Sign", sign_timings)

    print(f"\nBenchmarking Verify ({VERIFY_REPEATS} repetitions)")
    signed_ballots = [
        sign(ballot, schnorr_keypair_random()) for _ in range(VERIFY_REPEATS)
    ]
    verify_timings = [verify_bench(signed_ballot) for signed_ballot in signed_ballots]
    print_stats("Verify", verify_timings)

    results = {
        "sign": stats(sign_timings),
        "verify": stats(verify_timings),
        "keygen": stats(keygen_timings),
    }
    write_json_results(results, args.output)
