import argparse
import logging
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), os.pardir))
sys.path.insert(0, os.path.dirname(__file__))

from bench_common import write_json_results
from bench_vote import (
    BALLOT_STYLES,
    make_manifest,
    make_plaintext_ballot,
    register_voters,
)

from electionguard.elgamal import elgamal_keypair_from_secret
from electionguard.encrypt import encrypt_ballot
from electionguard.group import TWO_MOD_Q
from electionguard.logs import LOG
from electionguard.serialize import to_raw
from electionguard.sign import sign
from electionguard.utils import get_optional
from electionguard_tools.factories.election_factory import ElectionFactory

DEFAULT_OUTPUT = os.path.join(
    os.path.dirname(__file__), "results", "ballot_size_benchmark.json"
)


def size_in_bytes(ballot: object) -> int:
    return len(to_raw(ballot).encode("utf-8"))


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
        print(
            f"\nBallot style: {label} ({num_contests} contests | {candidates_per_contest} candidates)"
        )

        manifest = make_manifest(num_contests, candidates_per_contest)
        style_id = manifest.ballot_styles[0].object_id
        keypair = get_optional(elgamal_keypair_from_secret(TWO_MOD_Q))
        internal_manifest, context = ElectionFactory.get_fake_ciphertext_election(
            manifest, keypair.public_key
        )
        seed = ElectionFactory.get_encryption_device().get_hash()
        _, key_pairs, _ = register_voters(style_id, 1)
        key_pair = next(iter(key_pairs.values()))

        plaintext_ballot = make_plaintext_ballot(manifest, style_id, f"ballot-{label}")
        ciphertext_ballot = get_optional(
            encrypt_ballot(plaintext_ballot, internal_manifest, context, seed)
        )
        signed_ballot = sign(ciphertext_ballot, key_pair)

        unsigned_bytes = size_in_bytes(ciphertext_ballot)
        signed_bytes = size_in_bytes(signed_ballot)
        overhead_bytes = signed_bytes - unsigned_bytes

        print(f"    Unsigned = {unsigned_bytes} bytes")
        print(f"    Signed   = {signed_bytes} bytes")
        print(f"    Overhead = {overhead_bytes} bytes")

        results[label] = {
            "contests": num_contests,
            "candidates_per_contest": candidates_per_contest,
            "unsigned_bytes": unsigned_bytes,
            "signed_bytes": signed_bytes,
            "signature_overhead_bytes": overhead_bytes,
        }

    write_json_results(results, args.output)
