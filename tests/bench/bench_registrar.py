import argparse
import logging
import os
import sys
from timeit import default_timer as timer
from typing import List

sys.path.insert(0, os.path.join(os.path.dirname(__file__), os.pardir))
sys.path.insert(0, os.path.dirname(__file__))

from bench_common import (
    print_stats,
    stats,
    write_json_results,
)
from bench_vote import NUMBER_OF_REGISTRARS

from electionguard.credential_registry import (
    CredentialRegistry,
    make_credential_registry,
)
from electionguard.electoral_roll import ElectoralRoll
from electionguard.logs import LOG
from electionguard.manifest import ContactInformation
from electionguard.pedersen import PedersenCommitment, PedersenOpening, pedersen_commit
from electionguard.registrar import Registrar
from electionguard.voter import Voter

STYLE_ID = "some-ballot-style-id"
VOTER_COUNTS = (10, 100, 1000, 10000)
REPEATS = 50

DEFAULT_OUTPUT = os.path.join(
    os.path.dirname(__file__), "results", "registrar_benchmark.json"
)

def make_electoral_roll(count: int) -> ElectoralRoll:
    voters = [
        Voter(f"voter-{i}", f"Voter {i}", ContactInformation(), STYLE_ID)
        for i in range(count)
    ]
    return ElectoralRoll(f"roll-{count}", voters)

def make_registrars(electoral_roll: ElectoralRoll) -> List[Registrar]:
    return [
        Registrar(f"registrar-{j}", j, electoral_roll)
        for j in range(NUMBER_OF_REGISTRARS)
    ]

def make_registry(registrars: List[Registrar], count: int) -> CredentialRegistry:
    return make_credential_registry(
        number_of_registrars=NUMBER_OF_REGISTRARS,
        number_of_eligible_voters={STYLE_ID: count},
        shares_by_style={
            STYLE_ID: [
                registrar.publish_public_credentials_for_style(STYLE_ID)
                for registrar in registrars
            ]
        },
    )

def generate_credentials_bench(registrar: Registrar) -> float:
    start = timer()
    registrar.generate_credentials()
    end = timer()
    return end - start

def verify_registration_bench(registrar: Registrar, registry: CredentialRegistry) -> float:
    start = timer()
    verified = registrar.verify_registration(registry)
    end = timer()
    if not verified:
        raise Exception("Wasn't expecting an invalid registration during a benchmark!")
    return end - start

def verify_electoral_roll_bench(
    registrar: Registrar, commitment: PedersenCommitment, opening: PedersenOpening
) -> float:
    start = timer()
    verified = registrar.verify_electoral_roll_commitment(commitment, opening)
    end = timer()
    if not verified:
        raise Exception("Wasn't expecting an invalid commitment during a benchmark!")
    return end - start

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    _ = parser.add_argument(
        "--output", default=DEFAULT_OUTPUT, help="JSON file to write results to."
    )
    args = parser.parse_args()
    LOG.set_stream_log_level(logging.WARNING)

    results = {}
    for count in VOTER_COUNTS:
        print(f"\nBenchmarking on number of voters: {count}")
        electoral_roll = make_electoral_roll(count)

        print(f"  Benchmarking GenerateCredentials ({REPEATS} repetitions)")
        generate_timings = [
            generate_credentials_bench(Registrar("registrar-0", 0, electoral_roll))
            for _ in range(REPEATS)
        ]
        print_stats("GenerateCredentials", generate_timings)

        registrars = make_registrars(electoral_roll)
        for registrar in registrars:
            registrar.generate_credentials()
        registry = make_registry(registrars, count)

        repeats = REPEATS * 20 if count < 100 else REPEATS * 2
        print(f"  Benchmarking VerifyRegistration ({repeats} repetitions)")
        registration_timings = [
            verify_registration_bench(registrars[0], registry) for _ in range(repeats)
        ]
        print_stats("VerifyRegistration", registration_timings)

        print(f"  Benchmarking VerifyElectoralRollCommitment ({REPEATS} repetitions)")
        commitment, opening = pedersen_commit(*electoral_roll.voters)
        commitment_timings = [
            verify_electoral_roll_bench(registrars[0], commitment, opening)
            for _ in range(REPEATS)
        ]
        print_stats("VerifyElectoralRollCommitment", commitment_timings)

        results[str(count)] = {
            "generate_credentials": stats(generate_timings),
            "verify_registration": stats(registration_timings),
            "verify_electoral_roll_pedersen_commitment": stats(commitment_timings),
        }

    write_json_results(results, args.output)
