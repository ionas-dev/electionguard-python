import argparse
import logging
import os
import sys
from datetime import datetime
from timeit import default_timer as timer
from typing import Dict, List, Tuple

sys.path.insert(0, os.path.join(os.path.dirname(__file__), os.pardir))

from bench_common import (
    print_stats,
    stats,
    write_json_results,
)

from electionguard.ballot import CiphertextBallot, PlaintextBallot, SignedBallot
from electionguard.ballot_box import BallotBox
from electionguard.credential_registry import (
    CredentialRegistry,
    make_credential_registry,
)
from electionguard.election import CiphertextElectionContext
from electionguard.elgamal import elgamal_keypair_from_secret
from electionguard.electoral_roll import ElectoralRoll
from electionguard.encrypt import contest_from, encrypt_ballot
from electionguard.group import TWO_MOD_Q
from electionguard.logs import LOG
from electionguard.manifest import (
    BallotStyle,
    Candidate,
    CandidateContestDescription,
    ContactInformation,
    ElectionType,
    GeopoliticalUnit,
    InternalManifest,
    Manifest,
    ReportingUnitType,
    SelectionDescription,
    SpecVersion,
    VoteVariationType,
)
from electionguard.musig import aggregate_key_pair
from electionguard.registrar import Registrar
from electionguard.schnorr_signature import SchnorrKeyPair
from electionguard.sign import sign
from electionguard.utils import get_optional
from electionguard.voter import Voter
from electionguard_tools.factories.election_factory import ElectionFactory

# (number_of_contests, candidates_per_contest)
BALLOT_STYLES = (
    (1, 2),
    (2, 5),
    (3, 10),
    (4, 20),
)
NUMBER_OF_REGISTRARS = 2
REPEATS = 50

DEFAULT_OUTPUT = os.path.join(
    os.path.dirname(__file__), "results", "vote_benchmark.json"
)

def make_manifest(num_contests: int, candidates_per_contest: int) -> Manifest:
    """A manifest with `num_contests` single-winner contests, each with
    `candidates_per_contest` candidates, all under one ballot style."""
    ballot_style = BallotStyle("some-ballot-style-id")
    ballot_style.geopolitical_unit_ids = ["some-geopolitical-unit-id"]

    candidates: List[Candidate] = []
    contests: List[CandidateContestDescription] = []
    for c in range(num_contests):
        selections = []
        for k in range(candidates_per_contest):
            candidate_id = f"candidate-{c}-{k}"
            candidates.append(Candidate(candidate_id))
            selections.append(
                SelectionDescription(f"selection-{c}-{k}", k, candidate_id)
            )
        contests.append(
            CandidateContestDescription(
                f"contest-{c}",
                c,
                "some-geopolitical-unit-id",
                VoteVariationType.one_of_m,
                1,
                1,
                f"contest-{c}-name",
                selections,
            )
        )

    return Manifest(
        spec_version=SpecVersion.EG0_95,
        election_scope_id="bench-vote-scope",
        type=ElectionType.unknown,
        start_date=datetime.now(),
        end_date=datetime.now(),
        geopolitical_units=[
            GeopoliticalUnit(
                "some-geopolitical-unit-id",
                "some-gp-unit-name",
                ReportingUnitType.unknown,
            )
        ],
        parties=[],
        candidates=candidates,
        contests=contests,
        ballot_styles=[ballot_style],
    )

def make_plaintext_ballot(
    manifest: Manifest, style_id: str, ballot_id: str
) -> PlaintextBallot:
    return PlaintextBallot(
        ballot_id, style_id, [contest_from(contest) for contest in manifest.contests]
    )

def register_voters(
    style_id: str, count: int
) -> Tuple[List[Voter], Dict[str, SchnorrKeyPair], CredentialRegistry]:
    """Untimed setup: register `count` voters for `style_id` with
    NUMBER_OF_REGISTRARS registrars and aggregate each voter's own signing
    credential, mirroring step_register_voters in the extended end-to-end test."""
    voters = [
        Voter(f"voter-{style_id}-{i}", f"Voter {i}", ContactInformation(), style_id)
        for i in range(count)
    ]
    electoral_roll = ElectoralRoll(f"roll-{style_id}", voters)

    registrars = [
        Registrar(f"registrar-{j}", j, electoral_roll)
        for j in range(NUMBER_OF_REGISTRARS)
    ]
    for registrar in registrars:
        registrar.generate_credentials()

    shares_by_style = {
        style_id: [
            registrar.publish_public_credentials_for_style(style_id)
            for registrar in registrars
        ]
    }
    credential_registry = make_credential_registry(
        number_of_registrars=NUMBER_OF_REGISTRARS,
        number_of_eligible_voters={style_id: count},
        shares_by_style=shares_by_style,
    )

    key_pairs = {
        voter.object_id: aggregate_key_pair(
            [registrar.send_credential_to_voter(voter.object_id) for registrar in registrars]
        )
        for voter in voters
    }
    return voters, key_pairs, credential_registry

def encrypt_bench(
    ballot: PlaintextBallot,
    internal_manifest: InternalManifest,
    context: CiphertextElectionContext,
    seed: object,
) -> Tuple[float, CiphertextBallot]:
    start = timer()
    ciphertext_ballot = get_optional(
        encrypt_ballot(ballot, internal_manifest, context, seed)
    )
    end = timer()
    return end - start, ciphertext_ballot

def encrypt_and_sign_bench(
    ballot: PlaintextBallot,
    internal_manifest: InternalManifest,
    context: CiphertextElectionContext,
    seed: object,
    key_pair: SchnorrKeyPair,
) -> Tuple[float, SignedBallot]:
    start = timer()
    ciphertext_ballot = get_optional(
        encrypt_ballot(ballot, internal_manifest, context, seed)
    )
    signed_ballot = sign(ciphertext_ballot, key_pair)
    end = timer()
    return end - start, signed_ballot

def cast_bench(ballot_box: BallotBox, ballot: CiphertextBallot) -> float:
    start = timer()
    submitted = ballot_box.cast(ballot)
    end = timer()
    if submitted is None:
        raise Exception("Wasn't expecting a rejected ballot during a benchmark!")
    return end - start

def cast_signed_bench(ballot_box: BallotBox, ballot: SignedBallot) -> float:
    start = timer()
    submitted = ballot_box.cast_signed(ballot)
    end = timer()
    if submitted is None:
        raise Exception("Wasn't expecting a rejected ballot during a benchmark!")
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

        # --- unsigned election ---
        unsigned_ballot_box = BallotBox(internal_manifest, context)
        encrypt_timings: List[float] = []
        cast_timings: List[float]  = []

        print(f"  Benchmarking Vote, unsigned ({REPEATS} repetitions | {num_contests} contests | {candidates_per_contest} candidates)")
        for i in range(REPEATS):
            plaintext_ballot = make_plaintext_ballot(
                manifest, style_id, f"vote-{label}-unsigned-{i}"
            )
            elapsed, ciphertext_ballot = encrypt_bench(
                plaintext_ballot, internal_manifest, context, seed
            )
            encrypt_timings.append(elapsed)

            elapsed = cast_bench(unsigned_ballot_box, ciphertext_ballot)
            cast_timings.append(elapsed)

        print_stats("Encrypt", encrypt_timings)
        print_stats("Cast", cast_timings)

        # --- signed election ---
        _, key_pairs, credential_registry = register_voters(style_id, REPEATS)
        voter_ids = list(key_pairs.keys())
        signed_ballot_box = BallotBox(
            internal_manifest, context, _credential_registry=credential_registry
        )
        encrypt_sign_timings: List[float] = []
        cast_signed_timings: List[float] = []
        print(f"  Benchmarking Vote, signed ({REPEATS} repetitions | {num_contests} contests | {candidates_per_contest} candidates)")
        for i in range(REPEATS):
            plaintext_ballot = make_plaintext_ballot(
                manifest, style_id, f"vote-{label}-signed-{i}"
            )
            key_pair = key_pairs[voter_ids[i]]
            elapsed, signed_ballot = encrypt_and_sign_bench(
                plaintext_ballot, internal_manifest, context, seed, key_pair
            )
            encrypt_sign_timings.append(elapsed)

            elapsed = cast_signed_bench(signed_ballot_box, signed_ballot)
            cast_signed_timings.append(elapsed)

        print_stats("Encrypt+Sign", encrypt_sign_timings)
        print_stats("Cast", cast_signed_timings)

        results[label] = {
            "unsigned": {
                "encrypt": stats(encrypt_timings),
                "cast": stats(cast_timings),
            },
            "signed": {
                "encrypt_sign": stats(encrypt_sign_timings),
                "cast": stats(cast_signed_timings),
            },
        }

    write_json_results(results, args.output)
