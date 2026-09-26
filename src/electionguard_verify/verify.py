from dataclasses import dataclass
from typing import Dict, List, Optional, Set

from electionguard.ballot import (
    BallotBoxState,
    CiphertextBallot,
    SignedSubmittedBallot,
    SubmittedBallot,
)
from electionguard.credential_registry import CredentialRegistry
from electionguard.election import CiphertextElectionContext
from electionguard.group import ElementModP
from electionguard.key_ceremony import ElectionPublicKey
from electionguard.manifest import (
    InternalManifest,
    Manifest,
)
from electionguard.sign import SignedBallot
from electionguard.tally import CiphertextTally, PlaintextTally
from electionguard.type import GuardianId


@dataclass
class Verification:
    """
    Representation of a verification result with an optional message
    """

    verified: bool
    """Verification successful?"""
    message: Optional[str]


def verify_ballot(
    ballot: CiphertextBallot,
    manifest: Manifest,
    context: CiphertextElectionContext,
) -> Verification:
    """
    Method to verify the validity of a ballot
    """

    if not ballot.is_valid_encryption(
        manifest.crypto_hash(),
        context.elgamal_public_key,
        context.crypto_extended_base_hash,
    ):
        return Verification(
            False,
            message=f"verify_ballot: mismatching ballot encryption {ballot.object_id}",
        )

    return Verification(True, message=None)


def verify_ballot_eligibility(
    ballot: SignedBallot,
    registry: CredentialRegistry,
) -> Verification:
    """
    Method to verify that a signed ballot's credential was registered for the
    ballot's style, and that its signature verifies under that credential.
    """

    if not registry.is_registered(ballot.style_id, ballot.public_credential):
        return Verification(
            False,
            message=f"verify_ballot_eligibility: {ballot.object_id} credential is not registered",
        )

    if not ballot.verify_signature():
        return Verification(
            False,
            message=f"verify_ballot_eligibility: {ballot.object_id} failed signature verification",
        )

    return Verification(True, message=None)


def verify_credential_registry(
    registry: CredentialRegistry,
) -> Verification:
    """
    Method to verify the credential registry
    """

    if not registry.verify():
        return Verification(
            False,
            message="verify_credential_registry: credential registry is not valid",
        )

    return Verification(True, message=None)


def verify_decryption(
    tally: PlaintextTally,
    election_public_keys: Dict[GuardianId, ElectionPublicKey],
    context: CiphertextElectionContext,
) -> Verification:
    for _, contest in tally.contests.items():
        for selection_id, selection in contest.selections.items():
            for share in selection.shares:
                election_public_key = election_public_keys.get(share.guardian_id).key
                if not share.proof.is_valid(
                    selection.message,
                    election_public_key,
                    share.share,
                    context.crypto_extended_base_hash,
                ):
                    return Verification(
                        False,
                        message=f"verify_decryption: {selection_id} selection is not valid",
                    )

    return Verification(True, message=None)


def verify_aggregation(
    submitted_ballots: List[SubmittedBallot],
    tally: CiphertextTally,
    manifest: Manifest,
    context: CiphertextElectionContext,
) -> Verification:
    new_tally = CiphertextTally("verify", InternalManifest(manifest), context)

    for ballot in submitted_ballots:
        new_tally.append(ballot, True)

    if (
        isinstance(tally, CiphertextTally)
        and new_tally.cast_ballot_ids == tally.cast_ballot_ids
        and new_tally.spoiled_ballot_ids == tally.spoiled_ballot_ids
        and new_tally.contests == tally.contests
    ):
        return Verification(True, message=None)

    return Verification(
        False,
        message="verify_aggregation: aggregated value of ballots doesn't matches with tally",
    )


def verify_aggregation_with_credentials(
    submitted_ballots: List[SubmittedBallot],
    tally: CiphertextTally,
    credential_registry: CredentialRegistry,
    manifest: Manifest,
    context: CiphertextElectionContext,
) -> Verification:
    new_tally = CiphertextTally("verify", InternalManifest(manifest), context)
    used_credentials: Set[ElementModP] = set()

    for ballot in submitted_ballots:
        if ballot.state == BallotBoxState.CAST:
            if not isinstance(ballot, SignedSubmittedBallot):
                return Verification(
                    False,
                    message=f"verify_aggregation_with_credentials: cast ballot {ballot.object_id} is not signed",
                )

            credential = ballot.public_credential
            if credential in used_credentials:
                return Verification(
                    False,
                    message="verify_aggregation_with_credentials: ballots contain duplicate credentials",
                )
            used_credentials.add(credential)

        new_tally.append_signed_ballot(ballot, credential_registry, True)

    if (
        isinstance(tally, CiphertextTally)
        and new_tally.cast_ballot_ids == tally.cast_ballot_ids
        and new_tally.spoiled_ballot_ids == tally.spoiled_ballot_ids
        and new_tally.contests == tally.contests
    ):
        return Verification(True, message=None)

    return Verification(
        False,
        message="verify_aggregation_with_credentials: aggregated value of ballots doesn't matches with tally",
    )
