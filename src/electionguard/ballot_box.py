from dataclasses import dataclass, field
from typing import Dict, Optional

from electionguard.credential_registry import CredentialRegistry
from electionguard.schnorr_signature import SchnorrPublicKey
from electionguard.sign import SignedBallot

from .ballot import (
    BallotBoxState,
    CiphertextBallot,
    SignedSubmittedBallot,
    SubmittedBallot,
    make_ciphertext_submitted_ballot,
    make_signed_submitted_ballot,
)
from .ballot_validator import ballot_is_valid_for_election
from .data_store import DataStore
from .election import CiphertextElectionContext
from .logs import log_warning
from .manifest import InternalManifest
from .type import BallotId


@dataclass
class BallotBox:
    """A stateful convenience wrapper to cache election data."""

    _internal_manifest: InternalManifest = field()
    _encryption: CiphertextElectionContext = field()
    _store: DataStore = field(default_factory=lambda: DataStore())
    _signed_store: DataStore[SchnorrPublicKey, SignedSubmittedBallot] = field(
        default_factory=lambda: DataStore()
    )
    _credential_registry: Optional[CredentialRegistry] = None

    def cast(self, ballot: CiphertextBallot) -> Optional[SubmittedBallot]:
        """Cast a specific encrypted `CiphertextBallot`, unless the election requires signed ballots."""
        if self._credential_registry is not None:
            log_warning(
                f"ballot: {ballot.object_id} rejected, this election requires signed ballots"
            )
            return None
        return submit_ballot_to_box(
            ballot,
            BallotBoxState.CAST,
            self._internal_manifest,
            self._encryption,
            self._store,
        )

    def cast_signed(self, ballot: SignedBallot) -> Optional[SignedSubmittedBallot]:
        """Cast a specific encrypted `CiphertextBallot`, requiring its credential
        to be registered and its signature to verify."""
        return submit_signed_ballot_to_box(
            ballot,
            BallotBoxState.CAST,
            self._internal_manifest,
            self._encryption,
            self._store,
            self._signed_store,
            self._credential_registry,
        )

    def spoil(self, ballot: CiphertextBallot) -> Optional[SubmittedBallot]:
        """Spoil a specific encrypted `CiphertextBallot`."""
        return submit_ballot_to_box(
            ballot,
            BallotBoxState.SPOILED,
            self._internal_manifest,
            self._encryption,
            self._store,
        )


def submit_signed_ballot_to_box(
    ballot: SignedBallot,
    state: BallotBoxState,
    internal_manifest: InternalManifest,
    context: CiphertextElectionContext,
    store: DataStore[BallotId, SubmittedBallot],
    signed_store: DataStore[SchnorrPublicKey, SignedSubmittedBallot],
    credential_registry: Optional[CredentialRegistry],
) -> Optional[SignedSubmittedBallot]:
    """
    Submit a ballot within the context of a specified election and against an existing data store
    Verified that the ballot is valid for the election `internal_manifest` and `context`,
    that its credential is registered in `credential_registry` for the ballot's style,
    that its signature verifies, and that the ballot has not already been cast or spoiled.
    :return: a `SubmittedBallot` or `None` if there was an error
    """
    if not ballot_is_valid_for_election(ballot, internal_manifest, context, True):
        log_warning(f"ballot: {ballot.object_id} failed validity check")
        return None

    if credential_registry is None:
        log_warning(
            f"ballot: {ballot.object_id} rejected, no credential registry configured"
        )
        return None

    if not credential_registry.is_registered(ballot.style_id, ballot.public_credential):
        log_warning(f"ballot: {ballot.object_id} credential is not registered")
        return None

    if not ballot.verify_signature():
        log_warning(f"ballot: {ballot.object_id} failed signature verification")
        return None

    existing_ballot = store.get(ballot.object_id)
    if existing_ballot is not None:
        log_warning(
            f"error accepting ballot, {ballot.object_id} already exists with state: {existing_ballot.state}"
        )
        return None

    # TODO: ISSUE #56: check if the ballot includes the nonce, and regenerate the proofs
    # TODO: ISSUE #56: check if the ballot includes the proofs, if it does not include the nonce

    existing_ballot = signed_store.get(ballot.public_credential)
    if existing_ballot is not None:
        log_warning(
            f"error accepting ballot, {ballot.object_id} already exists with state: {existing_ballot.state}"
        )
        return None

    ballot_box_ballot = submit_signed_ballot(ballot, state)

    store.set(ballot.object_id, ballot_box_ballot)
    signed_store.set(ballot.public_credential, ballot_box_ballot)
    return ballot_box_ballot


def submit_ballot_to_box(
    ballot: CiphertextBallot,
    state: BallotBoxState,
    internal_manifest: InternalManifest,
    context: CiphertextElectionContext,
    store: DataStore,
) -> Optional[SubmittedBallot]:
    """
    Submit a ballot within the context of a specified election and against an existing data store
    Verified that the ballot is valid for the election `internal_manifest` and `context` and
    that the ballot has not already been cast or spoiled.
    :return: a `SubmittedBallot` or `None` if there was an error
    """
    if not ballot_is_valid_for_election(ballot, internal_manifest, context, True):
        log_warning(f"ballot: {ballot.object_id} failed validity check")
        return None

    existing_ballot = store.get(ballot.object_id)
    if existing_ballot is not None:
        log_warning(
            f"error accepting ballot, {ballot.object_id} already exists with state: {existing_ballot.state}"
        )
        return None

    # TODO: ISSUE #56: check if the ballot includes the nonce, and regenerate the proofs
    # TODO: ISSUE #56: check if the ballot includes the proofs, if it does not include the nonce

    ballot_box_ballot = submit_ballot(ballot, state)

    store.set(ballot_box_ballot.object_id, ballot_box_ballot)
    return store.get(ballot_box_ballot.object_id)


def get_ballots(
    store: DataStore, state: Optional[BallotBoxState]
) -> Dict[BallotId, SubmittedBallot]:
    """Get ballots from the store optionally filtering on state."""
    return {
        ballot_id: ballot
        for (ballot_id, ballot) in store.items()
        if state is None or ballot.state == state
    }


def submit_ballot(
    ballot: CiphertextBallot, state: BallotBoxState = BallotBoxState.UNKNOWN
) -> SubmittedBallot:
    """
    Convert a `CiphertextBallot` into a `SubmittedBallot`, with all nonces removed.
    """

    return make_ciphertext_submitted_ballot(
        ballot.object_id,
        ballot.style_id,
        ballot.manifest_hash,
        ballot.code_seed,
        ballot.contests,
        ballot.code,
        ballot.timestamp,
        state,
    )


def submit_signed_ballot(
    ballot: SignedBallot, state: BallotBoxState = BallotBoxState.UNKNOWN
) -> SignedSubmittedBallot:
    """
    Convert a `CiphertextBallot` into a `SubmittedBallot`, with all nonces removed.
    """

    return make_signed_submitted_ballot(
        ballot.object_id,
        ballot.style_id,
        ballot.manifest_hash,
        ballot.code_seed,
        ballot.contests,
        ballot.code,
        ballot.signature,
        ballot.public_credential,
        ballot.timestamp,
        state,
    )


def cast_ballot(ballot: CiphertextBallot) -> SubmittedBallot:
    """
    Convert a `CiphertextBallot` into a `SubmittedBallot`, with all nonces removed.
    Declare a ballot as CAST.
    """
    return submit_ballot(
        ballot,
        BallotBoxState.CAST,
    )


def cast_signed_ballot(ballot: SignedBallot) -> SignedSubmittedBallot:
    """
    Convert a `SignedBallot` into a `SignedSubmittedBallot`, with all nonces removed.
    Declare a ballot as CAST.
    """
    return submit_signed_ballot(
        ballot,
        BallotBoxState.CAST,
    )


def spoil_ballot(ballot: CiphertextBallot) -> SubmittedBallot:
    """
    Convert a `CiphertextBallot` into a `SubmittedBallot`, with all nonces removed.
    Declare a ballot as CAST.
    """
    return submit_ballot(
        ballot,
        BallotBoxState.SPOILED,
    )
