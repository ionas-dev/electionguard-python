# pylint: disable=protected-access
from dataclasses import dataclass, field, replace
from datetime import timedelta
from typing import Dict, List, Optional

from hypothesis import HealthCheck, Phase, given, settings
from hypothesis.strategies import integers

import electionguard_tools.factories.ballot_factory as BallotFactory
import electionguard_tools.factories.election_factory as ElectionFactory
from electionguard.ballot import BallotBoxState, CiphertextBallot, SubmittedBallot
from electionguard.ballot_box import cast_signed_ballot, spoil_ballot, submit_ballot
from electionguard.credential_registry import (
    CredentialRegistry,
    make_credential_registry,
)
from electionguard.data_store import DataStore
from electionguard.decrypt_with_shares import decrypt_tally
from electionguard.decryption import compute_decryption_share
from electionguard.decryption_share import DecryptionShare
from electionguard.election import CiphertextElectionContext
from electionguard.elgamal import ElGamalKeyPair, elgamal_keypair_from_secret
from electionguard.encrypt import EncryptionMediator, encrypt_ballot
from electionguard.group import ONE_MOD_Q, TWO_MOD_Q, add_q
from electionguard.key_ceremony import CeremonyDetails
from electionguard.key_ceremony_mediator import KeyCeremonyMediator
from electionguard.manifest import InternalManifest, Manifest
from electionguard.musig import aggregate_key_pair
from electionguard.schnorr_signature import SchnorrKeyPair, schnorr_keypair_random
from electionguard.sign import sign
from electionguard.tally import CiphertextTally, tally_ballots, tally_signed_ballots
from electionguard.type import BallotId, GuardianId
from electionguard.utils import get_optional
from electionguard_tools.helpers.election_builder import ElectionBuilder
from electionguard_tools.helpers.key_ceremony_orchestrator import (
    KeyCeremonyOrchestrator,
)
from electionguard_tools.strategies.election import (
    ElectionsAndBallotsTupleType,
    elections_and_ballots,
)
from electionguard_tools.strategies.elgamal import elgamal_keypairs
from electionguard_verify.verify import (
    verify_aggregation,
    verify_aggregation_with_credentials,
    verify_ballot,
    verify_ballot_eligibility,
    verify_credential_registry,
    verify_decryption,
)
from tests.base_test_case import BaseTestCase

election_factory = ElectionFactory.ElectionFactory()
ballot_factory = BallotFactory.BallotFactory()


class TestVerify(BaseTestCase):
    """Test ballot verification"""

    @settings(
        deadline=timedelta(milliseconds=2000),
        suppress_health_check=[HealthCheck.too_slow],
        max_examples=10,
        # disabling the "shrink" phase, because it runs very slowly
        phases=[Phase.explicit, Phase.reuse, Phase.generate, Phase.target],
    )
    @given(elgamal_keypairs())
    def test_verify_ballot(self, keypair: ElGamalKeyPair):
        # Arrange
        manifest = election_factory.get_simple_manifest_from_file()
        internal_manifest, context = election_factory.get_fake_ciphertext_election(
            manifest, keypair.public_key
        )

        data = ballot_factory.get_simple_ballot_from_file()
        device = election_factory.get_encryption_device()
        operator = EncryptionMediator(internal_manifest, context, device)

        encrypted_ballot = operator.encrypt(data)
        self.assertIsNotNone(encrypted_ballot)

        # Act
        verification = verify_ballot(encrypted_ballot, manifest, context)

        # Assert
        self.assertIsNotNone(verification)
        self.assertTrue(verification.verified)

    def _make_signed_ballot(self):
        keypair = get_optional(elgamal_keypair_from_secret(TWO_MOD_Q))
        manifest = election_factory.get_simple_manifest_from_file()
        internal_manifest, context = election_factory.get_fake_ciphertext_election(
            manifest, keypair.public_key
        )
        data = ballot_factory.get_simple_ballot_from_file()
        seed = election_factory.get_encryption_device().get_hash()
        encrypted_ballot = get_optional(
            encrypt_ballot(data, internal_manifest, context, seed)
        )
        share = schnorr_keypair_random()
        credential = aggregate_key_pair([share])
        return sign(encrypted_ballot, credential), share

    @staticmethod
    def _registered_registry(style_id: str, *public_keys) -> CredentialRegistry:
        return make_credential_registry(
            number_of_registrars=1,
            number_of_eligible_voters={style_id: len(public_keys)},
            shares_by_style={style_id: [list(public_keys)]},
        )

    def test_verify_ballot_eligibility(self) -> None:
        signed_ballot, share = self._make_signed_ballot()
        registry = self._registered_registry(signed_ballot.style_id, share.public_key)

        verification = verify_ballot_eligibility(signed_ballot, registry)

        self.assertTrue(verification.verified)

    def test_verify_ballot_eligibility_unregistered(
        self,
    ) -> None:
        signed_ballot, _share = self._make_signed_ballot()
        other_share = schnorr_keypair_random()
        registry = self._registered_registry(
            signed_ballot.style_id, other_share.public_key
        )

        verification = verify_ballot_eligibility(signed_ballot, registry)

        self.assertFalse(verification.verified)

    def test_verify_ballot_eligibility_invalid_signature(self) -> None:
        signed_ballot, share = self._make_signed_ballot()
        registry = self._registered_registry(signed_ballot.style_id, share.public_key)
        tampered_signature = replace(
            signed_ballot.signature,
            response=add_q(signed_ballot.signature.response, ONE_MOD_Q),
        )
        tampered_ballot = replace(signed_ballot, signature=tampered_signature)

        verification = verify_ballot_eligibility(tampered_ballot, registry)

        self.assertFalse(verification.verified)

    def test_verify_credential_registry(self) -> None:
        registry = self._registered_registry(
            "some-style",
            schnorr_keypair_random().public_key,
            schnorr_keypair_random().public_key,
        )

        verification = verify_credential_registry(registry)

        self.assertTrue(verification.verified)

    def test_verify_credential_registry_invalid(self) -> None:
        share = schnorr_keypair_random().public_key
        registry = self._registered_registry("some-style", share, share)

        verification = verify_credential_registry(registry)

        self.assertFalse(verification.verified)

    def test_verify_decryption(self):
        # Arrange
        NUMBER_OF_GUARDIANS = 3
        QUORUM = 2
        CEREMONY_DETAILS = CeremonyDetails(NUMBER_OF_GUARDIANS, QUORUM)

        key_ceremony_mediator = KeyCeremonyMediator(
            "key_ceremony_mediator_mediator", CEREMONY_DETAILS
        )
        guardians = KeyCeremonyOrchestrator.create_guardians(CEREMONY_DETAILS)
        KeyCeremonyOrchestrator.perform_full_ceremony(guardians, key_ceremony_mediator)
        joint_public_key = key_ceremony_mediator.publish_joint_key()
        election_public_keys = key_ceremony_mediator._election_public_keys

        # Setup the election
        manifest = election_factory.get_fake_manifest()
        builder = ElectionBuilder(NUMBER_OF_GUARDIANS, QUORUM, manifest)
        builder.set_public_key(joint_public_key.joint_public_key)
        builder.set_commitment_hash(joint_public_key.commitment_hash)
        internal_manifest, context = get_optional(builder.build())

        # generate encrypted tally
        ballot_store = DataStore()
        ciphertext_tally = tally_ballots(ballot_store, internal_manifest, context)

        # precompute decryption shares for specific selection for the guardians
        shares: Dict[GuardianId, DecryptionShare] = {
            guardian.id: compute_decryption_share(
                guardian._election_keys,
                ciphertext_tally,
                context,
            )
            for guardian in guardians
        }

        plaintext_tally = decrypt_tally(
            ciphertext_tally, shares, context.crypto_extended_base_hash, manifest
        )

        # Act
        verification = verify_decryption(plaintext_tally, election_public_keys, context)

        # Assert
        self.assertIsNotNone(verification)
        self.assertTrue(verification.verified)

    @settings(
        deadline=timedelta(milliseconds=10000),
        suppress_health_check=[HealthCheck.too_slow],
        max_examples=10,
        # disabling the "shrink" phase, because it runs very slowly
        phases=[Phase.explicit, Phase.reuse, Phase.generate, Phase.target],
    )
    @given(integers(1, 3).flatmap(lambda n: elections_and_ballots(n)))
    def test_verify_aggregation(self, election_details: ElectionsAndBallotsTupleType):
        # Arrange
        (
            manifest,
            internal_manifest,
            ballots,
            _secret_key,
            context,
        ) = election_details

        # encrypt each ballot
        store = DataStore()
        encryption_seed = election_factory.get_encryption_device().get_hash()
        for ballot in ballots:
            encrypted_ballot = encrypt_ballot(
                ballot,
                internal_manifest,
                context,
                encryption_seed,
                should_verify_proofs=True,
            )
            encryption_seed = encrypted_ballot.code
            self.assertIsNotNone(encrypted_ballot)
            # add to the ballot store
            store.set(
                encrypted_ballot.object_id,
                spoil_ballot(encrypted_ballot),
            )

        # Generate Tally
        submitted_ballots = store.all()
        tally = tally_ballots(store, internal_manifest, context)
        self.assertIsNotNone(tally)

        # Act
        verification = verify_aggregation(submitted_ballots, tally, manifest, context)

        # Assert
        self.assertIsNotNone(verification)
        self.assertTrue(verification.verified)

    @staticmethod
    def _signed_election() -> "_SignedElection":
        keypair = get_optional(elgamal_keypair_from_secret(TWO_MOD_Q))
        manifest = election_factory.get_fake_manifest()
        internal_manifest, context = election_factory.get_fake_ciphertext_election(
            manifest, keypair.public_key
        )
        shares = [schnorr_keypair_random() for _ in range(NUMBER_OF_VOTERS)]
        election = _SignedElection(manifest, internal_manifest, context, shares)
        election.ballots = [
            election.cast_signed(f"ballot-{i}", share) for i, share in enumerate(shares)
        ]
        style_id = election.ballots[0].style_id
        election.registry = make_credential_registry(
            number_of_registrars=1,
            number_of_eligible_voters={style_id: NUMBER_OF_VOTERS},
            shares_by_style={style_id: [[share.public_key for share in shares]]},
        )
        return election

    def test_verify_aggregation_with_credentials(self) -> None:
        election = self._signed_election()

        tally = election.signed_tally(election.ballots)

        self.assertTrue(election.verify(election.ballots, tally))

    def test_verify_aggregation_with_credentials_unsigned_spoiled_ballot(self) -> None:
        election = self._signed_election()
        spoiled_ballot = submit_ballot(
            election.encrypt("spoiled"), BallotBoxState.SPOILED
        )
        board = election.ballots + [spoiled_ballot]

        self.assertTrue(election.verify(board, election.signed_tally(board)))

    def test_verify_aggregation_with_credentials_tally_counts_unregistered(
        self,
    ) -> None:
        election = self._signed_election()
        unregistered_ballot = election.cast_signed(
            "unregistered", schnorr_keypair_random()
        )
        board = election.ballots + [unregistered_ballot]

        self.assertFalse(election.verify(board, election.unsigned_tally(board)))

    def test_verify_aggregation_with_credentials_unsigned_cast_ballot(self) -> None:
        election = self._signed_election()
        unsigned_ballot = submit_ballot(
            election.encrypt("unsigned"), BallotBoxState.CAST
        )
        board = election.ballots + [unsigned_ballot]

        self.assertFalse(election.verify(board, election.signed_tally(board)))

    def test_verify_aggregation_with_credentials_tally_omits_ballot(self) -> None:
        election = self._signed_election()

        tally = election.signed_tally(election.ballots[1:])

        self.assertFalse(election.verify(election.ballots, tally))

    def test_verify_aggregation_with_credentials_tally_sums_differ(self) -> None:
        election = self._signed_election()
        other_ballots = [
            election.cast_signed(ballot.object_id, share)
            for ballot, share in zip(election.ballots, election.shares)
        ]
        tally = election.signed_tally(other_ballots)

        self.assertEqual(
            tally.cast_ballot_ids,
            election.signed_tally(election.ballots).cast_ballot_ids,
        )
        self.assertFalse(election.verify(election.ballots, tally))

    def test_verify_aggregation_with_credentials_duplicate_credential(self) -> None:
        election = self._signed_election()
        second_vote = election.cast_signed("second-vote", election.shares[0])
        board = election.ballots + [second_vote]

        self.assertFalse(election.verify(board, election.signed_tally(board)))


NUMBER_OF_VOTERS = 3


@dataclass
class _SignedElection:
    """A fake election in which every voter casts a signed ballot."""

    manifest: Manifest
    internal_manifest: InternalManifest
    context: CiphertextElectionContext
    shares: List[SchnorrKeyPair]
    ballots: List[SubmittedBallot] = field(default_factory=list)
    registry: Optional[CredentialRegistry] = None

    def encrypt(self, ballot_id: str) -> CiphertextBallot:
        plaintext_ballot = election_factory.get_fake_ballot(self.manifest, ballot_id)
        seed = election_factory.get_encryption_device().get_hash()
        return get_optional(
            encrypt_ballot(plaintext_ballot, self.internal_manifest, self.context, seed)
        )

    def cast_signed(self, ballot_id: str, share: SchnorrKeyPair) -> SubmittedBallot:
        return cast_signed_ballot(
            sign(self.encrypt(ballot_id), aggregate_key_pair([share]))
        )

    @staticmethod
    def _store(ballots: List[SubmittedBallot]) -> DataStore[BallotId, SubmittedBallot]:
        store: DataStore[BallotId, SubmittedBallot] = DataStore()
        for ballot in ballots:
            store.set(ballot.object_id, ballot)
        return store

    def signed_tally(self, board: List[SubmittedBallot]) -> CiphertextTally:
        return get_optional(
            tally_signed_ballots(
                self._store(board),
                self.internal_manifest,
                self.context,
                get_optional(self.registry),
            )
        )

    def unsigned_tally(self, board: List[SubmittedBallot]) -> CiphertextTally:
        return get_optional(
            tally_ballots(self._store(board), self.internal_manifest, self.context)
        )

    def verify(self, board: List[SubmittedBallot], tally: CiphertextTally) -> bool:
        return verify_aggregation_with_credentials(
            board, tally, get_optional(self.registry), self.manifest, self.context
        ).verified
