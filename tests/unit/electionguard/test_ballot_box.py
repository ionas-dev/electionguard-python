from dataclasses import replace

import electionguard_tools.factories.election_factory as ElectionFactory
from electionguard.ballot import BallotBoxState
from electionguard.ballot_box import (
    BallotBox,
    cast_ballot,
    spoil_ballot,
    submit_ballot,
    submit_ballot_to_box,
)
from electionguard.credential_registry import CredentialRegistry
from electionguard.data_store import DataStore
from electionguard.elgamal import elgamal_keypair_from_secret
from electionguard.encrypt import encrypt_ballot
from electionguard.group import ONE_MOD_Q, TWO_MOD_Q, add_q
from electionguard.musig import aggregate_key_pair
from electionguard.schnorr_signature import schnorr_keypair_random
from electionguard.sign import sign
from electionguard.utils import get_optional
from tests.base_test_case import BaseTestCase


class TestBallotBox(BaseTestCase):
    """Ballot box tests"""

    def setUp(self) -> None:
        """Setup ballot box tests by creating a mock ballot, manifest, and encryption context."""

        election_factory = ElectionFactory.ElectionFactory()
        self.seed = election_factory.get_encryption_device().get_hash()
        keypair = get_optional(elgamal_keypair_from_secret(TWO_MOD_Q))
        manifest = election_factory.get_fake_manifest()
        (
            self.internal_manifest,
            self.context,
        ) = election_factory.get_fake_ciphertext_election(manifest, keypair.public_key)
        self.ballot = election_factory.get_fake_ballot(manifest)

    def test_ballot_box_cast_ballot(self) -> None:
        # Arrange
        encrypted_ballot = get_optional(
            encrypt_ballot(
                self.ballot,
                self.internal_manifest,
                self.context,
                self.seed,
            )
        )
        store: DataStore = DataStore()

        # Act
        ballot_box = BallotBox(self.internal_manifest, self.context, store)
        submitted_ballot = ballot_box.cast(encrypted_ballot)

        # Assert
        # Test returned ballot
        self.assertIsNotNone(submitted_ballot)
        self.assertEqual(submitted_ballot.state, BallotBoxState.CAST)

        # Test ballot in box
        ballot_in_box = store.get(encrypted_ballot.object_id)
        self.assertIsNotNone(ballot_in_box)
        self.assertEqual(ballot_in_box.state, BallotBoxState.CAST)
        self.assertEqual(ballot_in_box.object_id, submitted_ballot.object_id)

        # Test failure modes
        self.assertIsNone(ballot_box.cast(encrypted_ballot))  # cannot cast again
        self.assertIsNone(
            ballot_box.spoil(encrypted_ballot)
        )  # cannot spoil a ballot already cast

    def test_ballot_box_spoil_ballot(self) -> None:
        # Arrange
        encrypted_ballot = get_optional(
            encrypt_ballot(
                self.ballot,
                self.internal_manifest,
                self.context,
                self.seed,
            )
        )
        store: DataStore = DataStore()

        # Act
        ballot_box = BallotBox(self.internal_manifest, self.context, store)
        submitted_ballot = ballot_box.spoil(encrypted_ballot)

        # Assert
        # Test returned ballot
        self.assertIsNotNone(submitted_ballot)
        self.assertEqual(submitted_ballot.state, BallotBoxState.SPOILED)

        # Test ballot in box
        ballot_in_box = store.get(encrypted_ballot.object_id)
        self.assertIsNotNone(ballot_in_box)
        self.assertEqual(ballot_in_box.state, BallotBoxState.SPOILED)
        self.assertEqual(ballot_in_box.object_id, submitted_ballot.object_id)

        # Test failure modes
        self.assertIsNone(ballot_box.cast(encrypted_ballot))  # cannot cast again
        self.assertIsNone(
            ballot_box.spoil(encrypted_ballot)
        )  # cannot spoil a ballot already cast

    def test_submit_ballot_to_box(self) -> None:
        # Arrange
        encrypted_ballot = get_optional(
            encrypt_ballot(
                self.ballot,
                self.internal_manifest,
                self.context,
                self.seed,
            )
        )
        store: DataStore = DataStore()

        # Act
        submitted_ballot = submit_ballot_to_box(
            encrypted_ballot,
            BallotBoxState.CAST,
            self.internal_manifest,
            self.context,
            store,
        )

        # Assert
        # Test returned ballot
        self.assertIsNotNone(submitted_ballot)
        self.assertEqual(submitted_ballot.state, BallotBoxState.CAST)

        # Test ballot in box
        ballot_in_box = store.get(encrypted_ballot.object_id)
        self.assertIsNotNone(ballot_in_box)
        self.assertEqual(ballot_in_box.state, BallotBoxState.CAST)
        self.assertEqual(ballot_in_box.object_id, submitted_ballot.object_id)

        # Test failure modes
        self.assertIsNone(
            submit_ballot_to_box(
                encrypted_ballot,
                BallotBoxState.CAST,
                self.internal_manifest,
                self.context,
                store,
            )
        )  # cannot cast again
        self.assertIsNone(
            submit_ballot_to_box(
                encrypted_ballot,
                BallotBoxState.SPOILED,
                self.internal_manifest,
                self.context,
                store,
            )
        )  # cannot spoil a ballot already cast

    def test_cast_ballot(self) -> None:
        # Arrange
        encrypted_ballot = get_optional(
            encrypt_ballot(
                self.ballot,
                self.internal_manifest,
                self.context,
                self.seed,
            )
        )

        # Act
        submitted_ballot = cast_ballot(encrypted_ballot)

        # Assert
        self.assertIsNotNone(submitted_ballot)
        self.assertEqual(submitted_ballot.state, BallotBoxState.CAST)
        self.assertEqual(encrypted_ballot.object_id, submitted_ballot.object_id)

    def test_spoil_ballot(self) -> None:
        # Arrange
        encrypted_ballot = get_optional(
            encrypt_ballot(
                self.ballot,
                self.internal_manifest,
                self.context,
                self.seed,
            )
        )

        # Act
        submitted_ballot = spoil_ballot(encrypted_ballot)

        # Assert
        self.assertIsNotNone(submitted_ballot)
        self.assertEqual(submitted_ballot.state, BallotBoxState.SPOILED)
        self.assertEqual(encrypted_ballot.object_id, submitted_ballot.object_id)

    def test_submit_ballot(self) -> None:
        # Arrange
        encrypted_ballot = get_optional(
            encrypt_ballot(
                self.ballot,
                self.internal_manifest,
                self.context,
                self.seed,
            )
        )

        # Act
        submitted_ballot = submit_ballot(encrypted_ballot, BallotBoxState.CAST)

        # Assert
        self.assertIsNotNone(submitted_ballot)
        self.assertEqual(submitted_ballot.state, BallotBoxState.CAST)
        self.assertEqual(encrypted_ballot.object_id, submitted_ballot.object_id)

    def _make_signed_ballot(self):
        """
        Builds a signed ballot the way a real voter would: `share` is the one
        registrar share this test uses (what gets registered), and the
        ballot is actually signed with the MuSig-aggregated credential
        derived from it (aggregation applies a coefficient even for a single
        share, so the two are not the same key).
        """
        encrypted_ballot = get_optional(
            encrypt_ballot(
                self.ballot,
                self.internal_manifest,
                self.context,
                self.seed,
            )
        )
        share = schnorr_keypair_random()
        credential = aggregate_key_pair([share])
        return sign(encrypted_ballot, credential), share

    def _registered_registry(self, style_id: str, *public_keys) -> CredentialRegistry:
        registry = CredentialRegistry(
            number_of_registrars=1, number_of_eligible_voters={style_id: len(public_keys)}
        )
        registry.register_credentials(style_id, list(public_keys), 0)
        return registry

    def test_ballot_box_cast_signed_ballot_with_registered_credential(self) -> None:
        signed_ballot, key_pair = self._make_signed_ballot()
        registry = self._registered_registry(signed_ballot.style_id, key_pair.public_key)
        store: DataStore = DataStore()
        ballot_box = BallotBox(
            self.internal_manifest, self.context, store, _credential_registry=registry
        )

        submitted_ballot = ballot_box.cast_signed(signed_ballot)

        self.assertIsNotNone(submitted_ballot)
        self.assertEqual(submitted_ballot.state, BallotBoxState.CAST)
        ballot_in_box = store.get(signed_ballot.object_id)
        self.assertIsNotNone(ballot_in_box)
        self.assertEqual(ballot_in_box.state, BallotBoxState.CAST)

    def test_ballot_box_cast_signed_ballot_rejected_without_a_registry(self) -> None:
        signed_ballot, _ = self._make_signed_ballot()
        store: DataStore = DataStore()
        ballot_box = BallotBox(self.internal_manifest, self.context, store)

        self.assertIsNone(ballot_box.cast_signed(signed_ballot))
        self.assertIsNone(store.get(signed_ballot.object_id))

    def test_ballot_box_cast_signed_ballot_rejected_when_credential_not_registered(
        self,
    ) -> None:
        signed_ballot, _ = self._make_signed_ballot()
        other_key_pair = schnorr_keypair_random()
        registry = self._registered_registry(signed_ballot.style_id, other_key_pair.public_key)
        store: DataStore = DataStore()
        ballot_box = BallotBox(
            self.internal_manifest, self.context, store, _credential_registry=registry
        )

        self.assertIsNone(ballot_box.cast_signed(signed_ballot))
        self.assertIsNone(store.get(signed_ballot.object_id))

    def test_ballot_box_cast_signed_ballot_rejected_when_signature_invalid(self) -> None:
        # Tamper with the signature itself (not crypto_hash/public_credential) so this
        # exercises verify_signature() specifically, rather than being rejected earlier
        # by the pre-existing encryption-validity check or the registration check.
        signed_ballot, key_pair = self._make_signed_ballot()
        registry = self._registered_registry(signed_ballot.style_id, key_pair.public_key)
        tampered_signature = replace(
            signed_ballot.signature,
            response=add_q(signed_ballot.signature.response, ONE_MOD_Q),
        )
        tampered_ballot = replace(signed_ballot, signature=tampered_signature)
        store: DataStore = DataStore()
        ballot_box = BallotBox(
            self.internal_manifest, self.context, store, _credential_registry=registry
        )

        self.assertIsNone(ballot_box.cast_signed(tampered_ballot))
        self.assertIsNone(store.get(tampered_ballot.object_id))

    def test_ballot_box_cast_ballot_unaffected_by_missing_registry(self) -> None:
        # Unsigned casting must keep working with no credential registry at all.
        encrypted_ballot = get_optional(
            encrypt_ballot(
                self.ballot,
                self.internal_manifest,
                self.context,
                self.seed,
            )
        )
        store: DataStore = DataStore()
        ballot_box = BallotBox(self.internal_manifest, self.context, store)

        submitted_ballot = ballot_box.cast(encrypted_ballot)

        self.assertIsNotNone(submitted_ballot)
        self.assertEqual(submitted_ballot.state, BallotBoxState.CAST)

    def test_ballot_box_cast_rejected_when_registry_is_configured(self) -> None:
        # An election that has a credential registry requires signed ballots;
        # unsigned cast() must be refused, not silently accepted.
        encrypted_ballot = get_optional(
            encrypt_ballot(
                self.ballot,
                self.internal_manifest,
                self.context,
                self.seed,
            )
        )
        registry = CredentialRegistry(number_of_registrars=1, number_of_eligible_voters={})
        store: DataStore = DataStore()
        ballot_box = BallotBox(
            self.internal_manifest, self.context, store, _credential_registry=registry
        )

        self.assertIsNone(ballot_box.cast(encrypted_ballot))
        self.assertIsNone(store.get(encrypted_ballot.object_id))
