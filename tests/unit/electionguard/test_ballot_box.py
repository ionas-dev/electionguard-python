from dataclasses import replace
from typing import Optional

import electionguard_tools.factories.election_factory as ElectionFactory
from electionguard.ballot import BallotBoxState, SignedSubmittedBallot, SubmittedBallot
from electionguard.ballot_box import (
    BallotBox,
    cast_ballot,
    spoil_ballot,
    submit_ballot,
    submit_ballot_to_box,
)
from electionguard.credential_registry import (
    CredentialRegistry,
    make_credential_registry,
)
from electionguard.data_store import DataStore
from electionguard.elgamal import elgamal_keypair_from_secret
from electionguard.encrypt import encrypt_ballot
from electionguard.group import ONE_MOD_Q, TWO_MOD_Q, add_q
from electionguard.musig import aggregate_key_pair
from electionguard.schnorr_signature import SchnorrPublicKey, schnorr_keypair_random
from electionguard.sign import sign
from electionguard.type import BallotId
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

    def _make_signed_ballot(self, share=None, ballot_id=None):
        """Returns a ballot signed with the credential aggregated from `share`, and `share`."""
        plaintext_ballot = (
            self.ballot
            if ballot_id is None
            else replace(self.ballot, object_id=ballot_id)
        )
        encrypted_ballot = get_optional(
            encrypt_ballot(
                plaintext_ballot,
                self.internal_manifest,
                self.context,
                self.seed,
            )
        )
        share = share if share is not None else schnorr_keypair_random()
        credential = aggregate_key_pair([share])
        return sign(encrypted_ballot, credential), share

    def _registered_registry(self, style_id: str, *public_keys) -> CredentialRegistry:
        return make_credential_registry(
            number_of_registrars=1,
            number_of_eligible_voters={style_id: len(public_keys)},
            shares_by_style={style_id: [list(public_keys)]},
        )

    def _signed_ballot_box(
        self,
        registry: CredentialRegistry,
        store: DataStore[BallotId, SubmittedBallot],
        signed_store: Optional[
            DataStore[SchnorrPublicKey, SignedSubmittedBallot]
        ] = None,
    ) -> BallotBox:
        return BallotBox(
            self.internal_manifest,
            self.context,
            store,
            signed_store if signed_store is not None else DataStore(),
            registry,
        )

    def test_ballot_box_cast_signed_ballot(self) -> None:
        signed_ballot, key_pair = self._make_signed_ballot()
        registry = self._registered_registry(
            signed_ballot.style_id, key_pair.public_key
        )
        store: DataStore[BallotId, SubmittedBallot] = DataStore()
        ballot_box = self._signed_ballot_box(registry, store)

        submitted_ballot = ballot_box.cast_signed(signed_ballot)

        self.assertIsNotNone(submitted_ballot)
        self.assertEqual(submitted_ballot.state, BallotBoxState.CAST)
        ballot_in_box = store.get(signed_ballot.object_id)
        self.assertIsNotNone(ballot_in_box)
        self.assertEqual(ballot_in_box.state, BallotBoxState.CAST)

    def test_ballot_box_cast_signed_ballot_without_registry(self) -> None:
        signed_ballot, _ = self._make_signed_ballot()
        store: DataStore[BallotId, SubmittedBallot] = DataStore()
        ballot_box = BallotBox(self.internal_manifest, self.context, store)

        self.assertIsNone(ballot_box.cast_signed(signed_ballot))
        self.assertIsNone(store.get(signed_ballot.object_id))

    def test_ballot_box_cast_signed_ballot_unregistered(
        self,
    ) -> None:
        signed_ballot, _ = self._make_signed_ballot()
        other_key_pair = schnorr_keypair_random()
        registry = self._registered_registry(
            signed_ballot.style_id, other_key_pair.public_key
        )
        store: DataStore[BallotId, SubmittedBallot] = DataStore()
        ballot_box = self._signed_ballot_box(registry, store)

        self.assertIsNone(ballot_box.cast_signed(signed_ballot))
        self.assertIsNone(store.get(signed_ballot.object_id))

    def test_ballot_box_cast_signed_ballot_invalid_signature(self) -> None:
        signed_ballot, key_pair = self._make_signed_ballot()
        registry = self._registered_registry(
            signed_ballot.style_id, key_pair.public_key
        )
        tampered_signature = replace(
            signed_ballot.signature,
            response=add_q(signed_ballot.signature.response, ONE_MOD_Q),
        )
        tampered_ballot = replace(signed_ballot, signature=tampered_signature)
        store: DataStore[BallotId, SubmittedBallot] = DataStore()
        ballot_box = self._signed_ballot_box(registry, store)

        self.assertIsNone(ballot_box.cast_signed(tampered_ballot))
        self.assertIsNone(store.get(tampered_ballot.object_id))

    def test_ballot_box_cast_unsigned_ballot_with_registry(self) -> None:
        encrypted_ballot = get_optional(
            encrypt_ballot(
                self.ballot,
                self.internal_manifest,
                self.context,
                self.seed,
            )
        )
        registry = make_credential_registry(
            number_of_registrars=1, number_of_eligible_voters={}, shares_by_style={}
        )
        store: DataStore[BallotId, SubmittedBallot] = DataStore()
        ballot_box = self._signed_ballot_box(registry, store)

        self.assertIsNone(ballot_box.cast(encrypted_ballot))
        self.assertIsNone(store.get(encrypted_ballot.object_id))

    def test_ballot_box_cast_signed_ballot_credential_used(
        self,
    ) -> None:
        signed_ballot, share = self._make_signed_ballot()
        second_signed_ballot, _ = self._make_signed_ballot(
            share, ballot_id="second-ballot"
        )
        registry = self._registered_registry(signed_ballot.style_id, share.public_key)
        store: DataStore[BallotId, SubmittedBallot] = DataStore()
        ballot_box = self._signed_ballot_box(registry, store)

        self.assertIsNotNone(ballot_box.cast_signed(signed_ballot))
        self.assertIsNone(ballot_box.cast_signed(second_signed_ballot))
        self.assertIsNone(store.get(second_signed_ballot.object_id))
        self.assertEqual(len(store), 1)

    def test_ballot_box_cast_signed_ballot_id_used(
        self,
    ) -> None:
        signed_ballot, share = self._make_signed_ballot()
        same_id_ballot, other_share = self._make_signed_ballot()
        registry = make_credential_registry(
            number_of_registrars=1,
            number_of_eligible_voters={signed_ballot.style_id: 2},
            shares_by_style={
                signed_ballot.style_id: [[share.public_key, other_share.public_key]]
            },
        )
        store: DataStore[BallotId, SubmittedBallot] = DataStore()
        signed_store: DataStore[SchnorrPublicKey, SignedSubmittedBallot] = DataStore()
        ballot_box = self._signed_ballot_box(registry, store, signed_store)

        self.assertIsNotNone(ballot_box.cast_signed(signed_ballot))
        self.assertIsNone(ballot_box.cast_signed(same_id_ballot))
        self.assertEqual(
            get_optional(store.get(signed_ballot.object_id)).public_credential,
            signed_ballot.public_credential,
        )
        # the rejected ballot must not use up its credential
        self.assertIsNone(signed_store.get(same_id_ballot.public_credential))

    def test_ballot_box_cast_signed_ballot_invalid(
        self,
    ) -> None:
        signed_ballot, share = self._make_signed_ballot()
        registry = self._registered_registry(signed_ballot.style_id, share.public_key)
        invalid_ballot = replace(
            signed_ballot, manifest_hash=add_q(signed_ballot.manifest_hash, ONE_MOD_Q)
        )
        store: DataStore[BallotId, SubmittedBallot] = DataStore()
        ballot_box = self._signed_ballot_box(registry, store)

        self.assertTrue(invalid_ballot.verify_signature())
        self.assertIsNone(ballot_box.cast_signed(invalid_ballot))
        self.assertIsNone(store.get(invalid_ballot.object_id))

    def test_ballot_box_cast_signed_ballot_other_style(
        self,
    ) -> None:
        signed_ballot, share = self._make_signed_ballot()
        registry = make_credential_registry(
            number_of_registrars=1,
            number_of_eligible_voters={signed_ballot.style_id: 0, "other-style": 1},
            shares_by_style={
                signed_ballot.style_id: [[]],
                "other-style": [[share.public_key]],
            },
        )
        store: DataStore[BallotId, SubmittedBallot] = DataStore()
        ballot_box = self._signed_ballot_box(registry, store)

        self.assertIsNone(ballot_box.cast_signed(signed_ballot))
        self.assertIsNone(store.get(signed_ballot.object_id))
