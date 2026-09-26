from dataclasses import replace
from typing import List, Optional

import electionguard_tools.factories.election_factory as ElectionFactory
from electionguard.ballot import BallotBoxState, SignedSubmittedBallot, SubmittedBallot
from electionguard.ballot_box import (
    cast_signed_ballot,
    submit_ballot,
    submit_signed_ballot,
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
from electionguard.schnorr_signature import SchnorrKeyPair, schnorr_keypair_random
from electionguard.sign import sign
from electionguard.tally import (
    CiphertextTally,
    tally_signed_ballot,
    tally_signed_ballots,
)
from electionguard.type import BallotId
from electionguard.utils import get_optional
from tests.base_test_case import BaseTestCase

NUMBER_OF_BALLOTS = 3


class TestTally(BaseTestCase):
    """Ciphertext tally tests"""

    def setUp(self) -> None:
        election_factory = ElectionFactory.ElectionFactory()
        self.seed = election_factory.get_encryption_device().get_hash()
        keypair = get_optional(elgamal_keypair_from_secret(TWO_MOD_Q))
        self.manifest = election_factory.get_fake_manifest()
        (
            self.internal_manifest,
            self.context,
        ) = election_factory.get_fake_ciphertext_election(
            self.manifest, keypair.public_key
        )
        self.election_factory = election_factory

        self.shares = [schnorr_keypair_random() for _ in range(NUMBER_OF_BALLOTS)]
        self.ballots = [
            self._make_cast_ballot(f"ballot-{i}", share)
            for i, share in enumerate(self.shares)
        ]
        self.style_id = self.ballots[0].style_id
        self.registry = make_credential_registry(
            number_of_registrars=1,
            number_of_eligible_voters={self.style_id: NUMBER_OF_BALLOTS},
            shares_by_style={
                self.style_id: [[share.public_key for share in self.shares]]
            },
        )

    def _make_cast_ballot(
        self, ballot_id: str, share: SchnorrKeyPair
    ) -> SignedSubmittedBallot:
        plaintext_ballot = self.election_factory.get_fake_ballot(
            self.manifest, ballot_id
        )
        encrypted_ballot = get_optional(
            encrypt_ballot(
                plaintext_ballot, self.internal_manifest, self.context, self.seed
            )
        )
        return cast_signed_ballot(sign(encrypted_ballot, aggregate_key_pair([share])))

    @staticmethod
    def _store(ballots: List[SubmittedBallot]) -> DataStore[BallotId, SubmittedBallot]:
        store: DataStore[BallotId, SubmittedBallot] = DataStore()
        for ballot in ballots:
            store.set(ballot.object_id, ballot)
        return store

    def _tally(self) -> CiphertextTally:
        return CiphertextTally("tally", self.internal_manifest, self.context)

    def _tally_all(
        self, ballots: List[SubmittedBallot], registry: CredentialRegistry
    ) -> Optional[CiphertextTally]:
        return tally_signed_ballots(
            self._store(ballots), self.internal_manifest, self.context, registry
        )

    def test_tally_signed_ballots(self) -> None:
        tally = get_optional(self._tally_all(self.ballots, self.registry))

        self.assertEqual(tally.cast(), NUMBER_OF_BALLOTS)

    def test_tally_signed_ballots_invalid_registry(self) -> None:
        invalid_registry = CredentialRegistry(
            number_of_registrars=1,
            number_of_eligible_voters={self.style_id: NUMBER_OF_BALLOTS - 1},
            credentials_by_style=self.registry.credentials_by_style,
        )

        self.assertIsNone(self._tally_all(self.ballots, invalid_registry))

    def _assert_tallies_exactly(
        self, tally: Optional[CiphertextTally], ballots: List[SignedSubmittedBallot]
    ) -> None:
        expected = get_optional(self._tally_all(ballots, self.registry))
        self.assertEqual(get_optional(tally).cast_ballot_ids, expected.cast_ballot_ids)
        self.assertEqual(get_optional(tally).contests, expected.contests)

    def test_tally_signed_ballots_unregistered_credential(self) -> None:
        unregistered_ballot = self._make_cast_ballot(
            "unregistered", schnorr_keypair_random()
        )

        tally = self._tally_all(self.ballots + [unregistered_ballot], self.registry)

        self._assert_tallies_exactly(tally, self.ballots)

    def test_tally_signed_ballots_invalid_signature(self) -> None:
        ballot = self.ballots[0]
        tampered_ballot = replace(
            ballot,
            signature=replace(
                ballot.signature, response=add_q(ballot.signature.response, ONE_MOD_Q)
            ),
        )

        tally = self._tally_all([tampered_ballot] + self.ballots[1:], self.registry)

        self._assert_tallies_exactly(tally, self.ballots[1:])

    def test_tally_signed_ballots_duplicate_credential(self) -> None:
        second_vote = self._make_cast_ballot("second-vote", self.shares[0])

        tally = self._tally_all(self.ballots + [second_vote], self.registry)

        self._assert_tallies_exactly(tally, self.ballots)

    def test_tally_signed_ballot(self) -> None:
        tally = get_optional(
            tally_signed_ballot(self.ballots[0], self._tally(), self.registry)
        )

        self.assertEqual(tally.cast(), 1)

    def test_tally_signed_ballot_unknown_state(self) -> None:
        ballot = self.ballots[0]
        unknown_state_ballot = submit_signed_ballot(ballot, BallotBoxState.UNKNOWN)

        self.assertIsNone(
            tally_signed_ballot(unknown_state_ballot, self._tally(), self.registry)
        )

    def test_tally_signed_ballot_unregistered_credential(self) -> None:
        unregistered_ballot = self._make_cast_ballot(
            "unregistered", schnorr_keypair_random()
        )
        tally = self._tally()

        self.assertIsNone(
            tally_signed_ballot(unregistered_ballot, tally, self.registry)
        )
        self.assertEqual(len(tally), 0)

    def _unsigned_ballot(
        self, ballot_id: str, state: BallotBoxState
    ) -> SubmittedBallot:
        plaintext_ballot = self.election_factory.get_fake_ballot(
            self.manifest, ballot_id
        )
        encrypted_ballot = get_optional(
            encrypt_ballot(
                plaintext_ballot, self.internal_manifest, self.context, self.seed
            )
        )
        return submit_ballot(encrypted_ballot, state)

    def test_tally_signed_ballots_unsigned_spoiled_ballot(self) -> None:
        spoiled_ballot = self._unsigned_ballot("spoiled", BallotBoxState.SPOILED)

        tally = get_optional(
            self._tally_all(self.ballots + [spoiled_ballot], self.registry)
        )

        self.assertEqual(tally.cast(), NUMBER_OF_BALLOTS)
        self.assertEqual(tally.spoiled_ballot_ids, {spoiled_ballot.object_id})

    def test_tally_signed_ballots_unsigned_cast_ballot(self) -> None:
        unsigned_ballot = self._unsigned_ballot("unsigned", BallotBoxState.CAST)

        tally = self._tally_all(self.ballots + [unsigned_ballot], self.registry)

        self._assert_tallies_exactly(tally, self.ballots)

    def test_tally_signed_ballot_unsigned_spoiled_ballot(self) -> None:
        spoiled_ballot = self._unsigned_ballot("spoiled", BallotBoxState.SPOILED)

        tally = get_optional(
            tally_signed_ballot(spoiled_ballot, self._tally(), self.registry)
        )

        self.assertEqual(tally.spoiled(), 1)

    def test_append_signed_ballot_twice(self) -> None:
        second_vote = self._make_cast_ballot("second-vote", self.shares[0])
        tally = self._tally()

        self.assertTrue(
            tally.append_signed_ballot(self.ballots[0], self.registry, True)
        )
        self.assertFalse(tally.append_signed_ballot(second_vote, self.registry, True))
        self.assertEqual(tally.cast(), 1)

    def test_batch_append_signed_ballots_twice(
        self,
    ) -> None:
        second_vote = self._make_cast_ballot("second-vote", self.shares[0])
        tally = self._tally()

        self.assertTrue(
            tally.batch_append_signed_ballots(
                self._store(self.ballots), self.registry, True
            )
        )
        self.assertTrue(
            tally.batch_append_signed_ballots(
                self._store([second_vote]), self.registry, True
            )
        )
        self._assert_tallies_exactly(tally, self.ballots)

    def test_batch_append_after_append(self) -> None:
        second_vote = self._make_cast_ballot("second-vote", self.shares[0])
        tally = self._tally()

        self.assertTrue(
            tally.append_signed_ballot(self.ballots[0], self.registry, True)
        )
        self.assertTrue(
            tally.batch_append_signed_ballots(
                self._store([second_vote]), self.registry, True
            )
        )
        self._assert_tallies_exactly(tally, self.ballots[:1])

    def test_append_after_batch_append(self) -> None:
        second_vote = self._make_cast_ballot("second-vote", self.shares[0])
        tally = self._tally()

        self.assertTrue(
            tally.batch_append_signed_ballots(
                self._store(self.ballots), self.registry, True
            )
        )
        self.assertFalse(tally.append_signed_ballot(second_vote, self.registry, True))
        self.assertEqual(tally.cast(), NUMBER_OF_BALLOTS)

    def test_append_invalid_ballot_keeps_credential(self) -> None:
        ballot = self.ballots[0]
        invalid_ballot = replace(
            ballot, manifest_hash=add_q(ballot.manifest_hash, ONE_MOD_Q)
        )
        tally = self._tally()

        self.assertFalse(
            tally.append_signed_ballot(invalid_ballot, self.registry, True)
        )
        self.assertTrue(tally.append_signed_ballot(ballot, self.registry, True))
        self.assertEqual(tally.cast(), 1)

    def test_batch_append_invalid_ballot_keeps_credential(self) -> None:
        ballot = self.ballots[0]
        invalid_ballot = replace(
            ballot,
            object_id="invalid",
            manifest_hash=add_q(ballot.manifest_hash, ONE_MOD_Q),
        )

        tally = self._tally_all([invalid_ballot, ballot], self.registry)

        self._assert_tallies_exactly(tally, [ballot])

    def test_batch_append_skips_invalid_ballot(self) -> None:
        valid_ballot = self._unsigned_ballot("valid", BallotBoxState.CAST)
        invalid_ballot = self._unsigned_ballot("invalid", BallotBoxState.CAST)
        invalid_ballot = replace(
            invalid_ballot, crypto_hash=add_q(invalid_ballot.crypto_hash, ONE_MOD_Q)
        )
        tally = self._tally()
        expected = self._tally()

        self.assertTrue(
            tally.batch_append(
                [("valid", valid_ballot), ("invalid", invalid_ballot)], True
            )
        )
        _ = expected.batch_append([("valid", valid_ballot)], True)

        self.assertEqual(tally.cast_ballot_ids, {"valid"})
        self.assertEqual(tally.cast(), 1)
        self.assertEqual(tally.contests, expected.contests)
