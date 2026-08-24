from dataclasses import replace
from typing import override

import electionguard_tools.factories.election_factory as ElectionFactory
from electionguard.elgamal import elgamal_keypair_from_secret
from electionguard.encrypt import encrypt_ballot
from electionguard.group import ONE_MOD_Q, TWO_MOD_Q, add_q, g_pow_p
from electionguard.schnorr_signature import schnorr_keypair_random
from electionguard.sign import sign
from electionguard.utils import get_optional
from tests.base_test_case import BaseTestCase


class TestSign(BaseTestCase):
    """Ballot signature creation tests"""

    @override
    def setUp(self) -> None:
        election_factory = ElectionFactory.ElectionFactory()
        seed = election_factory.get_encryption_device().get_hash()
        keypair = get_optional(elgamal_keypair_from_secret(TWO_MOD_Q))
        manifest = election_factory.get_fake_manifest()
        internal_manifest, context = election_factory.get_fake_ciphertext_election(
            manifest, keypair.public_key
        )
        plaintext_ballot = election_factory.get_fake_ballot(manifest)

        self.ballot = get_optional(
            encrypt_ballot(plaintext_ballot, internal_manifest, context, seed)
        )
        self.credential = schnorr_keypair_random()

    def test_sign_produces_a_valid_signature(self) -> None:
        signed_ballot = sign(self.ballot, self.credential)

        self.assertTrue(signed_ballot.verify_signature())

    def test_sign_preserves_ballot_content(self) -> None:
        signed_ballot = sign(self.ballot, self.credential)

        self.assertEqual(signed_ballot.object_id, self.ballot.object_id)
        self.assertEqual(signed_ballot.style_id, self.ballot.style_id)
        self.assertEqual(signed_ballot.manifest_hash, self.ballot.manifest_hash)
        self.assertEqual(signed_ballot.contests, self.ballot.contests)
        self.assertEqual(signed_ballot.crypto_hash, self.ballot.crypto_hash)

    def test_sign_attaches_the_signer_public_credential(self) -> None:
        signed_ballot = get_optional(sign(self.ballot, self.credential))

        self.assertEqual(signed_ballot.public_credential, self.credential.public_key)

    def test_signing_twice_yields_two_different_valid_signatures(self) -> None:
        first_signed = sign(self.ballot, self.credential)
        second_signed = sign(self.ballot, self.credential)

        self.assertNotEqual(first_signed.signature, second_signed.signature)
        self.assertTrue(first_signed.verify_signature())
        self.assertTrue(second_signed.verify_signature())

    def test_verify_signature_fails_with_tampered_public_credential(self) -> None:
        signed_ballot = sign(self.ballot, self.credential)

        other_public_key = g_pow_p(add_q(self.credential.secret_key, ONE_MOD_Q))
        tampered_ballot = replace(signed_ballot, public_credential=other_public_key)

        self.assertFalse(tampered_ballot.verify_signature())

    def test_verify_signature_fails_with_tampered_crypto_hash(self) -> None:
        signed_ballot = sign(self.ballot, self.credential)

        tampered_ballot = replace(
            signed_ballot, crypto_hash=add_q(signed_ballot.crypto_hash, ONE_MOD_Q)
        )

        self.assertFalse(tampered_ballot.verify_signature())
