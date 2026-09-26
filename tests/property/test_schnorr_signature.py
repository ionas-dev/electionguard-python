from hypothesis import assume, given

from electionguard.group import (
    ONE_MOD_Q,
    ElementModQ,
    add_q,
    g_pow_p,
)
from electionguard.hash import hash_elems, hash_elems_sig
from electionguard.schnorr_signature import (
    SchnorrKeyPair,
    SchnorrSignature,
    schnorr_sign,
)
from electionguard_tools.strategies.group import (
    elements_mod_q,
    elements_mod_q_no_zero,
)
from electionguard_tools.strategies.schnorr import schnorr_keypairs
from tests.base_test_case import BaseTestCase


class TestSchnorrSignature(BaseTestCase):
    """Schnorr signature tests"""

    @given(schnorr_keypairs(), elements_mod_q(), elements_mod_q())
    def test_schnorr_signature_verifies(
        self, keypair: SchnorrKeyPair, message: ElementModQ, nonce: ElementModQ
    ) -> None:
        signature = schnorr_sign(nonce, message, keypair)

        self.assertTrue(signature.verify(keypair.public_key, message))

    @given(schnorr_keypairs(), elements_mod_q(), elements_mod_q())
    def test_verify_fails_on_tampered_message(
        self, keypair: SchnorrKeyPair, message: ElementModQ, nonce: ElementModQ
    ) -> None:
        signature = schnorr_sign(nonce, message, keypair)

        tampered_message = add_q(message, ONE_MOD_Q)
        self.assertFalse(signature.verify(keypair.public_key, tampered_message))

    @given(schnorr_keypairs(), schnorr_keypairs(), elements_mod_q(), elements_mod_q())
    def test_verify_fails_on_wrong_public_key(
        self,
        keypair: SchnorrKeyPair,
        other: SchnorrKeyPair,
        message: ElementModQ,
        nonce: ElementModQ,
    ) -> None:
        _ = assume(other.public_key != keypair.public_key)
        signature = schnorr_sign(nonce, message, keypair)  # pylint: disable=unreachable

        self.assertFalse(signature.verify(other.public_key, message))

    @given(
        schnorr_keypairs(), elements_mod_q(), elements_mod_q(), elements_mod_q_no_zero()
    )
    def test_verify_fails_on_tampered_challenge(
        self,
        keypair: SchnorrKeyPair,
        message: ElementModQ,
        nonce: ElementModQ,
        delta: ElementModQ,
    ) -> None:
        signature = schnorr_sign(nonce, message, keypair)

        tampered_challenge = add_q(signature.challenge, delta)
        tampered_signature = SchnorrSignature(tampered_challenge, signature.response)
        self.assertFalse(tampered_signature.verify(keypair.public_key, message))

    @given(
        schnorr_keypairs(), elements_mod_q(), elements_mod_q(), elements_mod_q_no_zero()
    )
    def test_verify_fails_on_tampered_response(
        self,
        keypair: SchnorrKeyPair,
        message: ElementModQ,
        nonce: ElementModQ,
        delta: ElementModQ,
    ) -> None:
        signature = schnorr_sign(nonce, message, keypair)

        tampered_response = add_q(signature.response, delta)
        tampered_signature = SchnorrSignature(signature.challenge, tampered_response)
        self.assertFalse(tampered_signature.verify(keypair.public_key, message))

    @given(schnorr_keypairs(), elements_mod_q(), elements_mod_q())
    def test_challenge_uses_signature_domain(
        self, keypair: SchnorrKeyPair, message: ElementModQ, nonce: ElementModQ
    ) -> None:
        signature = schnorr_sign(nonce, message, keypair)

        self.assertEqual(
            signature.challenge,
            hash_elems_sig(keypair.public_key, g_pow_p(nonce), message),
        )
        self.assertNotEqual(
            signature.challenge,
            hash_elems(keypair.public_key, g_pow_p(nonce), message),
        )
