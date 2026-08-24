from electionguard.group import ONE_MOD_Q, TWO_MOD_Q, add_q, g_pow_p
from electionguard.schnorr_signature import (
    SchnorrSignature,
    schnorr_keypair_random,
    schnorr_sign,
)
from tests.base_test_case import BaseTestCase


class TestSchnorrSignature(BaseTestCase):
    """Schnorr signature tests"""

    def test_schnorr_signature_verifies(self) -> None:
        keypair = schnorr_keypair_random()
        message = TWO_MOD_Q
        nonce = ONE_MOD_Q

        signature = schnorr_sign(nonce, message, keypair)

        self.assertTrue(signature.verify(keypair.public_key, message))

    def test_verify_fails_on_tampered_message(self) -> None:
        keypair = schnorr_keypair_random()
        message = TWO_MOD_Q
        nonce = ONE_MOD_Q

        signature = schnorr_sign(nonce, message, keypair)

        tampered_message = add_q(message, ONE_MOD_Q)
        self.assertFalse(signature.verify(keypair.public_key, tampered_message))

    def test_verify_fails_on_wrong_public_key(self) -> None:
        keypair = schnorr_keypair_random()
        message = TWO_MOD_Q
        nonce = ONE_MOD_Q

        signature = schnorr_sign(nonce, message, keypair)

        other_public_key = g_pow_p(add_q(keypair.secret_key, ONE_MOD_Q))
        self.assertFalse(signature.verify(other_public_key, message))

    def test_verify_fails_on_tampered_challenge(self) -> None:
        keypair = schnorr_keypair_random()
        message = TWO_MOD_Q
        nonce = ONE_MOD_Q

        signature = schnorr_sign(nonce, message, keypair)

        tampered_challenge = add_q(signature.challenge, ONE_MOD_Q)
        tampered_signature = SchnorrSignature(tampered_challenge, signature.response)
        self.assertFalse(tampered_signature.verify(keypair.public_key, message))

    def test_verify_fails_on_tampered_response(self) -> None:
        keypair = schnorr_keypair_random()
        message = TWO_MOD_Q
        nonce = ONE_MOD_Q

        signature = schnorr_sign(nonce, message, keypair)

        tampered_response = add_q(signature.response, ONE_MOD_Q)
        tampered_signature = SchnorrSignature(signature.challenge, tampered_response)
        self.assertFalse(tampered_signature.verify(keypair.public_key, message))
