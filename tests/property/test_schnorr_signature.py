from electionguard.group import ONE_MOD_Q, TWO_MOD_Q
from electionguard.schnorr_signature import (
    schnorr_keypair_random,
    schnorr_sign,
)
from electionguard.utils import get_optional
from tests.base_test_case import BaseTestCase


class TestSchnorrSignature(BaseTestCase):
    """Schnorr signature tests"""

    def test_schnorr_signature(self) -> None:
        keypair = schnorr_keypair_random()

        ballot_hash = TWO_MOD_Q
        nonce = ONE_MOD_Q

        signature = get_optional(schnorr_sign(nonce, ballot_hash, keypair.secret_key))

        self.assertTrue(signature.verify(keypair.public_key, ballot_hash))
