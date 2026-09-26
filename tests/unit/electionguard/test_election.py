from electionguard.constants import get_generator, get_large_prime, get_small_prime
from electionguard.election import make_ciphertext_election_context
from electionguard.group import ElementModP, ElementModQ, TWO_MOD_P, TWO_MOD_Q
from electionguard.hash import hash_elems
from tests.base_test_case import BaseTestCase


class TestElection(BaseTestCase):
    """Election context tests"""

    def test_base_hash_ignores_registrars(self) -> None:
        unextended_base_hash = hash_elems(
            ElementModP(get_large_prime(), False),
            ElementModQ(get_small_prime(), False),
            ElementModP(get_generator(), False),
            5,
            3,
            TWO_MOD_Q,
        )

        for number_of_registrars in (0, 2):
            with self.subTest(number_of_registrars=number_of_registrars):
                context = make_ciphertext_election_context(
                    5, 3, TWO_MOD_P, TWO_MOD_Q, TWO_MOD_Q, number_of_registrars
                )
                self.assertEqual(context.crypto_base_hash, unextended_base_hash)
                self.assertEqual(context.number_of_registrars, number_of_registrars)
