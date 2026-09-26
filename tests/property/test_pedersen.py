from hypothesis import given

from electionguard.constants import get_generator, get_generator_alt
from electionguard.group import ONE_MOD_Q, ElementModQ, add_q, mult_p, pow_p
from electionguard.hash import hash_elems_com
from electionguard.pedersen import pedersen_commit, pedersen_open
from electionguard_tools.strategies.group import elements_mod_q
from tests.base_test_case import BaseTestCase


class TestPedersen(BaseTestCase):
    """Pedersen commitment tests"""

    @given(elements_mod_q(), elements_mod_q())
    def test_commit(self, message: ElementModQ, opening: ElementModQ) -> None:
        commitment, returned_opening = pedersen_commit(message, opening=opening)

        expected = mult_p(
            pow_p(get_generator(), hash_elems_com(message)),
            pow_p(get_generator_alt(), opening),
        )
        self.assertEqual(commitment, expected)
        self.assertEqual(returned_opening, opening)

    @given(elements_mod_q())
    def test_open(self, message: ElementModQ) -> None:
        commitment, opening = pedersen_commit(message)

        self.assertTrue(pedersen_open(message, commitment=commitment, opening=opening))

    def test_open_other_message(self) -> None:
        commitment, opening = pedersen_commit("message")

        self.assertFalse(
            pedersen_open("other message", commitment=commitment, opening=opening)
        )

    @given(elements_mod_q())
    def test_open_other_opening(self, message: ElementModQ) -> None:
        commitment, opening = pedersen_commit(message)

        other_opening = add_q(opening, ONE_MOD_Q)
        self.assertFalse(
            pedersen_open(message, commitment=commitment, opening=other_opening)
        )

    def test_commit_is_randomized(self) -> None:
        first_commitment, _ = pedersen_commit("message")
        second_commitment, _ = pedersen_commit("message")

        self.assertNotEqual(first_commitment, second_commitment)
