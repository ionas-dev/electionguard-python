from typing import List

from hypothesis import given
from hypothesis.strategies import lists

from electionguard.group import (
    ONE_MOD_P,
    ElementModP,
    ElementModQ,
    mult_p,
    pow_p,
)
from electionguard.hash import hash_elems_agg
from electionguard.musig import aggregate_key_pair, aggregate_public_key
from electionguard.schnorr_signature import SchnorrKeyPair, schnorr_sign
from electionguard_tools.strategies.group import elements_mod_q
from electionguard_tools.strategies.schnorr import schnorr_keypairs
from tests.base_test_case import BaseTestCase

MAX_SHARES = 5


def _public_keys(key_pairs: List[SchnorrKeyPair]) -> List[ElementModP]:
    return [key_pair.public_key for key_pair in key_pairs]


class TestMusig(BaseTestCase):
    """MuSig key aggregation tests"""

    def test_aggregate_public_key_raises_on_empty_list(self) -> None:
        with self.assertRaises(ValueError):
            _ = aggregate_public_key([])

    @given(lists(schnorr_keypairs(), min_size=1, max_size=MAX_SHARES))
    def test_aggregate_public_key_matches_key_pair(
        self, key_pairs: List[SchnorrKeyPair]
    ) -> None:
        self.assertEqual(
            aggregate_public_key(_public_keys(key_pairs)),
            aggregate_key_pair(key_pairs).public_key,
        )

    @given(lists(schnorr_keypairs(), min_size=1, max_size=MAX_SHARES))
    def test_aggregate_public_key(self, key_pairs: List[SchnorrKeyPair]) -> None:
        """pc~ = prod pcs_i^(a_i) with a_i = H_agg(pc, pcs_i) and pc = (pcs_1, ..., pcs_m)"""
        public_keys = _public_keys(key_pairs)

        expected = ONE_MOD_P
        for public_key in public_keys:
            expected = mult_p(
                expected, pow_p(public_key, hash_elems_agg(public_keys, public_key))
            )

        self.assertEqual(aggregate_public_key(public_keys), expected)

    @given(
        lists(schnorr_keypairs(), min_size=1, max_size=MAX_SHARES),
        elements_mod_q(),
        elements_mod_q(),
    )
    def test_sign_with_aggregate_key(
        self, key_pairs: List[SchnorrKeyPair], message: ElementModQ, nonce: ElementModQ
    ) -> None:
        aggregated_public_key = aggregate_public_key(_public_keys(key_pairs))

        signature = schnorr_sign(nonce, message, aggregate_key_pair(key_pairs))

        self.assertTrue(signature.verify(aggregated_public_key, message))
