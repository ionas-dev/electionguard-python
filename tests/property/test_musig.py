from electionguard.group import (
    ONE_MOD_P,
    ZERO_MOD_Q,
    add_q,
    div_p,
    g_pow_p,
    mult_p,
    mult_q,
    pow_p,
    rand_q,
)
from electionguard.hash import hash_elems_agg
from electionguard.musig import aggregate_key_pair, aggregate_public_key
from electionguard.schnorr_signature import schnorr_keypair_random, schnorr_sign
from tests.base_test_case import BaseTestCase


class TestMusig(BaseTestCase):
    """MuSig key aggregation tests"""

    def test_aggregate_public_key_raises_on_empty_list(self) -> None:
        with self.assertRaises(ValueError):
            aggregate_public_key([])

    def test_aggregate_public_key_matches_aggregate_key_pair_public_key(self) -> None:
        key_pairs = [schnorr_keypair_random() for _ in range(3)]
        public_keys = [key_pair.public_key for key_pair in key_pairs]

        self.assertEqual(
            aggregate_public_key(public_keys),
            aggregate_key_pair(key_pairs).public_key,
        )

    def test_aggregate_key_pair_single_key_pair_applies_its_own_coefficient(self) -> None:
        keypair = schnorr_keypair_random()

        aggregated = aggregate_key_pair([keypair])

        coefficient = hash_elems_agg([keypair.public_key], keypair.public_key)
        self.assertEqual(aggregated.public_key, pow_p(keypair.public_key, coefficient))
        self.assertEqual(aggregated.secret_key, mult_q(keypair.secret_key, coefficient))

    def test_aggregate_key_pair_result_is_a_valid_schnorr_keypair(self) -> None:
        """
        The aggregated secret key must be the discrete log of the aggregated public key -
        i.e. the returned pair must actually be usable like any other SchnorrKeyPair
        (e.g. to sign with the secret key and verify with the public key).
        """
        key_pairs = [schnorr_keypair_random() for _ in range(3)]

        aggregated = aggregate_key_pair(key_pairs)

        self.assertEqual(g_pow_p(aggregated.secret_key), aggregated.public_key)

    def test_aggregate_public_key_applies_one_coefficient_per_share(self) -> None:
        """pc~ = prod pcs_i^(a_i) with a_i = H_agg(pc, pcs_i) and pc = (pcs_1, ..., pcs_m)"""
        public_keys = [schnorr_keypair_random().public_key for _ in range(3)]

        expected = ONE_MOD_P
        for public_key in public_keys:
            expected = mult_p(
                expected, pow_p(public_key, hash_elems_agg(public_keys, public_key))
            )

        self.assertEqual(aggregate_public_key(public_keys), expected)

    def test_aggregate_key_pair_secret_key_is_weighted_sum_of_shares(self) -> None:
        """sc~ = sum scs_i * a_i"""
        key_pairs = [schnorr_keypair_random() for _ in range(3)]
        public_keys = [key_pair.public_key for key_pair in key_pairs]

        expected = ZERO_MOD_Q
        for key_pair in key_pairs:
            expected = add_q(
                expected,
                mult_q(key_pair.secret_key, hash_elems_agg(public_keys, key_pair.public_key)),
            )

        self.assertEqual(aggregate_key_pair(key_pairs).secret_key, expected)

    def test_signature_with_aggregated_key_pair_verifies_under_aggregated_public_key(
        self,
    ) -> None:
        """The holder of all shares signs like an ordinary Schnorr signer."""
        key_pairs = [schnorr_keypair_random() for _ in range(3)]
        aggregated_public_key = aggregate_public_key(
            [key_pair.public_key for key_pair in key_pairs]
        )

        signature = schnorr_sign(rand_q(), "message", aggregate_key_pair(key_pairs))

        self.assertTrue(signature.verify(aggregated_public_key, "message"))

    def test_signature_with_a_missing_share_does_not_verify(self) -> None:
        key_pairs = [schnorr_keypair_random() for _ in range(3)]
        aggregated_public_key = aggregate_public_key(
            [key_pair.public_key for key_pair in key_pairs]
        )

        signature = schnorr_sign(rand_q(), "message", aggregate_key_pair(key_pairs[:-1]))

        self.assertFalse(signature.verify(aggregated_public_key, "message"))

    def test_aggregate_differs_from_plain_product_of_shares(self) -> None:
        """
        The coefficients prevent rogue-key attacks: a share chosen as g^x / pcs_1
        would cancel out the honest share in a plain product, but not in the aggregate.
        """
        honest = schnorr_keypair_random()
        attacker = schnorr_keypair_random()
        rogue_share = div_p(attacker.public_key, honest.public_key)

        self.assertEqual(mult_p(honest.public_key, rogue_share), attacker.public_key)
        self.assertNotEqual(
            aggregate_public_key([honest.public_key, rogue_share]), attacker.public_key
        )

    def test_aggregate_depends_on_the_order_of_shares(self) -> None:
        public_keys = [schnorr_keypair_random().public_key for _ in range(2)]

        self.assertNotEqual(
            aggregate_public_key(public_keys),
            aggregate_public_key(list(reversed(public_keys))),
        )
