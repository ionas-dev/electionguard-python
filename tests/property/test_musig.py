from electionguard.group import g_pow_p, mult_q, pow_p
from electionguard.hash import hash_elems_agg
from electionguard.musig import aggregate_key_pair, aggregate_public_key
from electionguard.schnorr_signature import schnorr_keypair_random
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
