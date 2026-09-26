from electionguard.group import ONE_MOD_P, ZERO_MOD_Q, add_q, mult_p, mult_q, pow_p
from electionguard.hash import hash_elems_agg
from electionguard.schnorr_signature import (
    SchnorrKeyPair,
    SchnorrPublicKey,
)


def aggregate_public_key(public_keys: list[SchnorrPublicKey]) -> SchnorrPublicKey:
    """Aggregate Schnorr public keys using the MuSig key aggregation scheme."""
    if len(public_keys) == 0:
        raise ValueError("At least one public key is required for aggregation.")

    aggregated_public_key = ONE_MOD_P
    for public_key in public_keys:
        coefficient = hash_elems_agg(public_keys, public_key)
        public_key_pow_coefficient = pow_p(public_key, coefficient)
        aggregated_public_key = mult_p(
            aggregated_public_key, public_key_pow_coefficient
        )

    return aggregated_public_key


def aggregate_key_pair(key_pairs: list[SchnorrKeyPair]) -> SchnorrKeyPair:
    public_keys = [key_pair.public_key for key_pair in key_pairs]

    aggregated_public_key = ONE_MOD_P
    aggregated_secret_key = ZERO_MOD_Q
    for key_pair in key_pairs:
        coefficient = hash_elems_agg(public_keys, key_pair.public_key)
        public_key_pow_coefficient = pow_p(key_pair.public_key, coefficient)
        secret_key_mult_coefficient = mult_q(key_pair.secret_key, coefficient)
        aggregated_public_key = mult_p(
            aggregated_public_key, public_key_pow_coefficient
        )

        aggregated_secret_key = add_q(
            aggregated_secret_key, secret_key_mult_coefficient
        )

    return SchnorrKeyPair(aggregated_secret_key, aggregated_public_key)
