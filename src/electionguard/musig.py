from electionguard.group import add_q, mult_p, pow_p
from electionguard.hash import hash_elems_agg
from electionguard.schnorr_signature import (
    SchnorrKeyPair,
    SchnorrPublicKey,
    SchnorrSecretKey,
)


def aggregate_public_key(public_keys: list[SchnorrPublicKey]) -> SchnorrPublicKey:
    """Aggregate Schnorr public keys using the MuSig key aggregation scheme."""
    if public_keys is None or len(public_keys) == 0:
        raise ValueError("At least one public key is required for aggregation.")

    sorted_public_keys = sorted(public_keys)

    aggregated_public_key =  sorted_public_keys[0]
    for public_key in sorted_public_keys[1:]:
        coefficient = hash_elems_agg(sorted_public_keys, public_key)
        public_key_pow_coefficient = pow_p(public_key, coefficient)
        aggregated_public_key = mult_p(aggregated_public_key, public_key_pow_coefficient)

    return aggregated_public_key

def aggregate_key_pair(key_pairs: list[SchnorrKeyPair]) -> SchnorrKeyPair:
    sorted_key_pairs = sorted(key_pairs, key=lambda kp: kp.public_key)

    sorted_public_keys = [kp.public_key for kp in sorted_key_pairs]

    aggregated_public_key = sorted_key_pairs[0].public_key
    aggregated_secret_key = sorted_key_pairs[0].secret_key
    for key_pair in sorted_key_pairs[1:]:
        coefficient = hash_elems_agg(sorted_public_keys, key_pair.public_key)
        public_key_pow_coefficient = pow_p(key_pair.public_key, coefficient)
        aggregated_public_key = mult_p(aggregated_public_key, public_key_pow_coefficient)

        aggregated_secret_key = add_q(aggregated_secret_key, key_pair.secret_key)

    return SchnorrKeyPair(aggregated_secret_key, aggregated_public_key)


