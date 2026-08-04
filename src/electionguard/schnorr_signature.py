from dataclasses import dataclass
from typing import Optional

from electionguard.group import (
    TWO_MOD_Q,
    ElementModP,
    ElementModQ,
    add_q,
    div_p,
    g_pow_p,
    mult_p,
    mult_q,
    pow_p,
    rand_range_q,
)
from electionguard.hash import CryptoHashableAll, hash_elems, hash_elems_agg
from electionguard.logs import log_error
from electionguard_tools.factories.election_factory import get_optional

SchnorrSecretKey = ElementModQ
SchnorrPublicKey = ElementModP
SchnorrMessage = CryptoHashableAll

@dataclass
class SchnorrKeyPair:
    """A tuple of a Schnorr secret key and public key."""

    secret_key: SchnorrSecretKey
    public_key: SchnorrPublicKey

@dataclass
class SchnorrSignature:
    """A Schnorr signature."""

    challenge: ElementModQ
    response: ElementModQ

    def verify(self, public_key: SchnorrPublicKey, message: SchnorrMessage) -> bool:
        g_pow_response = g_pow_p(self.response)
        pubkey_pow_challenge = pow_p(public_key, self.challenge)
        recovered_commitment = div_p(g_pow_response, pubkey_pow_challenge)

        computed_challenge = hash_elems(recovered_commitment, message)
        return computed_challenge == self.challenge


def schnorr_sign(nonce: ElementModQ, message: SchnorrMessage, secret_key: SchnorrSecretKey) -> Optional[SchnorrSignature]:
    """Sign a message using the Schnorr signature scheme."""
    commitment = g_pow_p(nonce)
    challenge = hash_elems(commitment, message)
    response = add_q(nonce, mult_q(secret_key, challenge))

    return SchnorrSignature(challenge, response)


def public_key_aggregate(public_keys: list[SchnorrPublicKey]) -> SchnorrPublicKey:
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

def schnorr_keypair_from_secret(a: SchnorrSecretKey) -> Optional[SchnorrKeyPair]:
    """
    Given an Schnorr secret key (typically, a random number in [2,Q)), returns
    an Schnorr keypair, consisting of the given secret key a and public key g^a.
    """
    secret_key_int = a
    if secret_key_int < 2:
        log_error("ElGamal secret key needs to be in [2,Q).")
        return None

    return SchnorrKeyPair(a, g_pow_p(a))


def schnorr_keypair_random() -> SchnorrKeyPair:
    """
    Create a random schnorr keypair

    :return: random schnorr key pair
    """
    return get_optional(schnorr_keypair_from_secret(rand_range_q(TWO_MOD_Q)))
