from dataclasses import dataclass
from typing import Optional

from electionguard.group import (
    TWO_MOD_Q,
    ElementModP,
    ElementModQ,
    add_q,
    div_p,
    g_pow_p,
    mult_q,
    pow_p,
    rand_range_q,
)
from electionguard.hash import CryptoHashableAll, hash_elems_sig
from electionguard.logs import log_error
from electionguard.utils import get_optional

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

        computed_challenge = hash_elems_sig(recovered_commitment, message)
        return computed_challenge == self.challenge


def schnorr_sign(nonce: ElementModQ, message: SchnorrMessage, key_pair: SchnorrKeyPair) -> Optional[SchnorrSignature]:
    """Sign a message using the Schnorr signature scheme."""
    commitment = g_pow_p(nonce)
    challenge = hash_elems_sig(key_pair.public_key, commitment, message)
    response = add_q(nonce, mult_q(key_pair.secret_key, challenge))

    return SchnorrSignature(challenge, response)


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
