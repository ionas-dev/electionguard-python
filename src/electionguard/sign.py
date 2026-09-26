from typing import Optional

from electionguard.group import ElementModQ, rand_q
from electionguard.schnorr_signature import (
    SchnorrKeyPair,
    schnorr_sign,
)

from .ballot import CiphertextBallot, SignedBallot, make_ciphertext_signed_ballot


def sign(
    ballot: CiphertextBallot,
    key_pair: SchnorrKeyPair,
    nonce: Optional[ElementModQ] = None,
) -> SignedBallot:
    message = ballot.crypto_hash
    nonce = nonce if nonce is not None else rand_q()
    signature = schnorr_sign(nonce, message, key_pair)

    return make_ciphertext_signed_ballot(ballot, signature, key_pair.public_key)
