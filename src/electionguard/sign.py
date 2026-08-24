
from typing import Optional

from electionguard.group import rand_q
from electionguard.schnorr_signature import (
    SchnorrKeyPair,
    schnorr_sign,
)

from .ballot import CiphertextBallot, SignedBallot, make_ciphertext_signed_ballot


def sign(ballot: CiphertextBallot, key_pair: SchnorrKeyPair) -> Optional[SignedBallot]:
    message = ballot.crypto_hash
    nonce = rand_q()

    signature = schnorr_sign(nonce, message, key_pair)
    if signature is None:
        return None

    return make_ciphertext_signed_ballot(ballot, signature, key_pair.public_key)
