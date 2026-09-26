from typing import Optional, Tuple

from electionguard.constants import get_generator, get_generator_alt
from electionguard.group import ElementModP, ElementModQ, mult_p, pow_p, rand_q
from electionguard.hash import CryptoHashableAll, hash_elems_com

PedersenCommitment = ElementModP
PedersenOpening = ElementModQ


def pedersen_commit(
    *message: CryptoHashableAll, opening: Optional[PedersenOpening] = None
) -> Tuple[PedersenCommitment, PedersenOpening]:
    hash = hash_elems_com(*message)
    opening = opening if opening is not None else rand_q()
    generator = get_generator()
    generator_alt = get_generator_alt()

    message_component = pow_p(generator, hash)
    blinding_component = pow_p(generator_alt, opening)

    commitment = mult_p(message_component, blinding_component)
    return (commitment, opening)


def pedersen_open(
    *message: CryptoHashableAll,
    commitment: PedersenCommitment,
    opening: PedersenOpening,
) -> bool:
    return pedersen_commit(*message, opening=opening) == (commitment, opening)
