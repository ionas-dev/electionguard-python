from typing import Callable, TypeVar

from hypothesis.strategies import SearchStrategy, composite

from electionguard.group import ONE_MOD_Q, TWO_MOD_Q
from electionguard.schnorr_signature import SchnorrKeyPair, schnorr_keypair_from_secret
from electionguard.utils import get_optional
from electionguard_tools.strategies.group import elements_mod_q_no_zero

_T = TypeVar("_T")
_DrawType = Callable[[SearchStrategy[_T]], _T]


@composite
def schnorr_keypairs(draw: _DrawType) -> SchnorrKeyPair:
    """
    Generates an arbitrary Schnorr secret/public keypair.

    :param draw: Hidden argument, used by Hypothesis.
    """
    e = draw(elements_mod_q_no_zero())
    return get_optional(schnorr_keypair_from_secret(e if e != ONE_MOD_Q else TWO_MOD_Q))
