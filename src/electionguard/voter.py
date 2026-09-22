from dataclasses import dataclass

from electionguard.group import ElementModQ
from electionguard.hash import CryptoHashable, hash_elems
from electionguard.manifest import ContactInformation
from electionguard.type import BallotStyleId, VoterId


@dataclass(unsafe_hash=True)
class Voter(CryptoHashable):
    """A single entry in the electoral roll, corresponding to one eligible voter."""

    object_id: VoterId
    """Unique identifier of the electoral roll entry."""

    name: str
    """Name of the voter."""

    contact_information: ContactInformation
    """Contact details of the voter. At least one of address_line, email, or phone should be provided."""

    ballot_style_id: BallotStyleId
    """Reference to the ballot style that determines which contests this voter is eligible to vote in."""

    def crypto_hash(self) -> ElementModQ:
        """
        A hash representation of the object
        """
        return hash_elems(
            self.object_id, self.name, self.contact_information, self.ballot_style_id
        )
