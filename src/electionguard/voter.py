from dataclasses import dataclass

from electionguard.manifest import ContactInformation
from electionguard.type import BallotStyleId, VoterId


@dataclass(unsafe_hash=True)
class Voter:
    """A single entry in the eligibility roll, corresponding to one eligible voter."""

    object_id: VoterId
    """Unique identifier of the eligibility roll entry."""

    name: str
    """Name of the voter."""

    contact_information: ContactInformation
    """Contact details of the voter. At least one of address_line, email, or phone should be provided."""

    ballot_style_id: BallotStyleId
    """Reference to the ballot style that determines which contests this voter is eligible to vote in."""
