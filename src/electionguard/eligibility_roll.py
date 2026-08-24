from dataclasses import dataclass
from typing import List

from electionguard.voter import Voter


@dataclass(unsafe_hash=True)
class EligibilityRoll:
    """The complete eligibility roll."""

    object_id: str
    """Unique identifier of the eligibility roll."""

    voters: List[Voter]
    """List of all eligibility roll entries, each corresponding to one eligible voter."""
