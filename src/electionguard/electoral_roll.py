from dataclasses import dataclass
from typing import List

from electionguard.voter import Voter


@dataclass(unsafe_hash=True)
class ElectoralRoll:
    """The complete electoral roll."""

    object_id: str
    """Unique identifier of the electoral roll."""

    voters: List[Voter]
    """List of all electoral roll entries, each corresponding to one eligible voter."""
