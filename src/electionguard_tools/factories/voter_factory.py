import os
from typing import List

from electionguard.serialize import from_list_in_file
from electionguard.voter import Voter

_data = os.path.realpath(os.path.join(__file__, "../../../../data"))


class VoterFactory:
    """Factory to create voters"""

    simple_voters_filename = "voters_simple.json"

    def get_simple_voters_from_file(self) -> List[Voter]:
        return self._get_voters_from_file(self.simple_voters_filename)

    @staticmethod
    def _get_voters_from_file(filename: str) -> List[Voter]:
        return from_list_in_file(Voter, os.path.join(_data, filename))
