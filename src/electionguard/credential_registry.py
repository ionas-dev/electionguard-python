from dataclasses import dataclass, field

from electionguard.musig import aggregate_public_key
from electionguard.schnorr_signature import SchnorrPublicKey
from electionguard.type import BallotStyleId


@dataclass
class CredentialEntry:
    """One registered credential: every registrar's public key share that went
    into it (ordered by registrar sequence_order), and the resulting aggregated
    public credential."""

    shares: list[SchnorrPublicKey]
    aggregated_public_key: SchnorrPublicKey


@dataclass
class CredentialRegistry:
    """
    Publicly published registry of registered credentials, kept separate per
    ballot style, built incrementally as each registrar publishes its own
    ordered (by voter) list of public key shares via `register_credentials`.
    """

    number_of_registrars: int
    number_of_eligible_voters: dict[BallotStyleId, int]
    _shares_by_style: dict[BallotStyleId, dict[int, list[SchnorrPublicKey]]] = field(
        default_factory=dict
    )
    _entries_by_style: dict[BallotStyleId, list[CredentialEntry]] = field(
        default_factory=dict, init=False, repr=False
    )

    def register_credentials(
        self, ballot_style_id: BallotStyleId, shares: list[SchnorrPublicKey], position: int
    ) -> None:
        """Register one registrar's ordered (by voter, roll order) public key
        shares for `ballot_style_id` at `position` (that registrar's
        sequence_order)."""
        if ballot_style_id not in self.number_of_eligible_voters:
            raise ValueError(f"unknown ballot style: {ballot_style_id}")
        if not 0 <= position < self.number_of_registrars:
            raise ValueError(
                f"position must be in [0, {self.number_of_registrars}), got {position}"
            )
        expected = self.number_of_eligible_voters[ballot_style_id]
        if len(shares) != expected:
            raise ValueError(
                f"expected {expected} shares for ballot style {ballot_style_id}, got {len(shares)}"
            )

        self._shares_by_style.setdefault(ballot_style_id, {})[position] = shares
        self._entries_by_style.pop(ballot_style_id, None)

    def entries(self, ballot_style_id: BallotStyleId) -> list[CredentialEntry]:
        """
        Aggregate every voter's shares across all registrars into a
        CredentialEntry, once every registrar has registered for this ballot
        style. Cached until register_credentials is called again for it.
        """
        if ballot_style_id not in self.number_of_eligible_voters:
            raise ValueError(f"unknown ballot style: {ballot_style_id}")
        if ballot_style_id in self._entries_by_style:
            return self._entries_by_style[ballot_style_id]

        positions = self._shares_by_style.get(ballot_style_id, {})
        if len(positions) != self.number_of_registrars:
            raise ValueError(
                f"not all registrars have registered shares for ballot style {ballot_style_id} yet"
            )

        ordered = [positions[i] for i in range(self.number_of_registrars)]
        built = [
            CredentialEntry(list(shares), aggregate_public_key(list(shares)))
            for shares in zip(*ordered)
        ]
        self._entries_by_style[ballot_style_id] = built
        return built

    def is_registered(self, ballot_style_id: BallotStyleId, public_key: SchnorrPublicKey) -> bool:
        """Is this aggregated public credential registered for this ballot style?"""
        return any(
            entry.aggregated_public_key == public_key for entry in self.entries(ballot_style_id)
        )
