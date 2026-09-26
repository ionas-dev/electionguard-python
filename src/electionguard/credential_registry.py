from dataclasses import dataclass

from electionguard.musig import aggregate_public_key
from electionguard.schnorr_signature import SchnorrPublicKey
from electionguard.type import BallotStyleId


@dataclass
class Credential:
    """The public key shares of a voter, ordered by registrar sequence_order, and their aggregate."""

    shares: list[SchnorrPublicKey]
    aggregated_public_key: SchnorrPublicKey


@dataclass
class CredentialRegistry:
    """The published credentials of the voters per ballot style."""

    number_of_registrars: int
    number_of_eligible_voters: dict[BallotStyleId, int]
    credentials_by_style: dict[BallotStyleId, list[Credential]]

    def entries(self, ballot_style_id: BallotStyleId) -> list[Credential]:
        """The registered credentials for `ballot_style_id`."""
        if ballot_style_id not in self.credentials_by_style:
            raise ValueError(f"unknown ballot style: {ballot_style_id}")
        return self.credentials_by_style[ballot_style_id]

    def is_registered(
        self, ballot_style_id: BallotStyleId, public_key: SchnorrPublicKey
    ) -> bool:
        """Is this aggregated public credential registered for this ballot style?"""
        return any(
            entry.aggregated_public_key == public_key
            for entry in self.credentials_by_style.get(ballot_style_id, [])
        )

    def verify(self) -> bool:
        """
        Verify that the registry does not contain more credentials than there are eligible voters,
        the keys are valid aggregates, there is one share per registrar for each credential
        and no duplicates.
        """

        for ballot_style_id, credentials in self.credentials_by_style.items():
            if len(credentials) > self.number_of_eligible_voters.get(
                ballot_style_id, 0
            ):
                return False

            aggregated_keys = [
                credential.aggregated_public_key for credential in credentials
            ]
            if len(aggregated_keys) != len(set(aggregated_keys)):
                return False

            if any(
                len(credential.shares) != self.number_of_registrars
                for credential in credentials
            ):
                return False

            if any(
                aggregate_public_key(credential.shares)
                != credential.aggregated_public_key
                for credential in credentials
            ):
                return False

        return True


def make_credential_registry(
    number_of_registrars: int,
    number_of_eligible_voters: dict[BallotStyleId, int],
    shares_by_style: dict[BallotStyleId, list[list[SchnorrPublicKey]]],
) -> CredentialRegistry:
    """
    Build the credential registry from the shares of every registrar, where `shares_by_style`
    contains the shares of each registrar per ballot style, ordered by sequence_order.
    """
    unknown_styles = set(shares_by_style) - set(number_of_eligible_voters)
    if unknown_styles:
        raise ValueError(f"unknown ballot style(s): {sorted(unknown_styles)}")

    credentials_by_style: dict[BallotStyleId, list[Credential]] = {}

    for ballot_style_id, expected in number_of_eligible_voters.items():
        ordered_shares = shares_by_style.get(ballot_style_id)

        if ordered_shares is None:
            raise ValueError(f"missing shares for ballot style: {ballot_style_id}")
        if len(ordered_shares) != number_of_registrars:
            raise ValueError(
                f"expected {number_of_registrars} registrars for ballot style "
                f"{ballot_style_id}, got {len(ordered_shares)}"
            )
        if any(len(shares) != expected for shares in ordered_shares):
            raise ValueError(
                f"expected {expected} shares per registrar for ballot style {ballot_style_id}"
            )

        credentials_by_style[ballot_style_id] = [
            Credential(list(shares), aggregate_public_key(list(shares)))
            for shares in zip(*ordered_shares)
        ]

    return CredentialRegistry(
        number_of_registrars, number_of_eligible_voters, credentials_by_style
    )
