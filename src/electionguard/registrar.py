from dataclasses import dataclass
from typing import Optional

from electionguard.credential_registry import CredentialRegistry
from electionguard.eligibility_roll import EligibilityRoll
from electionguard.group import ElementModQ, g_pow_p, rand_q
from electionguard.nonces import Nonces
from electionguard.schnorr_signature import SchnorrKeyPair, SchnorrPublicKey
from electionguard.type import BallotStyleId, RegistrarId


@dataclass
class Registrar:

    registrar_id: RegistrarId
    """The unique identifier of the registrar."""

    sequence_order: int
    """
    Unique sequence order of the registrars indicating the order
    in which the key shares per voter should be assembled
    """

    eligibility_roll: EligibilityRoll
    """The eligibility roll containing the list of eligible voters."""

    credentials: dict[str, SchnorrKeyPair]
    """A dictionary mapping voter ids to their corresponding Schnorr key pairs (credentials)."""

    nonce: ElementModQ
    """
    An nonce used in the generation of credentials.
    It will be combined with the voter id to create a unique secret key for each voter.
    """

    def __init__(
        self,
        registrar_id: RegistrarId,
        sequence_order: int,
        eligibility_roll: EligibilityRoll,
        nonce: Optional[ElementModQ] = None,
    ) -> None:
        self.registrar_id = registrar_id
        self.sequence_order = sequence_order
        self.eligibility_roll = eligibility_roll
        self.nonce = nonce if nonce is not None else rand_q()
        self.credentials = {}

    def publish_public_crendentials(self) -> list[SchnorrPublicKey]:
        """Publishes the public credentials for each voter in the eligibility roll."""

        return [self.credentials[voter.object_id].public_key for voter in self.eligibility_roll.voters]

    def publish_public_credentials_for_style(self, ballot_style_id: BallotStyleId) -> list[SchnorrPublicKey]:
        """
        Publishes this registrar's public credential shares for every voter
        eligible for `ballot_style_id`, in eligibility roll order. Used to
        register credentials with a CredentialRegistry, which keeps entries
        partitioned per ballot style.
        """
        return [
            self.credentials[voter.object_id].public_key
            for voter in self.eligibility_roll.voters
            if voter.ballot_style_id == ballot_style_id
        ]

    def verify_registration(self, registry: CredentialRegistry) -> bool:
        """
        Verify that every one of this registrar's own shares was correctly
        and completely published in `registry`, for every ballot style this
        registrar's voters belong to.
        """
        ballot_style_ids = {voter.ballot_style_id for voter in self.eligibility_roll.voters}

        for ballot_style_id in ballot_style_ids:
            own_shares = self.publish_public_credentials_for_style(ballot_style_id)
            try:
                entries = registry.entries(ballot_style_id)
            except ValueError:
                return False

            if len(own_shares) != len(entries):
                return False

            if any(
                entry.shares[self.sequence_order] != own_share
                for entry, own_share in zip(entries, own_shares)
            ):
                return False

        return True

    def send_credential_to_voter(self, id: str) -> SchnorrKeyPair:
        """""Sends the credential to a voter based on their ID."""

        if id not in self.credentials:
            raise ValueError("Invalid voter ID")

        return self.credentials[id]

    def generate_credentials(self) -> None:
        """Generates a Schnorr key pair for each voter in the eligibility roll."""

        nonces = Nonces(self.nonce, f"registrar-{self.registrar_id}-credentials")

        for (i, voter) in enumerate(self.eligibility_roll.voters):
            nonce = nonces.get_with_headers(i, voter.object_id)
            credential = self._generate_credential(nonce)
            self.credentials[voter.object_id] = credential

    def _generate_credential(self, nonce: Optional[ElementModQ] = None) -> SchnorrKeyPair:
        """Generates one Schnorr key pair"""

        secret_key = nonce if nonce is not None else rand_q()
        public_key = g_pow_p(secret_key)

        keypair = SchnorrKeyPair(secret_key, public_key)
        return keypair
