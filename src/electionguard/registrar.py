from dataclasses import dataclass
from typing import Optional

from electionguard.eligibility_roll import EligibilityRoll
from electionguard.group import ElementModQ, add_q, g_pow_p, rand_q
from electionguard.schnorr_signature import SchnorrKeyPair


@dataclass
class Registrar:
    eligibility_roll: EligibilityRoll
    """The eligibility roll containing the list of eligible voters."""

    credentials: dict[str, SchnorrKeyPair]
    """A dictionary mapping voter ids to their corresponding Schnorr key pairs (credentials)."""

    nonce: Optional[ElementModQ] = None
    """
    An optional nonce used in the generation of credentials.
    If provided, it will be combined with the voter id to create a unique secret key for each voter.
    """

    def __init__(self, eligibility_roll: EligibilityRoll, nonce: Optional[ElementModQ] = None) -> None:
        self.eligibility_roll = eligibility_roll
        self.nonce = nonce
        self.credentials = {}

    def publish_public_crendentials(self) -> list[SchnorrKeyPair]:
        """Publishes the public credentials for each voter in the eligibility roll."""

        return [self.credentials[voter.object_id] for voter in self.eligibility_roll.voters]

    def send_credential_to_voter(self, id: str) -> SchnorrKeyPair:
        """""Sends the credential to a voter based on their ID."""

        if id in self.credentials:
            raise ValueError("Invalid voter ID")

        return self.credentials[id]

    def generate_credentials(self):
        """Generates a Schnorr key pair for each voter in the eligibility roll."""

        nonce = rand_q()

        for (i, voter) in enumerate(self.eligibility_roll.voters):
            nonce = add_q(nonce, i)
            credential = self.generate_credential(nonce)

            voter_id = voter.object_id
            self.credentials[voter_id] = credential

    def generate_credential(self, nonce: Optional[ElementModQ] = None) -> SchnorrKeyPair:
        """Generates one Schnorr key pair"""

        secret_key = nonce if nonce is not None else rand_q()
        public_key = g_pow_p(secret_key)

        keypair = SchnorrKeyPair(secret_key, public_key)
        return keypair
