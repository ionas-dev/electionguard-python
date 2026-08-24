from dataclasses import dataclass, field
from typing import Generator, Optional

from electionguard.group import ElementModQ, add_q, g_pow_p, rand_q
from electionguard.schnorr_signature import SchnorrKeyPair
from electionguard.type import RegistrarId

EligibilityRoll = list[str]

@dataclass
class Registrar:
    eligibility_roll: EligibilityRoll
    credentials: dict[int, SchnorrKeyPair]
    nonce: Optional[ElementModQ] = None

    def __init__(self, eligibility_roll: EligibilityRoll, nonce: Optional[ElementModQ] = None) -> None:
        self.eligibility_roll = eligibility_roll
        self.nonce = nonce
        self.credentials = {}

    def publish_public_crendentials(self) -> list[SchnorrKeyPair]:
        """Publishes the public credentials for each voter in the eligibility roll."""
        return [self.credentials[id] for id in range(len(self.eligibility_roll))]

    def send_credential_to_voter(self, id: int) -> SchnorrKeyPair:
        """""Sends the credential to a voter based on their ID."""
        if id < 0 or id >= len(self.eligibility_roll):
            raise ValueError("Invalid voter ID")

        return self.credentials[id]


    def generate_credentials(self) -> list[SchnorrKeyPair]:
        """Generates a Schnorr key pair for each voter in the eligibility roll."""

        credentials = []

        for id in range(len(self.eligibility_roll)):
            credential = self.generate_credentials_for_voter(id)
            credentials.append(credential)
        return credentials


    def generate_credentials_for_voter(self, id: int) -> SchnorrKeyPair:
        """Generates a Schnorr key pair for a given voter ID."""
        if id < 0 or id >= len(self.eligibility_roll):
            raise ValueError("Invalid voter ID")

        # TODO: Nonce seqqeunce wie bei encrypt
        secret_key = add_q(self.nonce, id) if self.nonce is not None else rand_q()
        public_key = g_pow_p(secret_key)

        keypair = SchnorrKeyPair(secret_key, public_key)

        self.credentials[id] = keypair
        return keypair
