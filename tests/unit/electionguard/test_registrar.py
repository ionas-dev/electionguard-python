from typing import Optional

from electionguard.eligibility_roll import EligibilityRoll
from electionguard.group import ElementModQ, g_pow_p, rand_q
from electionguard.manifest import ContactInformation
from electionguard.registrar import Registrar
from electionguard.voter import Voter
from tests.base_test_case import BaseTestCase


def _voter(voter_id: str) -> Voter:
    return Voter(
        object_id=voter_id,
        name=f"Voter {voter_id}",
        contact_information=ContactInformation(),
        ballot_style_id="ballot-style-1",
    )


def _roll(*voter_ids: str) -> EligibilityRoll:
    return EligibilityRoll(
        object_id="roll-1", voters=[_voter(voter_id) for voter_id in voter_ids]
    )


def _registrar(roll: EligibilityRoll, nonce: Optional[ElementModQ] = None) -> Registrar:
    return Registrar("registrar-1", 0, roll, nonce=nonce)


class TestRegistrar(BaseTestCase):
    """Registrar credential generation tests"""

    def test_generate_credentials_creates_one_keypair_per_voter(self) -> None:
        roll = _roll("voter-1", "voter-2", "voter-3")
        registrar = _registrar(roll)

        registrar.generate_credentials()

        self.assertEqual(set(registrar.credentials.keys()), {"voter-1", "voter-2", "voter-3"})

    def test_generated_credentials_are_valid_schnorr_keypairs(self) -> None:
        roll = _roll("voter-1", "voter-2")
        registrar = _registrar(roll)

        registrar.generate_credentials()

        for credential in registrar.credentials.values():
            self.assertEqual(credential.public_key, g_pow_p(credential.secret_key))

    def test_generated_credentials_are_unique_per_voter(self) -> None:
        roll = _roll("voter-1", "voter-2", "voter-3")
        registrar = _registrar(roll)

        registrar.generate_credentials()

        secret_keys = [credential.secret_key for credential in registrar.credentials.values()]
        self.assertEqual(len(secret_keys), len(set(secret_keys)))

    def test_generate_credentials_is_deterministic_given_fixed_nonce(self) -> None:
        roll = _roll("voter-1", "voter-2")
        seed = rand_q()

        first_registrar = _registrar(EligibilityRoll(object_id="roll-1", voters=roll.voters), nonce=seed)
        second_registrar = _registrar(EligibilityRoll(object_id="roll-1", voters=roll.voters), nonce=seed)

        first_registrar.generate_credentials()
        second_registrar.generate_credentials()

        self.assertEqual(
            {vid: c.secret_key for vid, c in first_registrar.credentials.items()},
            {vid: c.secret_key for vid, c in second_registrar.credentials.items()},
        )

    def test_publish_public_crendentials(self) -> None:
        roll = _roll("voter-1", "voter-2")
        registrar = _registrar(roll)
        registrar.generate_credentials()

        published = registrar.publish_public_crendentials()

        self.assertEqual(
            published,
            [registrar.credentials["voter-1"].public_key, registrar.credentials["voter-2"].public_key],
        )

    def test_send_credential_to_voter_returns_credential_for_known_voter(self) -> None:
        roll = _roll("voter-1")
        registrar = _registrar(roll)
        registrar.generate_credentials()

        credential = registrar.send_credential_to_voter("voter-1")

        self.assertEqual(credential, registrar.credentials["voter-1"])

    def test_send_credential_to_voter_raises_for_unknown_voter(self) -> None:
        roll = _roll("voter-1")
        registrar = _registrar(roll)
        registrar.generate_credentials()

        with self.assertRaises(ValueError):
            registrar.send_credential_to_voter("unknown-voter")
