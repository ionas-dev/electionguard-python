from typing import Optional

from electionguard.credential_registry import make_credential_registry
from electionguard.electoral_roll import ElectoralRoll
from electionguard.group import ElementModQ, g_pow_p, rand_q
from electionguard.manifest import ContactInformation
from electionguard.registrar import Registrar
from electionguard.schnorr_signature import schnorr_keypair_random
from electionguard.voter import Voter
from tests.base_test_case import BaseTestCase

STYLE_1 = "ballot-style-1"
STYLE_2 = "ballot-style-2"


def _voter(voter_id: str, ballot_style_id: str = STYLE_1) -> Voter:
    return Voter(
        object_id=voter_id,
        name=f"Voter {voter_id}",
        contact_information=ContactInformation(),
        ballot_style_id=ballot_style_id,
    )


def _roll(*voters: Voter) -> ElectoralRoll:
    return ElectoralRoll(object_id="roll-1", voters=list(voters))


def _registrar(
    registrar_id: str, sequence_order: int, roll: ElectoralRoll, nonce: Optional[ElementModQ] = None
) -> Registrar:
    return Registrar(registrar_id, sequence_order, roll, seed=nonce)


class TestRegistrar(BaseTestCase):
    """Registrar credential generation tests"""

    def test_generate_credentials_creates_one_keypair_per_voter(self) -> None:
        roll = _roll(_voter("voter-1"), _voter("voter-2"), _voter("voter-3"))
        registrar = _registrar("registrar-1", 0, roll)

        registrar.generate_credentials()

        self.assertEqual(set(registrar.credentials.keys()), {"voter-1", "voter-2", "voter-3"})

    def test_generated_credentials_are_valid_schnorr_keypairs(self) -> None:
        roll = _roll(_voter("voter-1"), _voter("voter-2"))
        registrar = _registrar("registrar-1", 0, roll)

        registrar.generate_credentials()

        for credential in registrar.credentials.values():
            self.assertEqual(credential.public_key, g_pow_p(credential.secret_key))

    def test_generated_credentials_are_unique_per_voter(self) -> None:
        roll = _roll(_voter("voter-1"), _voter("voter-2"), _voter("voter-3"))
        registrar = _registrar("registrar-1", 0, roll)

        registrar.generate_credentials()

        secret_keys = [credential.secret_key for credential in registrar.credentials.values()]
        self.assertEqual(len(secret_keys), len(set(secret_keys)))

    def test_generate_credentials_is_deterministic_given_fixed_nonce(self) -> None:
        roll = _roll(_voter("voter-1"), _voter("voter-2"))
        seed = rand_q()

        first_registrar = _registrar("registrar-1", 0, roll, nonce=seed)
        second_registrar = _registrar("registrar-1", 0, roll, nonce=seed)

        first_registrar.generate_credentials()
        second_registrar.generate_credentials()

        self.assertEqual(
            {vid: c.secret_key for vid, c in first_registrar.credentials.items()},
            {vid: c.secret_key for vid, c in second_registrar.credentials.items()},
        )

    def test_publish_public_crendentials(self) -> None:
        roll = _roll(_voter("voter-1"), _voter("voter-2"))
        registrar = _registrar("registrar-1", 0, roll)
        registrar.generate_credentials()

        published = registrar.publish_public_credentials()

        self.assertEqual(
            published,
            [registrar.credentials["voter-1"].public_key, registrar.credentials["voter-2"].public_key],
        )

    def test_send_credential_to_voter_returns_credential_for_known_voter(self) -> None:
        roll = _roll(_voter("voter-1"))
        registrar = _registrar("registrar-1", 0, roll)
        registrar.generate_credentials()

        credential = registrar.send_credential_to_voter("voter-1")

        self.assertEqual(credential, registrar.credentials["voter-1"])

    def test_send_credential_to_voter_raises_for_unknown_voter(self) -> None:
        roll = _roll(_voter("voter-1"))
        registrar = _registrar("registrar-1", 0, roll)
        registrar.generate_credentials()

        with self.assertRaises(ValueError):
            registrar.send_credential_to_voter("unknown-voter")

    def test_publish_public_credentials_for_style_filters_and_preserves_order(self) -> None:
        roll = _roll(
            _voter("voter-1", STYLE_1),
            _voter("voter-2", STYLE_2),
            _voter("voter-3", STYLE_1),
        )
        registrar = _registrar("registrar-1", 0, roll)
        registrar.generate_credentials()

        published = registrar.publish_public_credentials_for_style(STYLE_1)

        self.assertEqual(
            published,
            [
                registrar.credentials["voter-1"].public_key,
                registrar.credentials["voter-3"].public_key,
            ],
        )

    def test_verify_registration_true_when_correctly_published(self) -> None:
        roll = _roll(_voter("voter-1"), _voter("voter-2"))
        registrar_a = _registrar("registrar-a", 0, roll)
        registrar_b = _registrar("registrar-b", 1, roll)
        registrar_a.generate_credentials()
        registrar_b.generate_credentials()

        registry = make_credential_registry(
            number_of_registrars=2,
            number_of_eligible_voters={STYLE_1: 2},
            shares_by_style={
                STYLE_1: [
                    registrar_a.publish_public_credentials_for_style(STYLE_1),
                    registrar_b.publish_public_credentials_for_style(STYLE_1),
                ]
            },
        )

        self.assertTrue(registrar_a.verify_registration(registry))
        self.assertTrue(registrar_b.verify_registration(registry))

    def test_verify_registration_false_when_registrys_ballot_style_is_unknown(self) -> None:
        roll = _roll(_voter("voter-1"), _voter("voter-2"))
        registrar_a = _registrar("registrar-a", 0, roll)
        registrar_a.generate_credentials()

        registry = make_credential_registry(
            number_of_registrars=1,
            number_of_eligible_voters={STYLE_2: 0},
            shares_by_style={STYLE_2: [[]]},
        )

        self.assertFalse(registrar_a.verify_registration(registry))

    def test_verify_registration_false_when_own_share_was_overwritten(self) -> None:
        roll = _roll(_voter("voter-1"), _voter("voter-2"))
        registrar_a = _registrar("registrar-a", 0, roll)
        registrar_b = _registrar("registrar-b", 1, roll)
        registrar_a.generate_credentials()
        registrar_b.generate_credentials()

        tampered_shares = [schnorr_keypair_random().public_key for _ in range(2)]
        registry = make_credential_registry(
            number_of_registrars=2,
            number_of_eligible_voters={STYLE_1: 2},
            shares_by_style={
                STYLE_1: [
                    tampered_shares,
                    registrar_b.publish_public_credentials_for_style(STYLE_1),
                ]
            },
        )

        self.assertFalse(registrar_a.verify_registration(registry))

    def test_verify_registration_true_across_multiple_ballot_styles(self) -> None:
        roll = _roll(
            _voter("voter-1", STYLE_1),
            _voter("voter-2", STYLE_2),
            _voter("voter-3", STYLE_1),
        )
        registrar_a = _registrar("registrar-a", 0, roll)
        registrar_b = _registrar("registrar-b", 1, roll)
        registrar_a.generate_credentials()
        registrar_b.generate_credentials()

        registry = make_credential_registry(
            number_of_registrars=2,
            number_of_eligible_voters={STYLE_1: 2, STYLE_2: 1},
            shares_by_style={
                style: [
                    registrar_a.publish_public_credentials_for_style(style),
                    registrar_b.publish_public_credentials_for_style(style),
                ]
                for style in (STYLE_1, STYLE_2)
            },
        )

        self.assertTrue(registrar_a.verify_registration(registry))
        self.assertTrue(registrar_b.verify_registration(registry))

    def test_verify_registration_false_when_only_one_of_several_styles_is_wrong(self) -> None:
        roll = _roll(
            _voter("voter-1", STYLE_1),
            _voter("voter-2", STYLE_2),
        )
        registrar_a = _registrar("registrar-a", 0, roll)
        registrar_b = _registrar("registrar-b", 1, roll)
        registrar_a.generate_credentials()
        registrar_b.generate_credentials()

        tampered_shares = [schnorr_keypair_random().public_key]
        registry = make_credential_registry(
            number_of_registrars=2,
            number_of_eligible_voters={STYLE_1: 1, STYLE_2: 1},
            shares_by_style={
                STYLE_1: [
                    registrar_a.publish_public_credentials_for_style(STYLE_1),
                    registrar_b.publish_public_credentials_for_style(STYLE_1),
                ],
                STYLE_2: [
                    tampered_shares,
                    registrar_b.publish_public_credentials_for_style(STYLE_2),
                ],
            },
        )

        self.assertFalse(registrar_a.verify_registration(registry))
