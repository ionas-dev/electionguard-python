from typing import Optional

from electionguard.credential_registry import make_credential_registry
from electionguard.electoral_roll import ElectoralRoll
from electionguard.group import ONE_MOD_Q, ElementModQ, add_q, rand_q
from electionguard.manifest import ContactInformation
from electionguard.pedersen import pedersen_commit
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
    registrar_id: str,
    sequence_order: int,
    roll: ElectoralRoll,
    nonce: Optional[ElementModQ] = None,
) -> Registrar:
    return Registrar(registrar_id, sequence_order, roll, seed=nonce)


class TestRegistrar(BaseTestCase):
    """Registrar credential generation tests"""

    def test_generate_credentials(self) -> None:
        roll = _roll(_voter("voter-1"), _voter("voter-2"), _voter("voter-3"))
        registrar = _registrar("registrar-1", 0, roll)

        registrar.generate_credentials()

        self.assertEqual(
            set(registrar.credentials.keys()), {"voter-1", "voter-2", "voter-3"}
        )

    def test_generated_credentials_are_unique_per_voter(self) -> None:
        roll = _roll(_voter("voter-1"), _voter("voter-2"), _voter("voter-3"))
        registrar = _registrar("registrar-1", 0, roll)

        registrar.generate_credentials()

        secret_keys = [
            credential.secret_key for credential in registrar.credentials.values()
        ]
        self.assertEqual(len(secret_keys), len(set(secret_keys)))

    def test_generate_credentials_is_deterministic(self) -> None:
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

    def test_publish_public_credentials(self) -> None:
        roll = _roll(_voter("voter-1"), _voter("voter-2"))
        registrar = _registrar("registrar-1", 0, roll)
        registrar.generate_credentials()

        published = registrar.publish_public_credentials()

        self.assertEqual(
            published,
            [
                registrar.credentials["voter-1"].public_key,
                registrar.credentials["voter-2"].public_key,
            ],
        )

    def test_publish_public_credentials_for_style(self) -> None:
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

    def test_verify_registration(self) -> None:
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

    def test_verify_registration_unknown_style(self) -> None:
        roll = _roll(_voter("voter-1"), _voter("voter-2"))
        registrar_a = _registrar("registrar-a", 0, roll)
        registrar_a.generate_credentials()

        registry = make_credential_registry(
            number_of_registrars=1,
            number_of_eligible_voters={STYLE_2: 0},
            shares_by_style={STYLE_2: [[]]},
        )

        self.assertFalse(registrar_a.verify_registration(registry))

    def test_verify_registration_overwritten_share(self) -> None:
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

    def test_verify_registration_multiple_styles(self) -> None:
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

    def test_verify_registration_one_style_wrong(self) -> None:
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

    def test_same_seed_different_registrars(self) -> None:
        roll = _roll(_voter("voter-1"))
        seed = rand_q()
        registrar_a = _registrar("registrar-a", 0, roll, nonce=seed)
        registrar_b = _registrar("registrar-b", 1, roll, nonce=seed)

        registrar_a.generate_credentials()
        registrar_b.generate_credentials()

        self.assertNotEqual(
            registrar_a.credentials["voter-1"], registrar_b.credentials["voter-1"]
        )

    def test_verify_registration_missing_share(self) -> None:
        roll = _roll(_voter("voter-1"), _voter("voter-2"))
        registrar_a = _registrar("registrar-a", 0, roll)
        registrar_a.generate_credentials()

        registry = make_credential_registry(
            number_of_registrars=1,
            number_of_eligible_voters={STYLE_1: 1},
            shares_by_style={
                STYLE_1: [registrar_a.publish_public_credentials_for_style(STYLE_1)[:1]]
            },
        )

        self.assertFalse(registrar_a.verify_registration(registry))

    def test_verify_electoral_roll_commitment(self) -> None:
        roll = _roll(_voter("voter-1"), _voter("voter-2"))
        registrar = _registrar("registrar-1", 0, roll)
        commitment, opening = pedersen_commit(*roll.voters)

        self.assertTrue(registrar.verify_electoral_roll_commitment(commitment, opening))

    def test_verify_electoral_roll_commitment_other_roll(self) -> None:
        committed_roll = _roll(_voter("voter-1"), _voter("voter-2"))
        received_roll = _roll(_voter("voter-1"), _voter("voter-2"), _voter("voter-3"))
        registrar = _registrar("registrar-1", 0, received_roll)
        commitment, opening = pedersen_commit(*committed_roll.voters)

        self.assertFalse(
            registrar.verify_electoral_roll_commitment(commitment, opening)
        )

    def test_verify_electoral_roll_commitment_changed_style(self) -> None:
        committed_roll = _roll(_voter("voter-1"), _voter("voter-2"))
        received_roll = _roll(_voter("voter-1"), _voter("voter-2", STYLE_2))
        registrar = _registrar("registrar-1", 0, received_roll)
        commitment, opening = pedersen_commit(*committed_roll.voters)

        self.assertFalse(
            registrar.verify_electoral_roll_commitment(commitment, opening)
        )

    def test_verify_electoral_roll_commitment_wrong_opening(self) -> None:
        roll = _roll(_voter("voter-1"), _voter("voter-2"))
        registrar = _registrar("registrar-1", 0, roll)
        commitment, opening = pedersen_commit(*roll.voters)

        self.assertFalse(
            registrar.verify_electoral_roll_commitment(
                commitment, add_q(opening, ONE_MOD_Q)
            )
        )
