from electionguard.credential_registry import (
    CredentialRegistry,
    make_credential_registry,
)
from electionguard.musig import aggregate_public_key
from electionguard.schnorr_signature import SchnorrPublicKey, schnorr_keypair_random
from tests.base_test_case import BaseTestCase

STYLE_A = "ballot-style-a"
STYLE_B = "ballot-style-b"


def _public_keys(count: int) -> list[SchnorrPublicKey]:
    return [schnorr_keypair_random().public_key for _ in range(count)]


class TestCredentialRegistry(BaseTestCase):
    """CredentialRegistry construction, aggregation and verification tests"""

    def test_make_registry_unknown_style(self) -> None:
        with self.assertRaises(ValueError):
            _ = make_credential_registry(
                number_of_registrars=1,
                number_of_eligible_voters={STYLE_A: 3},
                shares_by_style={"unknown-style": [_public_keys(3)]},
            )

    def test_make_registry_wrong_share_count(self) -> None:
        with self.assertRaises(ValueError):
            _ = make_credential_registry(
                number_of_registrars=1,
                number_of_eligible_voters={STYLE_A: 3},
                shares_by_style={STYLE_A: [_public_keys(2)]},
            )

    def test_entries_ordered_by_registrar(
        self,
    ) -> None:
        registrar_0_shares = _public_keys(3)
        registrar_1_shares = _public_keys(3)

        registry = make_credential_registry(
            number_of_registrars=2,
            number_of_eligible_voters={STYLE_A: 3},
            shares_by_style={STYLE_A: [registrar_0_shares, registrar_1_shares]},
        )

        entries = registry.entries(STYLE_A)
        self.assertEqual(len(entries), 3)
        for i, entry in enumerate(entries):
            self.assertEqual(
                entry.shares, [registrar_0_shares[i], registrar_1_shares[i]]
            )
            self.assertEqual(
                entry.aggregated_public_key,
                aggregate_public_key([registrar_0_shares[i], registrar_1_shares[i]]),
            )

    def test_is_registered(self) -> None:
        registrar_0_shares = _public_keys(2)
        registrar_1_shares = _public_keys(2)
        registry = make_credential_registry(
            number_of_registrars=2,
            number_of_eligible_voters={STYLE_A: 2},
            shares_by_style={STYLE_A: [registrar_0_shares, registrar_1_shares]},
        )

        registered_key = aggregate_public_key(
            [registrar_0_shares[0], registrar_1_shares[0]]
        )

        self.assertTrue(registry.is_registered(STYLE_A, registered_key))

    def test_is_registered_unregistered_key(self) -> None:
        registry = make_credential_registry(
            number_of_registrars=2,
            number_of_eligible_voters={STYLE_A: 2},
            shares_by_style={STYLE_A: [_public_keys(2), _public_keys(2)]},
        )

        unregistered_key = schnorr_keypair_random().public_key

        self.assertFalse(registry.is_registered(STYLE_A, unregistered_key))

    def test_is_registered_other_style(
        self,
    ) -> None:
        style_a_shares_0 = _public_keys(1)
        style_a_shares_1 = _public_keys(1)
        registry = make_credential_registry(
            number_of_registrars=2,
            number_of_eligible_voters={STYLE_A: 1, STYLE_B: 1},
            shares_by_style={
                STYLE_A: [style_a_shares_0, style_a_shares_1],
                STYLE_B: [_public_keys(1), _public_keys(1)],
            },
        )

        style_a_key = aggregate_public_key([style_a_shares_0[0], style_a_shares_1[0]])

        self.assertFalse(registry.is_registered(STYLE_B, style_a_key))

    def test_verify(self) -> None:
        registry = make_credential_registry(
            number_of_registrars=2,
            number_of_eligible_voters={STYLE_A: 2, STYLE_B: 1},
            shares_by_style={
                STYLE_A: [_public_keys(2), _public_keys(2)],
                STYLE_B: [_public_keys(1), _public_keys(1)],
            },
        )

        self.assertTrue(registry.verify())

    def test_verify_wrong_share_count(self) -> None:
        registry = make_credential_registry(
            number_of_registrars=2,
            number_of_eligible_voters={STYLE_A: 1},
            shares_by_style={STYLE_A: [_public_keys(1), _public_keys(1)]},
        )
        _ = registry.entries(STYLE_A)[0].shares.pop()

        self.assertFalse(registry.verify())

    def test_verify_duplicate_credentials(self) -> None:
        shared_share = _public_keys(1)
        registry = make_credential_registry(
            number_of_registrars=1,
            number_of_eligible_voters={STYLE_A: 2},
            shares_by_style={STYLE_A: [shared_share * 2]},
        )

        self.assertFalse(registry.verify())

    def test_verify_wrong_aggregate(self) -> None:
        registry = make_credential_registry(
            number_of_registrars=1,
            number_of_eligible_voters={STYLE_A: 1},
            shares_by_style={STYLE_A: [_public_keys(1)]},
        )
        registry.entries(STYLE_A)[
            0
        ].aggregated_public_key = schnorr_keypair_random().public_key

        self.assertFalse(registry.verify())

    def test_verify_too_many_credentials(self) -> None:
        built = make_credential_registry(
            number_of_registrars=1,
            number_of_eligible_voters={STYLE_A: 2},
            shares_by_style={STYLE_A: [_public_keys(2)]},
        )
        registry = CredentialRegistry(
            number_of_registrars=1,
            number_of_eligible_voters={STYLE_A: 1},
            credentials_by_style=built.credentials_by_style,
        )

        self.assertFalse(registry.verify())

    def test_is_registered_unknown_style(self) -> None:
        registry = make_credential_registry(
            number_of_registrars=1,
            number_of_eligible_voters={STYLE_A: 1},
            shares_by_style={STYLE_A: [_public_keys(1)]},
        )
        registered_key = registry.entries(STYLE_A)[0].aggregated_public_key

        self.assertFalse(registry.is_registered("unknown-style", registered_key))

    def test_verify_replaced_share(self) -> None:
        registry = make_credential_registry(
            number_of_registrars=2,
            number_of_eligible_voters={STYLE_A: 1},
            shares_by_style={STYLE_A: [_public_keys(1), _public_keys(1)]},
        )
        registry.entries(STYLE_A)[0].shares[1] = schnorr_keypair_random().public_key

        self.assertFalse(registry.verify())

    def test_verify_fewer_credentials_than_voters(self) -> None:
        built = make_credential_registry(
            number_of_registrars=1,
            number_of_eligible_voters={STYLE_A: 1},
            shares_by_style={STYLE_A: [_public_keys(1)]},
        )
        registry = CredentialRegistry(
            number_of_registrars=1,
            number_of_eligible_voters={STYLE_A: 2},
            credentials_by_style=built.credentials_by_style,
        )

        self.assertTrue(registry.verify())
