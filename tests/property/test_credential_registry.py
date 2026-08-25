from electionguard.credential_registry import CredentialRegistry
from electionguard.musig import aggregate_public_key
from electionguard.schnorr_signature import SchnorrPublicKey, schnorr_keypair_random
from tests.base_test_case import BaseTestCase

STYLE_A = "ballot-style-a"
STYLE_B = "ballot-style-b"


def _public_keys(count: int) -> list[SchnorrPublicKey]:
    return [schnorr_keypair_random().public_key for _ in range(count)]


def _registry(number_of_registrars: int = 2, **voters_by_style: int) -> CredentialRegistry:
    voters_by_style = voters_by_style or {STYLE_A: 3}
    return CredentialRegistry(
        number_of_registrars=number_of_registrars,
        number_of_eligible_voters=voters_by_style,
    )


class TestCredentialRegistry(BaseTestCase):
    """CredentialRegistry registration and aggregation tests"""

    def test_register_credentials_rejects_unknown_ballot_style(self) -> None:
        registry = _registry()

        with self.assertRaises(ValueError):
            registry.register_credentials("unknown-style", _public_keys(3), 0)

    def test_register_credentials_rejects_negative_position(self) -> None:
        registry = _registry()

        with self.assertRaises(ValueError):
            registry.register_credentials(STYLE_A, _public_keys(3), -1)

    def test_register_credentials_rejects_position_at_or_above_count(self) -> None:
        registry = _registry()

        with self.assertRaises(ValueError):
            registry.register_credentials(STYLE_A, _public_keys(3), 2)

    def test_register_credentials_rejects_wrong_number_of_shares(self) -> None:
        registry = _registry(**{STYLE_A: 3})

        with self.assertRaises(ValueError):
            registry.register_credentials(STYLE_A, _public_keys(2), 0)

    def test_entries_raises_before_all_registrars_have_registered(self) -> None:
        registry = _registry(**{STYLE_A: 3})
        registry.register_credentials(STYLE_A, _public_keys(3), 0)

        with self.assertRaises(ValueError):
            registry.entries(STYLE_A)

    def test_entries_raises_for_unknown_ballot_style(self) -> None:
        registry = _registry(**{STYLE_A: 3})

        with self.assertRaises(ValueError):
            registry.entries("unknown-style")

    def test_entries_has_one_entry_per_voter_with_shares_ordered_by_position(
        self,
    ) -> None:
        registrar_0_shares = _public_keys(3)
        registrar_1_shares = _public_keys(3)
        registry = _registry(**{STYLE_A: 3})

        registry.register_credentials(STYLE_A, registrar_1_shares, 1)
        registry.register_credentials(STYLE_A, registrar_0_shares, 0)

        entries = registry.entries(STYLE_A)
        self.assertEqual(len(entries), 3)
        for i, entry in enumerate(entries):
            self.assertEqual(entry.shares, [registrar_0_shares[i], registrar_1_shares[i]])
            self.assertEqual(
                entry.aggregated_public_key,
                aggregate_public_key([registrar_0_shares[i], registrar_1_shares[i]]),
            )

    def test_entries_are_kept_separate_per_ballot_style(self) -> None:
        registry = _registry(**{STYLE_A: 2, STYLE_B: 1})
        style_a_registrar_0 = _public_keys(2)
        style_a_registrar_1 = _public_keys(2)
        style_b_registrar_0 = _public_keys(1)
        style_b_registrar_1 = _public_keys(1)

        registry.register_credentials(STYLE_A, style_a_registrar_0, 0)
        registry.register_credentials(STYLE_A, style_a_registrar_1, 1)
        registry.register_credentials(STYLE_B, style_b_registrar_0, 0)
        registry.register_credentials(STYLE_B, style_b_registrar_1, 1)

        style_a_entries = registry.entries(STYLE_A)
        style_b_entries = registry.entries(STYLE_B)

        self.assertEqual(
            [entry.shares for entry in style_a_entries],
            [[style_a_registrar_0[i], style_a_registrar_1[i]] for i in range(2)],
        )
        self.assertEqual(
            [entry.shares for entry in style_b_entries],
            [[style_b_registrar_0[0], style_b_registrar_1[0]]],
        )

    def test_is_registered_true_for_an_aggregated_entry(self) -> None:
        registrar_0_shares = _public_keys(2)
        registrar_1_shares = _public_keys(2)
        registry = _registry(**{STYLE_A: 2})
        registry.register_credentials(STYLE_A, registrar_0_shares, 0)
        registry.register_credentials(STYLE_A, registrar_1_shares, 1)

        registered_key = aggregate_public_key([registrar_0_shares[0], registrar_1_shares[0]])

        self.assertTrue(registry.is_registered(STYLE_A, registered_key))

    def test_is_registered_false_for_an_unregistered_key(self) -> None:
        registry = _registry(**{STYLE_A: 2})
        registry.register_credentials(STYLE_A, _public_keys(2), 0)
        registry.register_credentials(STYLE_A, _public_keys(2), 1)

        unregistered_key = schnorr_keypair_random().public_key

        self.assertFalse(registry.is_registered(STYLE_A, unregistered_key))

    def test_is_registered_false_for_a_key_registered_under_a_different_style(
        self,
    ) -> None:
        registry = _registry(**{STYLE_A: 1, STYLE_B: 1})
        style_a_shares_0 = _public_keys(1)
        style_a_shares_1 = _public_keys(1)
        registry.register_credentials(STYLE_A, style_a_shares_0, 0)
        registry.register_credentials(STYLE_A, style_a_shares_1, 1)
        registry.register_credentials(STYLE_B, _public_keys(1), 0)
        registry.register_credentials(STYLE_B, _public_keys(1), 1)

        style_a_key = aggregate_public_key([style_a_shares_0[0], style_a_shares_1[0]])

        self.assertFalse(registry.is_registered(STYLE_B, style_a_key))

    def test_entries_cache_is_invalidated_by_re_registering(self) -> None:
        registry = _registry(number_of_registrars=1, **{STYLE_A: 2})
        registry.register_credentials(STYLE_A, _public_keys(2), 0)
        first_entries = registry.entries(STYLE_A)

        new_shares = _public_keys(2)
        registry.register_credentials(STYLE_A, new_shares, 0)
        second_entries = registry.entries(STYLE_A)

        self.assertNotEqual(first_entries, second_entries)
        self.assertEqual([entry.shares[0] for entry in second_entries], new_shares)
