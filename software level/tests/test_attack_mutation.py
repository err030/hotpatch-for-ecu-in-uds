"""Tests for the deterministic UDS 0x27 -> 0x2E mutation campaign."""

import unittest

from src.hotpatch_uds.attack_mutation import (
    PROFILE_AFTER,
    PROFILE_BEFORE,
    build_uds_2e_mutation_corpus,
    run_uds_2e_mutation_campaign,
    summarize_uds_2e_mutation_outcomes,
)


class Uds2eAttackMutationTests(unittest.TestCase):
    def test_campaign_has_high_pre_hotpatch_success_and_zero_post_hotpatch_success(self) -> None:
        corpus = build_uds_2e_mutation_corpus(count=200)

        before = summarize_uds_2e_mutation_outcomes(
            run_uds_2e_mutation_campaign(corpus, profile=PROFILE_BEFORE)
        )
        after = summarize_uds_2e_mutation_outcomes(
            run_uds_2e_mutation_campaign(corpus, profile=PROFILE_AFTER)
        )

        self.assertGreater(before.attack_success_rate, 0.65)
        self.assertLess(before.attack_success_rate, 0.95)
        self.assertEqual(after.attack_successes, 0)
        self.assertGreater(after.hotpatch_blocked_valid_shapes, 0)

    def test_corpus_is_deterministic(self) -> None:
        self.assertEqual(
            build_uds_2e_mutation_corpus(count=20, seed=1234),
            build_uds_2e_mutation_corpus(count=20, seed=1234),
        )


if __name__ == "__main__":
    unittest.main()
