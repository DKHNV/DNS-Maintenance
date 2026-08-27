from __future__ import annotations

import copy
import unittest

from dns_maintenance.runtime_candidate_exact_promotion import (
    EXACT_PROMOTION_MODE,
    EXACT_PROMOTION_STATES,
    EXACT_PROMOTION_VERSION,
    evaluate_exact_promotion,
    exact_promotion_settings,
)


class RuntimeCandidateExactPromotionTests(
    unittest.TestCase
):
    def candidate(self) -> dict:
        return {
            "candidate_id": "candidate-1",
            "hostname": "video.example.com",
            "suffix": "example.com",
            "state": "observed",
            "feed_present": True,
            "current_presence": True,
            "current_routing_status": "active",
            "observation_count": 5,
            "presence_cycles": 100,
            "active_cycles": 50,
            "reactivation_count": 1,
            "seen_dates": [
                "2026-08-24",
                "2026-08-25",
                "2026-08-26",
            ],
        }

    def ready_maturity(
        self,
    ) -> dict:
        return {
            "version": 1,
            "mode": "shadow",
            "state": "ready",
            "reason": (
                "candidate_maturity_met"
            ),
            "candidate_since": (
                "2026-08-24T18:00:00Z"
            ),
            "criteria": {
                "enabled": True,
                "min_candidate_age_hours": 24.0,
                "min_additional_seen_days": 1,
                "min_additional_observation_count": 1,
            },
            "baseline": {
                "seen_days": 2,
                "observation_count": 3,
            },
            "evidence": {
                "feed_present": True,
                "candidate_age_hours": 48.0,
                "seen_days": 3,
                "observation_count": 5,
                "additional_seen_days": 1,
                "additional_observation_count": 2,
            },
        }

    def classification(
        self,
        *,
        decision: str = "candidate",
        maturity: dict | None = None,
        exact_dns_present: bool = False,
        policy_excluded: bool = False,
    ) -> dict:
        result = {
            "version": 1,
            "mode": "shadow",
            "classified_at": (
                "2026-08-26T18:00:00Z"
            ),
            "decision": decision,
            "reason": (
                "candidate_retained"
            ),
            "policy_reason": None,
            "evidence": {
                "feed_present": True,
                "current_presence": True,
                "current_routing_status": "active",
                "observation_count": 5,
                "presence_cycles": 100,
                "active_cycles": 50,
                "reactivation_count": 1,
                "seen_days": 3,
                "exact_dns_present": (
                    exact_dns_present
                ),
                "exact_dns_status": None,
                "policy_excluded": (
                    policy_excluded
                ),
                "policy_rule": None,
            },
        }

        if maturity is not None:
            result["maturity"] = maturity

        return result

    def dns_state(self) -> dict:
        return {
            "version": 2,
            "updated_at": (
                "2026-08-26T18:00:00Z"
            ),
            "hosts": {},
        }

    def policy(self) -> dict:
        return {
            "enabled": True,
            "allow": [],
            "exclude": [],
        }

    def enabled_settings(
        self,
    ) -> dict:
        return {
            "enabled": True,
        }

    def test_default_settings_are_disabled(
        self,
    ) -> None:
        self.assertEqual(
            exact_promotion_settings(
                None
            ),
            {
                "enabled": False,
            },
        )

    def test_settings_reject_unknown_keys(
        self,
    ) -> None:
        with self.assertRaises(
            ValueError
        ):
            exact_promotion_settings(
                {
                    "enabled": False,
                    "write_exact_dns": True,
                }
            )

    def test_settings_require_boolean_enabled(
        self,
    ) -> None:
        with self.assertRaises(
            ValueError
        ):
            exact_promotion_settings(
                {
                    "enabled": 1,
                }
            )

    def test_states_are_shadow_only(
        self,
    ) -> None:
        self.assertEqual(
            EXACT_PROMOTION_STATES,
            {
                "hold",
                "eligible",
            },
        )

        self.assertNotIn(
            "promoted_exact",
            EXACT_PROMOTION_STATES,
        )

        self.assertNotIn(
            "pending",
            EXACT_PROMOTION_STATES,
        )

        self.assertNotIn(
            "active",
            EXACT_PROMOTION_STATES,
        )

    def test_ready_candidate_becomes_shadow_eligible(
        self,
    ) -> None:
        result = (
            evaluate_exact_promotion(
                self.candidate(),
                self.classification(
                    maturity=(
                        self.ready_maturity()
                    )
                ),
                self.dns_state(),
                self.policy(),
                settings=(
                    self.enabled_settings()
                ),
            )
        )

        self.assertEqual(
            result["version"],
            EXACT_PROMOTION_VERSION,
        )

        self.assertEqual(
            result["mode"],
            EXACT_PROMOTION_MODE,
        )

        self.assertEqual(
            result["state"],
            "eligible",
        )

        self.assertEqual(
            result["reason"],
            "exact_promotion_eligible",
        )

        self.assertEqual(
            result["candidate_id"],
            "candidate-1",
        )

        self.assertEqual(
            result["hostname"],
            "video.example.com",
        )

        self.assertFalse(
            result["evidence"][
                "exact_dns_present"
            ]
        )

        self.assertFalse(
            result["evidence"][
                "policy_excluded"
            ]
        )

    def test_disabled_setting_holds_ready_candidate(
        self,
    ) -> None:
        result = (
            evaluate_exact_promotion(
                self.candidate(),
                self.classification(
                    maturity=(
                        self.ready_maturity()
                    )
                ),
                self.dns_state(),
                self.policy(),
            )
        )

        self.assertEqual(
            result["state"],
            "hold",
        )

        self.assertEqual(
            result["reason"],
            "exact_promotion_disabled",
        )

    def test_tracking_candidate_is_not_eligible(
        self,
    ) -> None:
        maturity = (
            self.ready_maturity()
        )

        maturity["state"] = (
            "tracking"
        )

        maturity["reason"] = (
            "candidate_maturity_"
            "insufficient_additional_seen_days"
        )

        result = (
            evaluate_exact_promotion(
                self.candidate(),
                self.classification(
                    maturity=maturity
                ),
                self.dns_state(),
                self.policy(),
                settings=(
                    self.enabled_settings()
                ),
            )
        )

        self.assertEqual(
            result["state"],
            "hold",
        )

        self.assertEqual(
            result["reason"],
            "exact_promotion_maturity_not_ready",
        )

    def test_missing_maturity_is_not_eligible(
        self,
    ) -> None:
        result = (
            evaluate_exact_promotion(
                self.candidate(),
                self.classification(),
                self.dns_state(),
                self.policy(),
                settings=(
                    self.enabled_settings()
                ),
            )
        )

        self.assertEqual(
            result["state"],
            "hold",
        )

        self.assertEqual(
            result["reason"],
            "exact_promotion_maturity_missing",
        )

    def test_non_candidate_is_not_eligible(
        self,
    ) -> None:
        result = (
            evaluate_exact_promotion(
                self.candidate(),
                self.classification(
                    decision="observed",
                ),
                self.dns_state(),
                self.policy(),
                settings=(
                    self.enabled_settings()
                ),
            )
        )

        self.assertEqual(
            result["state"],
            "hold",
        )

        self.assertEqual(
            result["reason"],
            "exact_promotion_not_candidate",
        )

    def test_feed_absence_blocks_new_eligibility(
        self,
    ) -> None:
        candidate = self.candidate()

        candidate[
            "feed_present"
        ] = False

        result = (
            evaluate_exact_promotion(
                candidate,
                self.classification(
                    maturity=(
                        self.ready_maturity()
                    )
                ),
                self.dns_state(),
                self.policy(),
                settings=(
                    self.enabled_settings()
                ),
            )
        )

        self.assertEqual(
            result["state"],
            "hold",
        )

        self.assertEqual(
            result["reason"],
            "exact_promotion_feed_absent",
        )

    def test_policy_exclusion_is_rechecked_independently(
        self,
    ) -> None:
        policy = self.policy()

        policy["exclude"] = [
            {
                "id": "exclude-video",
                "match": "exact",
                "value": (
                    "video.example.com"
                ),
                "reason": (
                    "test exclusion"
                ),
            }
        ]

        result = (
            evaluate_exact_promotion(
                self.candidate(),
                self.classification(
                    maturity=(
                        self.ready_maturity()
                    ),
                    policy_excluded=False,
                ),
                self.dns_state(),
                policy,
                settings=(
                    self.enabled_settings()
                ),
            )
        )

        self.assertEqual(
            result["state"],
            "hold",
        )

        self.assertEqual(
            result["reason"],
            "exact_promotion_hostname_policy_excluded",
        )

        self.assertTrue(
            result["evidence"][
                "policy_excluded"
            ]
        )

        self.assertFalse(
            result["evidence"][
                "classification_reported_policy_excluded"
            ]
        )

    def test_exact_dns_presence_is_rechecked_independently(
        self,
    ) -> None:
        dns_state = self.dns_state()

        dns_state["hosts"][
            "video.example.com"
        ] = {
            "hostname": (
                "video.example.com"
            ),
            "status": "pending",
        }

        result = (
            evaluate_exact_promotion(
                self.candidate(),
                self.classification(
                    maturity=(
                        self.ready_maturity()
                    ),
                    exact_dns_present=False,
                ),
                dns_state,
                self.policy(),
                settings=(
                    self.enabled_settings()
                ),
            )
        )

        self.assertEqual(
            result["state"],
            "hold",
        )

        self.assertEqual(
            result["reason"],
            "exact_promotion_exact_dns_existing",
        )

        self.assertTrue(
            result["evidence"][
                "exact_dns_present"
            ]
        )

        self.assertEqual(
            result["evidence"][
                "exact_dns_status"
            ],
            "pending",
        )

        self.assertFalse(
            result["evidence"][
                "classification_reported_exact_dns_present"
            ]
        )

    def test_malformed_maturity_fails_closed(
        self,
    ) -> None:
        maturity = (
            self.ready_maturity()
        )

        maturity["version"] = 999

        with self.assertRaises(
            ValueError
        ):
            evaluate_exact_promotion(
                self.candidate(),
                self.classification(
                    maturity=maturity
                ),
                self.dns_state(),
                self.policy(),
                settings=(
                    self.enabled_settings()
                ),
            )

    def test_unknown_classification_version_fails_closed(
        self,
    ) -> None:
        classification = (
            self.classification(
                maturity=(
                    self.ready_maturity()
                )
            )
        )

        classification[
            "version"
        ] = 999

        with self.assertRaises(
            ValueError
        ):
            evaluate_exact_promotion(
                self.candidate(),
                classification,
                self.dns_state(),
                self.policy(),
                settings=(
                    self.enabled_settings()
                ),
            )

    def test_maturity_on_non_candidate_fails_closed(
        self,
    ) -> None:
        classification = (
            self.classification(
                decision="observed",
                maturity=(
                    self.ready_maturity()
                ),
            )
        )

        with self.assertRaises(
            ValueError
        ):
            evaluate_exact_promotion(
                self.candidate(),
                classification,
                self.dns_state(),
                self.policy(),
                settings=(
                    self.enabled_settings()
                ),
            )

    def test_evaluation_does_not_mutate_inputs(
        self,
    ) -> None:
        candidate = self.candidate()

        classification = (
            self.classification(
                maturity=(
                    self.ready_maturity()
                )
            )
        )

        dns_state = self.dns_state()
        policy = self.policy()

        before = copy.deepcopy(
            (
                candidate,
                classification,
                dns_state,
                policy,
            )
        )

        evaluate_exact_promotion(
            candidate,
            classification,
            dns_state,
            policy,
            settings=(
                self.enabled_settings()
            ),
        )

        self.assertEqual(
            (
                candidate,
                classification,
                dns_state,
                policy,
            ),
            before,
        )


if __name__ == "__main__":
    unittest.main()
