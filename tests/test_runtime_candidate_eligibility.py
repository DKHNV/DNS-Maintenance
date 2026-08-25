from __future__ import annotations

import copy
import unittest

from dns_maintenance.runtime_candidate_eligibility import (
    DEFAULT_MIN_OBSERVATION_COUNT,
    DEFAULT_MIN_SEEN_DAYS,
    ELIGIBILITY_DECISIONS,
    ELIGIBILITY_MODE,
    ELIGIBILITY_VERSION,
    candidate_eligibility_settings,
    evaluate_candidate_eligibility,
)


class RuntimeCandidateEligibilityTests(unittest.TestCase):
    def candidate(self) -> dict:
        return {
            "candidate_id": "candidate-1",
            "hostname": "video.example.com",
            "suffix": "example.com",
            "state": "observed",
            "feed_present": True,
            "current_presence": True,
            "current_routing_status": "active",
            "observation_count": 2,
            "presence_cycles": 50,
            "active_cycles": 25,
            "reactivation_count": 3,
            "seen_dates": [
                "2026-08-24",
                "2026-08-25",
            ],
        }

    def enabled_settings(self) -> dict:
        return {
            "enabled": True,
            "min_seen_days": 2,
            "min_observation_count": 2,
        }

    def test_default_settings_are_disabled_and_conservative(
        self,
    ) -> None:
        settings = candidate_eligibility_settings(None)

        self.assertFalse(settings["enabled"])
        self.assertEqual(
            settings["min_seen_days"],
            DEFAULT_MIN_SEEN_DAYS,
        )
        self.assertEqual(
            settings["min_observation_count"],
            DEFAULT_MIN_OBSERVATION_COUNT,
        )
        self.assertEqual(
            DEFAULT_MIN_SEEN_DAYS,
            2,
        )
        self.assertEqual(
            DEFAULT_MIN_OBSERVATION_COUNT,
            2,
        )

    def test_disabled_policy_never_creates_candidate(
        self,
    ) -> None:
        result = evaluate_candidate_eligibility(
            self.candidate(),
        )

        self.assertEqual(
            result["decision"],
            "observed",
        )
        self.assertEqual(
            result["reason"],
            "candidate_eligibility_disabled",
        )

    def test_one_seen_day_never_creates_candidate(
        self,
    ) -> None:
        candidate = self.candidate()
        candidate["seen_dates"] = [
            "2026-08-25",
        ]
        candidate["observation_count"] = 100000
        candidate["presence_cycles"] = 100000
        candidate["active_cycles"] = 100000
        candidate["reactivation_count"] = 100000

        result = evaluate_candidate_eligibility(
            candidate,
            settings=self.enabled_settings(),
        )

        self.assertEqual(
            result["decision"],
            "observed",
        )
        self.assertEqual(
            result["reason"],
            "candidate_eligibility_insufficient_seen_days",
        )
        self.assertEqual(
            result["evidence"]["seen_days"],
            1,
        )

    def test_insufficient_observation_count_remains_observed(
        self,
    ) -> None:
        candidate = self.candidate()
        candidate["observation_count"] = 1

        result = evaluate_candidate_eligibility(
            candidate,
            settings=self.enabled_settings(),
        )

        self.assertEqual(
            result["decision"],
            "observed",
        )
        self.assertEqual(
            result["reason"],
            "candidate_eligibility_insufficient_observation_count",
        )

    def test_thresholds_met_create_candidate(
        self,
    ) -> None:
        result = evaluate_candidate_eligibility(
            self.candidate(),
            settings=self.enabled_settings(),
        )

        self.assertEqual(
            result["version"],
            ELIGIBILITY_VERSION,
        )
        self.assertEqual(
            result["mode"],
            ELIGIBILITY_MODE,
        )
        self.assertEqual(
            result["decision"],
            "candidate",
        )
        self.assertEqual(
            result["reason"],
            "candidate_eligibility_met",
        )
        self.assertEqual(
            result["evidence"]["seen_days"],
            2,
        )
        self.assertEqual(
            result["evidence"]["observation_count"],
            2,
        )

    def test_feed_absence_blocks_new_candidate(
        self,
    ) -> None:
        candidate = self.candidate()
        candidate["feed_present"] = False

        result = evaluate_candidate_eligibility(
            candidate,
            settings=self.enabled_settings(),
        )

        self.assertEqual(
            result["decision"],
            "observed",
        )
        self.assertEqual(
            result["reason"],
            "candidate_eligibility_feed_absent",
        )

    def test_existing_candidate_is_retained_when_feed_absent(
        self,
    ) -> None:
        candidate = self.candidate()
        candidate["feed_present"] = False
        candidate["seen_dates"] = []
        candidate["observation_count"] = 0

        result = evaluate_candidate_eligibility(
            candidate,
            previous_decision="candidate",
            settings=self.enabled_settings(),
        )

        self.assertEqual(
            result["decision"],
            "candidate",
        )
        self.assertEqual(
            result["reason"],
            "candidate_retained",
        )

    def test_existing_candidate_is_retained_when_policy_disabled(
        self,
    ) -> None:
        candidate = self.candidate()

        result = evaluate_candidate_eligibility(
            candidate,
            previous_decision="candidate",
            settings={"enabled": False},
        )

        self.assertEqual(
            result["decision"],
            "candidate",
        )
        self.assertEqual(
            result["reason"],
            "candidate_retained",
        )

    def test_current_routing_status_does_not_drive_decision(
        self,
    ) -> None:
        decisions = set()

        for routing_status in (
            "active",
            "expired",
            "suspect",
            "unknown",
            None,
        ):
            candidate = self.candidate()
            candidate["current_routing_status"] = (
                routing_status
            )

            result = evaluate_candidate_eligibility(
                candidate,
                settings=self.enabled_settings(),
            )

            decisions.add(result["decision"])

        self.assertEqual(
            decisions,
            {"candidate"},
        )

    def test_presence_and_active_cycles_do_not_drive_decision(
        self,
    ) -> None:
        candidate = self.candidate()
        candidate["seen_dates"] = [
            "2026-08-25",
        ]
        candidate["observation_count"] = 1
        candidate["presence_cycles"] = 999999
        candidate["active_cycles"] = 999999
        candidate["reactivation_count"] = 999999

        result = evaluate_candidate_eligibility(
            candidate,
            settings=self.enabled_settings(),
        )

        self.assertEqual(
            result["decision"],
            "observed",
        )

    def test_duplicate_seen_dates_count_as_one_day(
        self,
    ) -> None:
        candidate = self.candidate()
        candidate["seen_dates"] = [
            "2026-08-25",
            "2026-08-25",
            "2026-08-25",
        ]
        candidate["observation_count"] = 10

        result = evaluate_candidate_eligibility(
            candidate,
            settings=self.enabled_settings(),
        )

        self.assertEqual(
            result["decision"],
            "observed",
        )
        self.assertEqual(
            result["evidence"]["seen_days"],
            1,
        )

    def test_candidate_decisions_do_not_include_later_states(
        self,
    ) -> None:
        self.assertEqual(
            ELIGIBILITY_DECISIONS,
            {
                "observed",
                "candidate",
            },
        )
        self.assertNotIn(
            "covered_by_suffix",
            ELIGIBILITY_DECISIONS,
        )
        self.assertNotIn(
            "promoted_exact",
            ELIGIBILITY_DECISIONS,
        )

    def test_unknown_previous_decision_fails_closed(
        self,
    ) -> None:
        for previous_decision in (
            "covered_by_suffix",
            "promoted_exact",
            "something_new",
        ):
            with self.subTest(
                previous_decision=previous_decision
            ):
                with self.assertRaisesRegex(
                    ValueError,
                    "Unsupported previous",
                ):
                    evaluate_candidate_eligibility(
                        self.candidate(),
                        previous_decision=previous_decision,
                        settings=self.enabled_settings(),
                    )

    def test_invalid_settings_fail_closed(
        self,
    ) -> None:
        invalid_settings = (
            {"enabled": "yes"},
            {"min_seen_days": 0},
            {"min_seen_days": True},
            {"min_observation_count": 0},
            {"min_observation_count": True},
            {"unknown": 1},
        )

        for settings in invalid_settings:
            with self.subTest(settings=settings):
                with self.assertRaises(ValueError):
                    candidate_eligibility_settings(
                        settings
                    )

    def test_invalid_runtime_evidence_fails_closed(
        self,
    ) -> None:
        cases = (
            ("feed_present", None),
            ("observation_count", -1),
            ("observation_count", True),
            ("seen_dates", None),
            ("seen_dates", [1]),
        )

        for key, value in cases:
            with self.subTest(
                key=key,
                value=value,
            ):
                candidate = self.candidate()
                candidate[key] = value

                with self.assertRaises(ValueError):
                    evaluate_candidate_eligibility(
                        candidate,
                        settings=self.enabled_settings(),
                    )

    def test_evaluator_does_not_mutate_inputs(
        self,
    ) -> None:
        candidate = self.candidate()
        settings = self.enabled_settings()

        candidate_before = copy.deepcopy(candidate)
        settings_before = copy.deepcopy(settings)

        evaluate_candidate_eligibility(
            candidate,
            settings=settings,
        )

        self.assertEqual(
            candidate,
            candidate_before,
        )
        self.assertEqual(
            settings,
            settings_before,
        )


if __name__ == "__main__":
    unittest.main()
