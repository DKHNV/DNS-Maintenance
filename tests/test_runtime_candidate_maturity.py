from __future__ import annotations

import copy
import unittest
from datetime import datetime, timedelta, timezone

from dns_maintenance.runtime_candidate_maturity import (
    DEFAULT_MIN_ADDITIONAL_OBSERVATION_COUNT,
    DEFAULT_MIN_ADDITIONAL_SEEN_DAYS,
    DEFAULT_MIN_CANDIDATE_AGE_HOURS,
    MATURITY_MODE,
    MATURITY_STATES,
    MATURITY_VERSION,
    candidate_maturity_settings,
    evaluate_candidate_maturity,
    validate_candidate_maturity_history,
)


class RuntimeCandidateMaturityTests(unittest.TestCase):
    def now(self) -> datetime:
        return datetime(
            2026,
            8,
            25,
            18,
            0,
            tzinfo=timezone.utc,
        )

    def candidate(self) -> dict:
        return {
            "candidate_id": "candidate-1",
            "hostname": "video.example.com",
            "suffix": "example.com",
            "state": "observed",
            "feed_present": True,
            "current_presence": True,
            "current_routing_status": "active",
            "observation_count": 3,
            "presence_cycles": 80,
            "active_cycles": 40,
            "reactivation_count": 2,
            "seen_dates": [
                "2026-08-24",
                "2026-08-25",
            ],
        }

    def enabled_settings(self) -> dict:
        return {
            "enabled": True,
            "min_candidate_age_hours": 24,
            "min_additional_seen_days": 1,
            "min_additional_observation_count": 1,
        }

    def tracking_history(
        self,
        *,
        candidate_since: str = "2026-08-24T18:00:00Z",
        seen_days: int = 2,
        observation_count: int = 3,
    ) -> dict:
        return {
            "version": MATURITY_VERSION,
            "mode": MATURITY_MODE,
            "state": "tracking",
            "reason": "candidate_maturity_tracking_started",
            "candidate_since": candidate_since,
            "criteria": self.enabled_settings(),
            "baseline": {
                "seen_days": seen_days,
                "observation_count": observation_count,
            },
            "evidence": {
                "feed_present": True,
                "candidate_age_hours": 0.0,
                "seen_days": seen_days,
                "observation_count": observation_count,
                "additional_seen_days": 0,
                "additional_observation_count": 0,
            },
        }

    def ready_history(self) -> dict:
        history = self.tracking_history()
        history["state"] = "ready"
        history["reason"] = "candidate_maturity_met"
        return history

    def test_default_settings_are_disabled_and_conservative(
        self,
    ) -> None:
        settings = candidate_maturity_settings(None)

        self.assertFalse(settings["enabled"])
        self.assertEqual(
            settings["min_candidate_age_hours"],
            DEFAULT_MIN_CANDIDATE_AGE_HOURS,
        )
        self.assertEqual(
            settings["min_additional_seen_days"],
            DEFAULT_MIN_ADDITIONAL_SEEN_DAYS,
        )
        self.assertEqual(
            settings["min_additional_observation_count"],
            DEFAULT_MIN_ADDITIONAL_OBSERVATION_COUNT,
        )

        self.assertEqual(
            DEFAULT_MIN_CANDIDATE_AGE_HOURS,
            24.0,
        )
        self.assertEqual(
            DEFAULT_MIN_ADDITIONAL_SEEN_DAYS,
            1,
        )
        self.assertEqual(
            DEFAULT_MIN_ADDITIONAL_OBSERVATION_COUNT,
            1,
        )

    def test_maturity_states_are_shadow_only(self) -> None:
        self.assertEqual(
            MATURITY_STATES,
            {
                "tracking",
                "ready",
            },
        )
        self.assertNotIn(
            "promoted_exact",
            MATURITY_STATES,
        )
        self.assertNotIn(
            "active",
            MATURITY_STATES,
        )

    def test_first_enabled_evaluation_starts_tracking(
        self,
    ) -> None:
        result = evaluate_candidate_maturity(
            self.candidate(),
            self.now(),
            settings=self.enabled_settings(),
        )

        self.assertEqual(
            result["version"],
            MATURITY_VERSION,
        )
        self.assertEqual(
            result["mode"],
            MATURITY_MODE,
        )
        self.assertEqual(
            result["state"],
            "tracking",
        )
        self.assertEqual(
            result["reason"],
            "candidate_maturity_tracking_started",
        )
        self.assertEqual(
            result["candidate_since"],
            "2026-08-25T18:00:00Z",
        )
        self.assertEqual(
            result["baseline"],
            {
                "seen_days": 2,
                "observation_count": 3,
            },
        )
        self.assertEqual(
            result["evidence"]["candidate_age_hours"],
            0.0,
        )
        self.assertEqual(
            result["evidence"]["additional_seen_days"],
            0,
        )
        self.assertEqual(
            result["evidence"][
                "additional_observation_count"
            ],
            0,
        )

    def test_first_evaluation_can_never_be_ready(
        self,
    ) -> None:
        candidate = self.candidate()

        candidate["observation_count"] = 100000
        candidate["seen_dates"] = [
            f"2026-08-{day:02d}"
            for day in range(1, 26)
        ]
        candidate["presence_cycles"] = 100000
        candidate["active_cycles"] = 100000
        candidate["reactivation_count"] = 100000

        result = evaluate_candidate_maturity(
            candidate,
            self.now(),
            settings=self.enabled_settings(),
        )

        self.assertEqual(
            result["state"],
            "tracking",
        )
        self.assertEqual(
            result["reason"],
            "candidate_maturity_tracking_started",
        )
        self.assertEqual(
            result["evidence"]["additional_seen_days"],
            0,
        )
        self.assertEqual(
            result["evidence"][
                "additional_observation_count"
            ],
            0,
        )

    def test_disabled_first_evaluation_is_tracking(
        self,
    ) -> None:
        result = evaluate_candidate_maturity(
            self.candidate(),
            self.now(),
        )

        self.assertEqual(
            result["state"],
            "tracking",
        )
        self.assertEqual(
            result["reason"],
            "candidate_maturity_disabled",
        )

    def test_ready_requires_new_evidence_after_baseline(
        self,
    ) -> None:
        candidate = self.candidate()

        candidate["seen_dates"].append(
            "2026-08-26"
        )
        candidate["observation_count"] = 4

        now = self.now() + timedelta(
            hours=24
        )

        result = evaluate_candidate_maturity(
            candidate,
            now,
            previous_maturity=self.tracking_history(),
            settings=self.enabled_settings(),
        )

        self.assertEqual(
            result["state"],
            "ready",
        )
        self.assertEqual(
            result["reason"],
            "candidate_maturity_met",
        )
        self.assertEqual(
            result["evidence"]["candidate_age_hours"],
            48.0,
        )
        self.assertEqual(
            result["evidence"]["additional_seen_days"],
            1,
        )
        self.assertEqual(
            result["evidence"][
                "additional_observation_count"
            ],
            1,
        )

    def test_candidate_age_threshold_is_required(
        self,
    ) -> None:
        candidate = self.candidate()
        candidate["seen_dates"].append(
            "2026-08-26"
        )
        candidate["observation_count"] = 4

        history = self.tracking_history(
            candidate_since="2026-08-25T06:00:00Z"
        )

        result = evaluate_candidate_maturity(
            candidate,
            self.now(),
            previous_maturity=history,
            settings=self.enabled_settings(),
        )

        self.assertEqual(
            result["state"],
            "tracking",
        )
        self.assertEqual(
            result["reason"],
            "candidate_maturity_insufficient_candidate_age",
        )
        self.assertEqual(
            result["evidence"]["candidate_age_hours"],
            12.0,
        )

    def test_additional_seen_day_is_required(
        self,
    ) -> None:
        candidate = self.candidate()
        candidate["observation_count"] = 10

        result = evaluate_candidate_maturity(
            candidate,
            self.now(),
            previous_maturity=self.tracking_history(),
            settings=self.enabled_settings(),
        )

        self.assertEqual(
            result["state"],
            "tracking",
        )
        self.assertEqual(
            result["reason"],
            "candidate_maturity_insufficient_additional_seen_days",
        )
        self.assertEqual(
            result["evidence"]["additional_seen_days"],
            0,
        )

    def test_additional_observation_is_required(
        self,
    ) -> None:
        candidate = self.candidate()
        candidate["seen_dates"].append(
            "2026-08-26"
        )

        result = evaluate_candidate_maturity(
            candidate,
            self.now(),
            previous_maturity=self.tracking_history(),
            settings=self.enabled_settings(),
        )

        self.assertEqual(
            result["state"],
            "tracking",
        )
        self.assertEqual(
            result["reason"],
            (
                "candidate_maturity_insufficient_"
                "additional_observation_count"
            ),
        )
        self.assertEqual(
            result["evidence"][
                "additional_observation_count"
            ],
            0,
        )

    def test_feed_absence_blocks_new_ready_state(
        self,
    ) -> None:
        candidate = self.candidate()
        candidate["feed_present"] = False
        candidate["seen_dates"].append(
            "2026-08-26"
        )
        candidate["observation_count"] = 4

        result = evaluate_candidate_maturity(
            candidate,
            self.now(),
            previous_maturity=self.tracking_history(),
            settings=self.enabled_settings(),
        )

        self.assertEqual(
            result["state"],
            "tracking",
        )
        self.assertEqual(
            result["reason"],
            "candidate_maturity_feed_absent",
        )
        self.assertEqual(
            result["candidate_since"],
            "2026-08-24T18:00:00Z",
        )
        self.assertEqual(
            result["baseline"],
            {
                "seen_days": 2,
                "observation_count": 3,
            },
        )

    def test_disabled_policy_retains_tracking_history(
        self,
    ) -> None:
        candidate = self.candidate()
        candidate["seen_dates"].append(
            "2026-08-26"
        )
        candidate["observation_count"] = 4

        result = evaluate_candidate_maturity(
            candidate,
            self.now(),
            previous_maturity=self.tracking_history(),
            settings={"enabled": False},
        )

        self.assertEqual(
            result["state"],
            "tracking",
        )
        self.assertEqual(
            result["reason"],
            "candidate_maturity_disabled_retained",
        )
        self.assertEqual(
            result["candidate_since"],
            "2026-08-24T18:00:00Z",
        )

    def test_ready_state_is_retained_when_feed_absent(
        self,
    ) -> None:
        candidate = self.candidate()
        candidate["feed_present"] = False
        candidate["seen_dates"] = []
        candidate["observation_count"] = 0

        result = evaluate_candidate_maturity(
            candidate,
            self.now(),
            previous_maturity=self.ready_history(),
            settings={"enabled": False},
        )

        self.assertEqual(
            result["state"],
            "ready",
        )
        self.assertEqual(
            result["reason"],
            "candidate_maturity_ready_retained",
        )
        self.assertEqual(
            result["candidate_since"],
            "2026-08-24T18:00:00Z",
        )

    def test_duplicate_seen_dates_do_not_create_progress(
        self,
    ) -> None:
        candidate = self.candidate()
        candidate["seen_dates"] = [
            "2026-08-24",
            "2026-08-25",
            "2026-08-25",
            "2026-08-25",
        ]
        candidate["observation_count"] = 4

        result = evaluate_candidate_maturity(
            candidate,
            self.now(),
            previous_maturity=self.tracking_history(),
            settings=self.enabled_settings(),
        )

        self.assertEqual(
            result["state"],
            "tracking",
        )
        self.assertEqual(
            result["evidence"]["seen_days"],
            2,
        )
        self.assertEqual(
            result["evidence"]["additional_seen_days"],
            0,
        )

    def test_counter_regression_is_never_negative_progress(
        self,
    ) -> None:
        candidate = self.candidate()

        candidate["seen_dates"] = [
            "2026-08-25",
        ]
        candidate["observation_count"] = 1

        result = evaluate_candidate_maturity(
            candidate,
            self.now(),
            previous_maturity=self.tracking_history(),
            settings=self.enabled_settings(),
        )

        self.assertEqual(
            result["state"],
            "tracking",
        )
        self.assertEqual(
            result["evidence"]["additional_seen_days"],
            0,
        )
        self.assertEqual(
            result["evidence"][
                "additional_observation_count"
            ],
            0,
        )

    def test_routing_metrics_do_not_drive_maturity(
        self,
    ) -> None:
        states = set()

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
            candidate["presence_cycles"] = 999999
            candidate["active_cycles"] = 999999
            candidate["reactivation_count"] = 999999

            result = evaluate_candidate_maturity(
                candidate,
                self.now(),
                previous_maturity=self.tracking_history(),
                settings=self.enabled_settings(),
            )

            states.add(
                (
                    result["state"],
                    result["reason"],
                )
            )

        self.assertEqual(
            states,
            {
                (
                    "tracking",
                    "candidate_maturity_insufficient_additional_seen_days",
                )
            },
        )

    def test_future_candidate_since_fails_closed(
        self,
    ) -> None:
        history = self.tracking_history(
            candidate_since="2026-08-26T18:00:00Z"
        )

        with self.assertRaisesRegex(
            ValueError,
            "cannot be in the future",
        ):
            evaluate_candidate_maturity(
                self.candidate(),
                self.now(),
                previous_maturity=history,
                settings=self.enabled_settings(),
            )

    def test_invalid_settings_fail_closed(
        self,
    ) -> None:
        invalid_settings = (
            {"enabled": "yes"},
            {"min_candidate_age_hours": 0},
            {"min_candidate_age_hours": True},
            {"min_additional_seen_days": 0},
            {"min_additional_seen_days": True},
            {"min_additional_observation_count": 0},
            {"min_additional_observation_count": True},
            {"unknown": 1},
        )

        for settings in invalid_settings:
            with self.subTest(settings=settings):
                with self.assertRaises(ValueError):
                    candidate_maturity_settings(
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
                    evaluate_candidate_maturity(
                        candidate,
                        self.now(),
                        settings=self.enabled_settings(),
                    )

    def test_invalid_previous_history_fails_closed(
        self,
    ) -> None:
        invalid_histories = []

        wrong_version = self.tracking_history()
        wrong_version["version"] = 999
        invalid_histories.append(wrong_version)

        wrong_mode = self.tracking_history()
        wrong_mode["mode"] = "automatic"
        invalid_histories.append(wrong_mode)

        wrong_state = self.tracking_history()
        wrong_state["state"] = "promoted_exact"
        invalid_histories.append(wrong_state)

        invalid_time = self.tracking_history()
        invalid_time["candidate_since"] = "not-a-time"
        invalid_histories.append(invalid_time)

        invalid_baseline = self.tracking_history()
        invalid_baseline["baseline"] = None
        invalid_histories.append(invalid_baseline)

        invalid_seen_days = self.tracking_history()
        invalid_seen_days["baseline"]["seen_days"] = -1
        invalid_histories.append(invalid_seen_days)

        invalid_observation_count = self.tracking_history()
        invalid_observation_count["baseline"][
            "observation_count"
        ] = True
        invalid_histories.append(
            invalid_observation_count
        )

        for history in invalid_histories:
            with self.subTest(history=history):
                with self.assertRaises(ValueError):
                    validate_candidate_maturity_history(
                        history
                    )

    def test_evaluator_does_not_mutate_inputs(
        self,
    ) -> None:
        candidate = self.candidate()
        history = self.tracking_history()
        settings = self.enabled_settings()

        candidate_before = copy.deepcopy(
            candidate
        )
        history_before = copy.deepcopy(
            history
        )
        settings_before = copy.deepcopy(
            settings
        )

        evaluate_candidate_maturity(
            candidate,
            self.now(),
            previous_maturity=history,
            settings=settings,
        )

        self.assertEqual(
            candidate,
            candidate_before,
        )
        self.assertEqual(
            history,
            history_before,
        )
        self.assertEqual(
            settings,
            settings_before,
        )


if __name__ == "__main__":
    unittest.main()
