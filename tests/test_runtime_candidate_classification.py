from __future__ import annotations

import copy
import unittest
from datetime import datetime, timezone

from dns_maintenance.runtime_candidate_classification import (
    CLASSIFICATION_MODE,
    CLASSIFICATION_VERSION,
    SHADOW_DECISIONS,
    classify_runtime_candidate,
    classify_runtime_candidate_state,
)


class RuntimeCandidateClassificationTests(unittest.TestCase):
    def now(self) -> datetime:
        return datetime(
            2026,
            8,
            25,
            14,
            30,
            tzinfo=timezone.utc,
        )

    def candidate(
        self,
        hostname: str = "video.example.com",
    ) -> dict:
        return {
            "candidate_id": "candidate-1",
            "hostname": hostname,
            "suffix": "example.com",
            "state": "observed",
            "first_intake_at": "2026-08-25T10:00:00Z",
            "last_intake_at": "2026-08-25T14:00:00Z",
            "feed_present": True,
            "first_observed": "2026-08-24T08:00:00Z",
            "last_observed": "2026-08-25T13:00:00Z",
            "current_presence": True,
            "current_routing_status": "active",
            "observation_count": 4,
            "presence_cycles": 8,
            "active_cycles": 5,
            "reactivation_count": 1,
            "seen_dates": [
                "2026-08-24",
                "2026-08-25",
            ],
            "last_external_at": "2026-08-25T12:00:00Z",
        }

    def policy_disabled(self) -> dict:
        return {
            "enabled": False,
            "allow": [],
            "exclude": [],
        }

    def policy_excluding_example(self) -> dict:
        return {
            "enabled": True,
            "allow": [],
            "exclude": [
                {
                    "id": "exclude-example",
                    "match": "suffix",
                    "value": "example.com",
                    "reason": "test exclusion",
                }
            ],
        }

    def test_unknown_candidate_remains_observed(self) -> None:
        result = classify_runtime_candidate(
            self.candidate(),
            {"hosts": {}},
            self.policy_disabled(),
            self.now(),
        )

        self.assertEqual(
            result["version"],
            CLASSIFICATION_VERSION,
        )
        self.assertEqual(
            result["mode"],
            CLASSIFICATION_MODE,
        )
        self.assertEqual(
            result["decision"],
            "observed",
        )
        self.assertEqual(
            result["reason"],
            "awaiting_classification_policy",
        )

        self.assertNotIn(
            "eligibility",
            result,
        )

        evidence = result["evidence"]

        self.assertTrue(evidence["feed_present"])
        self.assertTrue(evidence["current_presence"])
        self.assertEqual(
            evidence["observation_count"],
            4,
        )
        self.assertEqual(
            evidence["presence_cycles"],
            8,
        )
        self.assertEqual(
            evidence["active_cycles"],
            5,
        )
        self.assertEqual(
            evidence["reactivation_count"],
            1,
        )
        self.assertEqual(
            evidence["seen_days"],
            2,
        )
        self.assertFalse(
            evidence["exact_dns_present"]
        )
        self.assertIsNone(
            evidence["exact_dns_status"]
        )
        self.assertFalse(
            evidence["policy_excluded"]
        )

    def test_hostname_policy_exclusion_is_rejected(self) -> None:
        result = classify_runtime_candidate(
            self.candidate(),
            {
                "hosts": {
                    "video.example.com": {
                        "status": "active",
                    }
                }
            },
            self.policy_excluding_example(),
            self.now(),
        )

        self.assertEqual(
            result["decision"],
            "rejected",
        )
        self.assertEqual(
            result["reason"],
            "hostname_policy_excluded",
        )
        self.assertEqual(
            result["policy_reason"],
            "test exclusion",
        )
        self.assertTrue(
            result["evidence"]["policy_excluded"]
        )
        self.assertEqual(
            result["evidence"]["policy_rule"],
            "exclude-example",
        )

    def test_existing_active_exact_dns_is_observe_only(
        self,
    ) -> None:
        result = classify_runtime_candidate(
            self.candidate(),
            {
                "hosts": {
                    "video.example.com": {
                        "status": "active",
                    }
                }
            },
            self.policy_disabled(),
            self.now(),
        )

        self.assertEqual(
            result["decision"],
            "observe_only",
        )
        self.assertEqual(
            result["reason"],
            "exact_dns_existing",
        )
        self.assertTrue(
            result["evidence"]["exact_dns_present"]
        )
        self.assertEqual(
            result["evidence"]["exact_dns_status"],
            "active",
        )

    def test_all_existing_exact_dns_lifecycle_states_are_observe_only(
        self,
    ) -> None:
        for status in (
            "pending",
            "active",
            "suspect",
            "quarantine",
            "expired",
            "excluded",
        ):
            with self.subTest(status=status):
                result = classify_runtime_candidate(
                    self.candidate(),
                    {
                        "hosts": {
                            "video.example.com": {
                                "status": status,
                            }
                        }
                    },
                    self.policy_disabled(),
                    self.now(),
                )

                self.assertEqual(
                    result["decision"],
                    "observe_only",
                )
                self.assertEqual(
                    result["reason"],
                    "exact_dns_existing",
                )
                self.assertEqual(
                    result["evidence"][
                        "exact_dns_status"
                    ],
                    status,
                )

    def test_feed_absence_is_not_negative_evidence(
        self,
    ) -> None:
        candidate = self.candidate()
        candidate["feed_present"] = False
        candidate["current_presence"] = False

        result = classify_runtime_candidate(
            candidate,
            {"hosts": {}},
            self.policy_disabled(),
            self.now(),
        )

        self.assertEqual(
            result["decision"],
            "observed",
        )
        self.assertFalse(
            result["evidence"]["feed_present"]
        )
        self.assertFalse(
            result["evidence"]["current_presence"]
        )

    def test_current_routing_status_does_not_drive_decision(
        self,
    ) -> None:
        for routing_status in (
            "active",
            "expired",
            "suspect",
            "unknown",
            None,
        ):
            with self.subTest(
                routing_status=routing_status
            ):
                candidate = self.candidate()
                candidate[
                    "current_routing_status"
                ] = routing_status

                result = classify_runtime_candidate(
                    candidate,
                    {"hosts": {}},
                    self.policy_disabled(),
                    self.now(),
                )

                self.assertEqual(
                    result["decision"],
                    "observed",
                )
                self.assertEqual(
                    result["evidence"][
                        "current_routing_status"
                    ],
                    routing_status,
                )

    def test_runtime_metrics_do_not_promote_candidate(
        self,
    ) -> None:
        candidate = self.candidate()

        candidate["observation_count"] = 100000
        candidate["presence_cycles"] = 100000
        candidate["active_cycles"] = 100000
        candidate["reactivation_count"] = 1000
        candidate["seen_dates"] = [
            f"2026-08-{day:02d}"
            for day in range(1, 26)
        ]

        result = classify_runtime_candidate(
            candidate,
            {"hosts": {}},
            self.policy_disabled(),
            self.now(),
        )

        self.assertEqual(
            result["decision"],
            "observed",
        )
        self.assertNotEqual(
            result["decision"],
            "candidate",
        )
        self.assertNotEqual(
            result["decision"],
            "promoted_exact",
        )

    def test_shadow_decisions_include_candidate_only(
        self,
    ) -> None:
        self.assertEqual(
            SHADOW_DECISIONS,
            {
                "observed",
                "candidate",
                "observe_only",
                "rejected",
            },
        )
        self.assertIn(
            "candidate",
            SHADOW_DECISIONS,
        )
        self.assertNotIn(
            "covered_by_suffix",
            SHADOW_DECISIONS,
        )
        self.assertNotIn(
            "promoted_exact",
            SHADOW_DECISIONS,
        )

    def test_eligibility_can_classify_candidate(
        self,
    ) -> None:
        result = classify_runtime_candidate(
            self.candidate(),
            {"hosts": {}},
            self.policy_disabled(),
            self.now(),
            candidate_eligibility_cfg={
                "enabled": True,
                "min_seen_days": 2,
                "min_observation_count": 2,
            },
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
            result["eligibility"]["decision"],
            "candidate",
        )
        self.assertEqual(
            result["eligibility"]["evidence"][
                "seen_days"
            ],
            2,
        )

    def test_policy_exclusion_overrides_candidate_eligibility(
        self,
    ) -> None:
        result = classify_runtime_candidate(
            self.candidate(),
            {"hosts": {}},
            self.policy_excluding_example(),
            self.now(),
            candidate_eligibility_cfg={
                "enabled": True,
                "min_seen_days": 2,
                "min_observation_count": 2,
            },
            previous_decision="candidate",
        )

        self.assertEqual(
            result["decision"],
            "rejected",
        )
        self.assertEqual(
            result["reason"],
            "hostname_policy_excluded",
        )
        self.assertNotIn(
            "eligibility",
            result,
        )

    def test_exact_dns_overrides_previous_candidate(
        self,
    ) -> None:
        result = classify_runtime_candidate(
            self.candidate(),
            {
                "hosts": {
                    "video.example.com": {
                        "status": "active",
                    }
                }
            },
            self.policy_disabled(),
            self.now(),
            candidate_eligibility_cfg={
                "enabled": True,
            },
            previous_decision="candidate",
        )

        self.assertEqual(
            result["decision"],
            "observe_only",
        )
        self.assertEqual(
            result["reason"],
            "exact_dns_existing",
        )
        self.assertNotIn(
            "eligibility",
            result,
        )

    def test_state_classifier_retains_previous_candidate(
        self,
    ) -> None:
        candidate = self.candidate()
        candidate["feed_present"] = False
        candidate["current_presence"] = False
        candidate["seen_dates"] = []
        candidate["observation_count"] = 0

        runtime_state = {
            "schema_version": 1,
            "service": "demo",
            "candidates": {
                candidate["candidate_id"]: candidate,
            },
        }

        previous_snapshot = {
            "version": 1,
            "mode": "shadow",
            "service": "demo",
            "candidates": {
                candidate["candidate_id"]: {
                    "decision": "candidate",
                }
            },
        }

        result = classify_runtime_candidate_state(
            runtime_state,
            {"hosts": {}},
            self.policy_disabled(),
            self.now(),
            candidate_eligibility_cfg={
                "enabled": True,
                "min_seen_days": 2,
                "min_observation_count": 2,
            },
            previous_snapshot=previous_snapshot,
        )

        self.assertEqual(
            result["counts"]["candidate"],
            1,
        )
        self.assertEqual(
            result["counts"]["observed"],
            0,
        )
        self.assertEqual(
            result["candidates"][
                "candidate-1"
            ]["decision"],
            "candidate",
        )
        self.assertEqual(
            result["candidates"][
                "candidate-1"
            ]["reason"],
            "candidate_retained",
        )

    def test_default_off_state_preserves_legacy_counts(
        self,
    ) -> None:
        candidate = self.candidate()

        runtime_state = {
            "schema_version": 1,
            "service": "demo",
            "candidates": {
                candidate["candidate_id"]: candidate,
            },
        }

        result = classify_runtime_candidate_state(
            runtime_state,
            {"hosts": {}},
            self.policy_disabled(),
            self.now(),
        )

        self.assertEqual(
            result["counts"],
            {
                "observed": 1,
                "observe_only": 0,
                "rejected": 0,
            },
        )
        self.assertNotIn(
            "candidate",
            result["counts"],
        )
        self.assertNotIn(
            "eligibility",
            result["candidates"][
                "candidate-1"
            ],
        )

    def test_classifier_does_not_mutate_inputs(
        self,
    ) -> None:
        candidate = self.candidate()

        dns_state = {
            "hosts": {
                "other.example.com": {
                    "status": "active",
                    "sources": ["manual"],
                }
            }
        }

        candidate_before = copy.deepcopy(
            candidate
        )
        dns_before = copy.deepcopy(
            dns_state
        )

        classify_runtime_candidate(
            candidate,
            dns_state,
            self.policy_disabled(),
            self.now(),
        )

        self.assertEqual(
            candidate,
            candidate_before,
        )
        self.assertEqual(
            dns_state,
            dns_before,
        )

    def test_state_classifier_returns_snapshot_without_mutation(
        self,
    ) -> None:
        candidate = self.candidate()

        runtime_state = {
            "schema_version": 1,
            "service": "demo",
            "candidates": {
                candidate["candidate_id"]: candidate,
            },
        }

        before = copy.deepcopy(
            runtime_state
        )

        result = classify_runtime_candidate_state(
            runtime_state,
            {"hosts": {}},
            self.policy_disabled(),
            self.now(),
        )

        self.assertEqual(
            runtime_state,
            before,
        )
        self.assertEqual(
            result["version"],
            1,
        )
        self.assertEqual(
            result["mode"],
            "shadow",
        )
        self.assertEqual(
            result["service"],
            "demo",
        )
        self.assertEqual(
            result["candidates"][
                "candidate-1"
            ]["decision"],
            "observed",
        )

    def test_non_normalized_hostname_is_rejected(
        self,
    ) -> None:
        candidate = self.candidate(
            "Video.Example.com"
        )

        with self.assertRaisesRegex(
            ValueError,
            "normalized hostname",
        ):
            classify_runtime_candidate(
                candidate,
                {"hosts": {}},
                self.policy_disabled(),
                self.now(),
            )

    def test_invalid_runtime_evidence_fails_closed(
        self,
    ) -> None:
        candidate = self.candidate()
        candidate["observation_count"] = -1

        with self.assertRaisesRegex(
            ValueError,
            "observation_count",
        ):
            classify_runtime_candidate(
                candidate,
                {"hosts": {}},
                self.policy_disabled(),
                self.now(),
            )

    def test_invalid_dns_state_fails_closed(
        self,
    ) -> None:
        with self.assertRaisesRegex(
            ValueError,
            "DNS state hosts",
        ):
            classify_runtime_candidate(
                self.candidate(),
                {"hosts": []},
                self.policy_disabled(),
                self.now(),
            )

    def test_invalid_exact_dns_entry_fails_closed(
        self,
    ) -> None:
        with self.assertRaisesRegex(
            ValueError,
            "Exact DNS state entry",
        ):
            classify_runtime_candidate(
                self.candidate(),
                {
                    "hosts": {
                        "video.example.com": "active",
                    }
                },
                self.policy_disabled(),
                self.now(),
            )

    def test_state_candidate_id_mismatch_fails_closed(
        self,
    ) -> None:
        candidate = self.candidate()

        runtime_state = {
            "schema_version": 1,
            "service": "demo",
            "candidates": {
                "different-id": candidate,
            },
        }

        with self.assertRaisesRegex(
            ValueError,
            "candidate_id mismatch",
        ):
            classify_runtime_candidate_state(
                runtime_state,
                {"hosts": {}},
                self.policy_disabled(),
                self.now(),
            )


if __name__ == "__main__":
    unittest.main()
