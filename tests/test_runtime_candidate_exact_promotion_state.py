from __future__ import annotations

import copy
import json
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

from dns_maintenance.runtime_candidate_exact_promotion_state import (
    evaluate_exact_promotion_state,
    write_exact_promotion_snapshot,
)


class RuntimeCandidateExactPromotionStateTests(
    unittest.TestCase
):
    def now(self) -> datetime:
        return datetime(
            2026,
            8,
            27,
            6,
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

    def runtime_state(self) -> dict:
        return {
            "version": 1,
            "service": "youtube",
            "source_content_hash": (
                "a" * 64
            ),
            "source_generated_at": (
                "2026-08-27T05:55:00Z"
            ),
            "last_intake_at": (
                "2026-08-27T06:00:00Z"
            ),
            "candidates": {
                "candidate-1": (
                    self.candidate()
                ),
            },
        }

    def maturity(
        self,
        *,
        state: str = "ready",
    ) -> dict:
        return {
            "version": 1,
            "mode": "shadow",
            "state": state,
            "reason": (
                "candidate_maturity_met"
                if state == "ready"
                else
                "candidate_maturity_"
                "insufficient_additional_seen_days"
            ),
            "candidate_since": (
                "2026-08-25T06:00:00Z"
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

    def classification_entry(
        self,
        *,
        decision: str = "candidate",
        maturity_state: str | None = "ready",
    ) -> dict:
        result = {
            "version": 1,
            "mode": "shadow",
            "classified_at": (
                "2026-08-27T06:00:00Z"
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
                "exact_dns_present": False,
                "exact_dns_status": None,
                "policy_excluded": False,
                "policy_rule": None,
            },
        }

        if maturity_state is not None:
            result["maturity"] = (
                self.maturity(
                    state=maturity_state
                )
            )

        return result

    def classification_state(
        self,
        *,
        decision: str = "candidate",
        maturity_state: str | None = "ready",
    ) -> dict:
        return {
            "version": 1,
            "mode": "shadow",
            "service": "youtube",
            "classified_at": (
                "2026-08-27T06:00:00Z"
            ),
            "source_content_hash": (
                "a" * 64
            ),
            "source_generated_at": (
                "2026-08-27T05:55:00Z"
            ),
            "source_last_intake_at": (
                "2026-08-27T06:00:00Z"
            ),
            "counts": {
                "observed": 0,
                "candidate": (
                    1
                    if decision == "candidate"
                    else 0
                ),
                "observe_only": 0,
                "rejected": 0,
            },
            "candidates": {
                "candidate-1": (
                    self.classification_entry(
                        decision=decision,
                        maturity_state=(
                            maturity_state
                        ),
                    )
                ),
            },
        }

    def dns_state(self) -> dict:
        return {
            "version": 2,
            "updated_at": (
                "2026-08-27T06:00:00Z"
            ),
            "hosts": {},
        }

    def policy(self) -> dict:
        return {
            "enabled": True,
            "allow": [],
            "exclude": [],
        }

    def enabled_settings(self) -> dict:
        return {
            "enabled": True,
        }

    def test_state_snapshot_reports_eligible(
        self,
    ) -> None:
        result = (
            evaluate_exact_promotion_state(
                self.runtime_state(),
                self.classification_state(),
                self.dns_state(),
                self.policy(),
                self.now(),
                settings=(
                    self.enabled_settings()
                ),
            )
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
            "youtube",
        )

        self.assertEqual(
            result["counts"],
            {
                "hold": 0,
                "eligible": 1,
            },
        )

        self.assertEqual(
            result["candidates"][
                "candidate-1"
            ]["state"],
            "eligible",
        )

    def test_disabled_state_snapshot_holds(
        self,
    ) -> None:
        result = (
            evaluate_exact_promotion_state(
                self.runtime_state(),
                self.classification_state(),
                self.dns_state(),
                self.policy(),
                self.now(),
            )
        )

        self.assertEqual(
            result["counts"],
            {
                "hold": 1,
                "eligible": 0,
            },
        )

        self.assertEqual(
            result["candidates"][
                "candidate-1"
            ]["reason"],
            "exact_promotion_disabled",
        )

    def test_tracking_maturity_holds(
        self,
    ) -> None:
        result = (
            evaluate_exact_promotion_state(
                self.runtime_state(),
                self.classification_state(
                    maturity_state="tracking",
                ),
                self.dns_state(),
                self.policy(),
                self.now(),
                settings=(
                    self.enabled_settings()
                ),
            )
        )

        self.assertEqual(
            result["counts"],
            {
                "hold": 1,
                "eligible": 0,
            },
        )

        self.assertEqual(
            result["candidates"][
                "candidate-1"
            ]["reason"],
            "exact_promotion_maturity_not_ready",
        )

    def test_source_hash_mismatch_fails_closed(
        self,
    ) -> None:
        classification = (
            self.classification_state()
        )

        classification[
            "source_content_hash"
        ] = "b" * 64

        with self.assertRaises(
            ValueError
        ):
            evaluate_exact_promotion_state(
                self.runtime_state(),
                classification,
                self.dns_state(),
                self.policy(),
                self.now(),
                settings=(
                    self.enabled_settings()
                ),
            )

    def test_service_mismatch_fails_closed(
        self,
    ) -> None:
        classification = (
            self.classification_state()
        )

        classification[
            "service"
        ] = "netflix"

        with self.assertRaises(
            ValueError
        ):
            evaluate_exact_promotion_state(
                self.runtime_state(),
                classification,
                self.dns_state(),
                self.policy(),
                self.now(),
                settings=(
                    self.enabled_settings()
                ),
            )

    def test_candidate_set_mismatch_fails_closed(
        self,
    ) -> None:
        classification = (
            self.classification_state()
        )

        classification[
            "candidates"
        ] = {}

        with self.assertRaises(
            ValueError
        ):
            evaluate_exact_promotion_state(
                self.runtime_state(),
                classification,
                self.dns_state(),
                self.policy(),
                self.now(),
                settings=(
                    self.enabled_settings()
                ),
            )

    def test_runtime_candidate_id_mismatch_fails_closed(
        self,
    ) -> None:
        runtime_state = (
            self.runtime_state()
        )

        runtime_state[
            "candidates"
        ][
            "candidate-1"
        ][
            "candidate_id"
        ] = "candidate-other"

        with self.assertRaises(
            ValueError
        ):
            evaluate_exact_promotion_state(
                runtime_state,
                self.classification_state(),
                self.dns_state(),
                self.policy(),
                self.now(),
                settings=(
                    self.enabled_settings()
                ),
            )

    def test_invalid_classified_at_fails_closed(
        self,
    ) -> None:
        classification = (
            self.classification_state()
        )

        classification[
            "classified_at"
        ] = "not-a-timestamp"

        with self.assertRaises(
            ValueError
        ):
            evaluate_exact_promotion_state(
                self.runtime_state(),
                classification,
                self.dns_state(),
                self.policy(),
                self.now(),
                settings=(
                    self.enabled_settings()
                ),
            )

    def test_state_evaluation_does_not_mutate_inputs(
        self,
    ) -> None:
        runtime_state = (
            self.runtime_state()
        )

        classification = (
            self.classification_state()
        )

        dns_state = self.dns_state()
        policy = self.policy()

        before = copy.deepcopy(
            (
                runtime_state,
                classification,
                dns_state,
                policy,
            )
        )

        evaluate_exact_promotion_state(
            runtime_state,
            classification,
            dns_state,
            policy,
            self.now(),
            settings=(
                self.enabled_settings()
            ),
        )

        self.assertEqual(
            (
                runtime_state,
                classification,
                dns_state,
                policy,
            ),
            before,
        )

    def test_dry_run_computes_without_writing(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state_path = (
                Path(tmp)
                / "runtime_candidate_"
                "exact_promotion.json"
            )

            result = (
                write_exact_promotion_snapshot(
                    self.runtime_state(),
                    self.classification_state(),
                    self.dns_state(),
                    self.policy(),
                    state_path,
                    True,
                    self.now(),
                    settings=(
                        self.enabled_settings()
                    ),
                )
            )

            self.assertEqual(
                result["status"],
                "ok",
            )

            self.assertFalse(
                result["written"]
            )

            self.assertTrue(
                result["dry_run"]
            )

            self.assertFalse(
                state_path.exists()
            )

            self.assertEqual(
                result["state"][
                    "counts"
                ][
                    "eligible"
                ],
                1,
            )

    def test_normal_run_writes_shadow_snapshot(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state_path = (
                Path(tmp)
                / "runtime_candidate_"
                "exact_promotion.json"
            )

            result = (
                write_exact_promotion_snapshot(
                    self.runtime_state(),
                    self.classification_state(),
                    self.dns_state(),
                    self.policy(),
                    state_path,
                    False,
                    self.now(),
                    settings=(
                        self.enabled_settings()
                    ),
                )
            )

            self.assertEqual(
                result["status"],
                "ok",
            )

            self.assertTrue(
                result["written"]
            )

            self.assertTrue(
                state_path.exists()
            )

            persisted = json.loads(
                state_path.read_text(
                    encoding="utf-8"
                )
            )

            self.assertEqual(
                persisted[
                    "counts"
                ],
                {
                    "hold": 0,
                    "eligible": 1,
                },
            )

    def test_invalid_state_never_overwrites_snapshot(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state_path = (
                Path(tmp)
                / "runtime_candidate_"
                "exact_promotion.json"
            )

            original = {
                "preserve": True,
            }

            state_path.write_text(
                json.dumps(
                    original
                ),
                encoding="utf-8",
            )

            classification = (
                self.classification_state()
            )

            classification[
                "source_content_hash"
            ] = "b" * 64

            result = (
                write_exact_promotion_snapshot(
                    self.runtime_state(),
                    classification,
                    self.dns_state(),
                    self.policy(),
                    state_path,
                    False,
                    self.now(),
                    settings=(
                        self.enabled_settings()
                    ),
                )
            )

            self.assertEqual(
                result["status"],
                "state_error",
            )

            self.assertFalse(
                result["written"]
            )

            persisted = json.loads(
                state_path.read_text(
                    encoding="utf-8"
                )
            )

            self.assertEqual(
                persisted,
                original,
            )

    def test_write_error_is_isolated(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state_path = (
                Path(tmp)
                / "runtime_candidate_"
                "exact_promotion.json"
            )

            with patch(
                "dns_maintenance."
                "runtime_candidate_exact_promotion_state."
                "save_json",
                side_effect=OSError(
                    "write failed"
                ),
            ):
                result = (
                    write_exact_promotion_snapshot(
                        self.runtime_state(),
                        self.classification_state(),
                        self.dns_state(),
                        self.policy(),
                        state_path,
                        False,
                        self.now(),
                        settings=(
                            self.enabled_settings()
                        ),
                    )
                )

            self.assertEqual(
                result["status"],
                "write_error",
            )

            self.assertFalse(
                result["written"]
            )

            self.assertIn(
                "write failed",
                result["error"],
            )


if __name__ == "__main__":
    unittest.main()
