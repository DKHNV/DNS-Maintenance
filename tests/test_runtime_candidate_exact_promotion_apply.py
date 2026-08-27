from __future__ import annotations

import copy
import json
import tempfile
import unittest
from datetime import (
    datetime,
    timezone,
)
from pathlib import Path
from unittest.mock import patch

from dns_maintenance.runtime_candidate_exact_promotion_apply import (
    EXACT_PROMOTION_APPLY_SOURCE,
    apply_exact_promotion_pending,
    evaluate_exact_promotion_apply,
    exact_promotion_apply_settings,
)
from dns_maintenance.runtime_candidate_exact_promotion_state import (
    evaluate_exact_promotion_state,
)


NOW = datetime(
    2026,
    8,
    28,
    8,
    0,
    tzinfo=timezone.utc,
)


class RuntimeCandidateExactPromotionApplyTests(
    unittest.TestCase
):
    def candidate(self) -> dict:
        return {
            "candidate_id": (
                "candidate-1"
            ),
            "hostname": (
                "video.example.com"
            ),
            "suffix": (
                "example.com"
            ),
            "state": "observed",
            "feed_present": True,
            "current_presence": True,
            "current_routing_status": (
                "active"
            ),
            "observation_count": 5,
            "presence_cycles": 100,
            "active_cycles": 50,
            "reactivation_count": 1,
            "seen_dates": [
                "2026-08-25",
                "2026-08-26",
                "2026-08-27",
            ],
        }

    def runtime_state(self) -> dict:
        return {
            "service": "youtube",
            "source_content_hash": (
                "a" * 64
            ),
            "source_generated_at": (
                "2026-08-28T07:55:00Z"
            ),
            "last_intake_at": (
                "2026-08-28T08:00:00Z"
            ),
            "candidates": {
                "candidate-1": (
                    self.candidate()
                ),
            },
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
                "2026-08-26T08:00:00Z"
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
    ) -> dict:
        return {
            "version": 1,
            "mode": "shadow",
            "classified_at": (
                "2026-08-28T08:00:00Z"
            ),
            "decision": "candidate",
            "reason": (
                "candidate_retained"
            ),
            "policy_reason": None,
            "eligibility": {
                "version": 1,
                "mode": "shadow",
                "decision": "candidate",
                "reason": (
                    "candidate_eligibility_met"
                ),
                "criteria": {
                    "enabled": True,
                    "min_seen_days": 2,
                    "min_observation_count": 2,
                },
                "evidence": {
                    "feed_present": True,
                    "seen_days": 3,
                    "observation_count": 5,
                },
            },
            "maturity": (
                self.ready_maturity()
            ),
            "evidence": {
                "feed_present": True,
                "current_presence": True,
                "current_routing_status": (
                    "active"
                ),
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

    def classification_state(
        self,
    ) -> dict:
        return {
            "version": 1,
            "mode": "shadow",
            "service": "youtube",
            "classified_at": (
                "2026-08-28T08:00:00Z"
            ),
            "source_content_hash": (
                "a" * 64
            ),
            "source_generated_at": (
                "2026-08-28T07:55:00Z"
            ),
            "source_last_intake_at": (
                "2026-08-28T08:00:00Z"
            ),
            "counts": {
                "observed": 0,
                "candidate": 1,
                "observe_only": 0,
                "rejected": 0,
            },
            "candidates": {
                "candidate-1": (
                    self.classification_entry()
                ),
            },
        }

    def dns_state(self) -> dict:
        return {
            "version": 2,
            "updated_at": (
                "2026-08-28T08:00:00Z"
            ),
            "hosts": {},
        }

    def policy(self) -> dict:
        return {
            "enabled": True,
            "allow": [],
            "exclude": [],
        }

    def promotion_state(
        self,
        *,
        dns_state: dict | None = None,
        policy: dict | None = None,
    ) -> dict:
        return (
            evaluate_exact_promotion_state(
                self.runtime_state(),
                self.classification_state(),
                (
                    self.dns_state()
                    if dns_state is None
                    else dns_state
                ),
                (
                    self.policy()
                    if policy is None
                    else policy
                ),
                NOW,
                settings={
                    "enabled": True,
                },
            )
        )

    def enabled_settings(
        self,
    ) -> dict:
        return {
            "enabled": True,
        }

    def test_apply_is_disabled_by_default(
        self,
    ) -> None:
        self.assertEqual(
            exact_promotion_apply_settings(
                None
            ),
            {
                "enabled": False,
            },
        )

    def test_apply_enabled_must_be_boolean(
        self,
    ) -> None:
        with self.assertRaises(
            ValueError
        ):
            exact_promotion_apply_settings(
                {
                    "enabled": 1,
                }
            )

    def test_unknown_apply_setting_fails_closed(
        self,
    ) -> None:
        with self.assertRaises(
            ValueError
        ):
            exact_promotion_apply_settings(
                {
                    "enabled": False,
                    "publish_active": True,
                }
            )

    def test_eligible_candidate_creates_pending(
        self,
    ) -> None:
        dns_state = self.dns_state()

        result = (
            evaluate_exact_promotion_apply(
                self.runtime_state(),
                self.classification_state(),
                self.promotion_state(),
                dns_state,
                self.policy(),
                NOW,
                settings=(
                    self.enabled_settings()
                ),
            )
        )

        self.assertEqual(
            result["counts"],
            {
                "hold": 0,
                "created_pending": 1,
            },
        )

        candidate_result = (
            result["candidates"][
                "candidate-1"
            ]
        )

        self.assertEqual(
            candidate_result["action"],
            "created_pending",
        )

        exact_entry = (
            result["dns_state"][
                "hosts"
            ][
                "video.example.com"
            ]
        )

        self.assertEqual(
            exact_entry["status"],
            "pending",
        )

        self.assertFalse(
            exact_entry[
                "ever_validated"
            ]
        )

        self.assertEqual(
            exact_entry[
                "last_result"
            ],
            "UNTESTED",
        )

        self.assertEqual(
            exact_entry[
                "sources"
            ],
            [
                EXACT_PROMOTION_APPLY_SOURCE
            ],
        )

        self.assertEqual(
            exact_entry[
                "runtime_promotion"
            ][
                "candidate_id"
            ],
            "candidate-1",
        )

        self.assertEqual(
            exact_entry[
                "runtime_promotion"
            ][
                "source_content_hash"
            ],
            "a" * 64,
        )

        self.assertEqual(
            result[
                "pending_hosts"
            ],
            [
                "video.example.com"
            ],
        )

    def test_apply_does_not_mutate_input_dns_state(
        self,
    ) -> None:
        dns_state = self.dns_state()

        before = copy.deepcopy(
            dns_state
        )

        evaluate_exact_promotion_apply(
            self.runtime_state(),
            self.classification_state(),
            self.promotion_state(),
            dns_state,
            self.policy(),
            NOW,
            settings=(
                self.enabled_settings()
            ),
        )

        self.assertEqual(
            dns_state,
            before,
        )

    def test_disabled_apply_holds_eligible_candidate(
        self,
    ) -> None:
        result = (
            evaluate_exact_promotion_apply(
                self.runtime_state(),
                self.classification_state(),
                self.promotion_state(),
                self.dns_state(),
                self.policy(),
                NOW,
            )
        )

        self.assertEqual(
            result["counts"],
            {
                "hold": 1,
                "created_pending": 0,
            },
        )

        self.assertEqual(
            result["candidates"][
                "candidate-1"
            ]["reason"],
            "exact_promotion_apply_disabled",
        )

        self.assertNotIn(
            "video.example.com",
            result["dns_state"][
                "hosts"
            ],
        )

    def test_stored_shadow_hold_blocks_apply(
        self,
    ) -> None:
        promotion = (
            self.promotion_state()
        )

        entry = (
            promotion[
                "candidates"
            ][
                "candidate-1"
            ]
        )

        entry["state"] = "hold"
        entry["reason"] = (
            "exact_promotion_disabled"
        )

        result = (
            evaluate_exact_promotion_apply(
                self.runtime_state(),
                self.classification_state(),
                promotion,
                self.dns_state(),
                self.policy(),
                NOW,
                settings=(
                    self.enabled_settings()
                ),
            )
        )

        self.assertEqual(
            result["counts"][
                "created_pending"
            ],
            0,
        )

        self.assertEqual(
            result["candidates"][
                "candidate-1"
            ]["reason"],
            "exact_promotion_apply_"
            "shadow_not_eligible",
        )

    def test_policy_change_blocks_stale_eligible(
        self,
    ) -> None:
        promotion = (
            self.promotion_state()
        )

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
            },
        ]

        result = (
            evaluate_exact_promotion_apply(
                self.runtime_state(),
                self.classification_state(),
                promotion,
                self.dns_state(),
                policy,
                NOW,
                settings=(
                    self.enabled_settings()
                ),
            )
        )

        self.assertEqual(
            result["counts"][
                "created_pending"
            ],
            0,
        )

        candidate = (
            result["candidates"][
                "candidate-1"
            ]
        )

        self.assertEqual(
            candidate["reason"],
            "exact_promotion_apply_"
            "recheck_not_eligible",
        )

        self.assertTrue(
            candidate[
                "evidence"
            ][
                "policy_excluded"
            ]
        )

    def test_existing_exact_dns_blocks_stale_eligible(
        self,
    ) -> None:
        promotion = (
            self.promotion_state()
        )

        dns_state = (
            self.dns_state()
        )

        dns_state[
            "hosts"
        ][
            "video.example.com"
        ] = {
            "hostname": (
                "video.example.com"
            ),
            "status": "pending",
            "ever_validated": False,
            "sources": [
                "manual"
            ],
        }

        result = (
            evaluate_exact_promotion_apply(
                self.runtime_state(),
                self.classification_state(),
                promotion,
                dns_state,
                self.policy(),
                NOW,
                settings=(
                    self.enabled_settings()
                ),
            )
        )

        self.assertEqual(
            result["counts"][
                "created_pending"
            ],
            0,
        )

        candidate = (
            result["candidates"][
                "candidate-1"
            ]
        )

        self.assertEqual(
            candidate["reason"],
            "exact_promotion_apply_"
            "recheck_not_eligible",
        )

        self.assertTrue(
            candidate[
                "evidence"
            ][
                "exact_dns_present"
            ]
        )

    def test_source_hash_mismatch_fails_closed(
        self,
    ) -> None:
        promotion = (
            self.promotion_state()
        )

        promotion[
            "source_content_hash"
        ] = "b" * 64

        with self.assertRaises(
            ValueError
        ):
            evaluate_exact_promotion_apply(
                self.runtime_state(),
                self.classification_state(),
                promotion,
                self.dns_state(),
                self.policy(),
                NOW,
                settings=(
                    self.enabled_settings()
                ),
            )

    def test_classified_at_mismatch_fails_closed(
        self,
    ) -> None:
        promotion = (
            self.promotion_state()
        )

        promotion[
            "source_classified_at"
        ] = (
            "2026-08-28T07:00:00Z"
        )

        with self.assertRaises(
            ValueError
        ):
            evaluate_exact_promotion_apply(
                self.runtime_state(),
                self.classification_state(),
                promotion,
                self.dns_state(),
                self.policy(),
                NOW,
                settings=(
                    self.enabled_settings()
                ),
            )

    def test_candidate_set_mismatch_fails_closed(
        self,
    ) -> None:
        promotion = (
            self.promotion_state()
        )

        promotion[
            "candidates"
        ] = {}

        with self.assertRaises(
            ValueError
        ):
            evaluate_exact_promotion_apply(
                self.runtime_state(),
                self.classification_state(),
                promotion,
                self.dns_state(),
                self.policy(),
                NOW,
                settings=(
                    self.enabled_settings()
                ),
            )

    def test_invalid_eligible_reason_fails_closed(
        self,
    ) -> None:
        promotion = (
            self.promotion_state()
        )

        promotion[
            "candidates"
        ][
            "candidate-1"
        ][
            "reason"
        ] = "manually-forced"

        with self.assertRaises(
            ValueError
        ):
            evaluate_exact_promotion_apply(
                self.runtime_state(),
                self.classification_state(),
                promotion,
                self.dns_state(),
                self.policy(),
                NOW,
                settings=(
                    self.enabled_settings()
                ),
            )

    def test_dry_run_computes_pending_without_writes(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)

            state_path = (
                root
                / "state.json"
            )

            pending_path = (
                root
                / "pending.txt"
            )

            result = (
                apply_exact_promotion_pending(
                    self.runtime_state(),
                    self.classification_state(),
                    self.promotion_state(),
                    self.dns_state(),
                    self.policy(),
                    state_path,
                    pending_path,
                    True,
                    NOW,
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

            self.assertEqual(
                result["result"][
                    "counts"
                ][
                    "created_pending"
                ],
                1,
            )

            self.assertFalse(
                state_path.exists()
            )

            self.assertFalse(
                pending_path.exists()
            )

    def test_normal_run_writes_only_exact_pending_state(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)

            state_path = (
                root
                / "state.json"
            )

            pending_path = (
                root
                / "pending.txt"
            )

            result = (
                apply_exact_promotion_pending(
                    self.runtime_state(),
                    self.classification_state(),
                    self.promotion_state(),
                    self.dns_state(),
                    self.policy(),
                    state_path,
                    pending_path,
                    False,
                    NOW,
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

            persisted = json.loads(
                state_path.read_text(
                    encoding="utf-8"
                )
            )

            exact_entry = (
                persisted[
                    "hosts"
                ][
                    "video.example.com"
                ]
            )

            self.assertEqual(
                exact_entry["status"],
                "pending",
            )

            self.assertFalse(
                exact_entry[
                    "ever_validated"
                ]
            )

            self.assertEqual(
                pending_path.read_text(
                    encoding="utf-8"
                ),
                "video.example.com\n",
            )

    def test_no_created_pending_means_no_write(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)

            state_path = (
                root
                / "state.json"
            )

            pending_path = (
                root
                / "pending.txt"
            )

            result = (
                apply_exact_promotion_pending(
                    self.runtime_state(),
                    self.classification_state(),
                    self.promotion_state(),
                    self.dns_state(),
                    self.policy(),
                    state_path,
                    pending_path,
                    False,
                    NOW,
                )
            )

            self.assertEqual(
                result["status"],
                "ok",
            )

            self.assertFalse(
                result["written"]
            )

            self.assertFalse(
                state_path.exists()
            )

            self.assertFalse(
                pending_path.exists()
            )

    def test_write_error_is_isolated(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)

            state_path = (
                root
                / "state.json"
            )

            pending_path = (
                root
                / "pending.txt"
            )

            with patch(
                "dns_maintenance."
                "runtime_candidate_exact_promotion_apply."
                "save_json",
                side_effect=OSError(
                    "disk failed"
                ),
            ):
                result = (
                    apply_exact_promotion_pending(
                        self.runtime_state(),
                        self.classification_state(),
                        self.promotion_state(),
                        self.dns_state(),
                        self.policy(),
                        state_path,
                        pending_path,
                        False,
                        NOW,
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
                "disk failed",
                result["error"],
            )


if __name__ == "__main__":
    unittest.main()
