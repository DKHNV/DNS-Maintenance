from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from dns_maintenance.config import (
    load_config,
    runtime_candidate_exact_promotion_apply_settings,
)


class RuntimeCandidateExactPromotionApplyConfigTests(
    unittest.TestCase
):
    def collection(self) -> dict:
        return {
            "name": "youtube",
            "active_file": "YouTube_DNS",
            "data_dir": "dns/youtube",
            "runtime_candidate": {
                "enabled": True,
                "classification": {
                    "enabled": True,
                    "candidate_eligibility": {
                        "enabled": True,
                        "min_seen_days": 2,
                        "min_observation_count": 2,
                    },
                    "candidate_maturity": {
                        "enabled": True,
                        "min_candidate_age_hours": 24,
                        "min_additional_seen_days": 1,
                        "min_additional_observation_count": 1,
                    },
                },
                "exact_promotion": {
                    "enabled": True,
                },
                "exact_promotion_apply": {
                    "enabled": True,
                },
            },
        }

    def test_apply_is_disabled_by_default(
        self,
    ) -> None:
        collection = self.collection()

        collection[
            "runtime_candidate"
        ].pop(
            "exact_promotion_apply"
        )

        result = (
            runtime_candidate_exact_promotion_apply_settings(
                collection
            )
        )

        self.assertEqual(
            result,
            {
                "enabled": False,
            },
        )

    def test_apply_can_be_enabled(
        self,
    ) -> None:
        result = (
            runtime_candidate_exact_promotion_apply_settings(
                self.collection()
            )
        )

        self.assertEqual(
            result,
            {
                "enabled": True,
            },
        )

    def test_apply_requires_exact_promotion(
        self,
    ) -> None:
        collection = self.collection()

        collection[
            "runtime_candidate"
        ][
            "exact_promotion"
        ][
            "enabled"
        ] = False

        with self.assertRaisesRegex(
            ValueError,
            "exact_promotion_apply.enabled requires "
            "runtime_candidate.exact_promotion.enabled",
        ):
            runtime_candidate_exact_promotion_apply_settings(
                collection
            )

    def test_apply_requires_exact_promotion_when_missing(
        self,
    ) -> None:
        collection = self.collection()

        collection[
            "runtime_candidate"
        ].pop(
            "exact_promotion"
        )

        with self.assertRaisesRegex(
            ValueError,
            "exact_promotion_apply.enabled requires "
            "runtime_candidate.exact_promotion.enabled",
        ):
            runtime_candidate_exact_promotion_apply_settings(
                collection
            )

    def test_apply_enabled_must_be_boolean(
        self,
    ) -> None:
        collection = self.collection()

        collection[
            "runtime_candidate"
        ][
            "exact_promotion_apply"
        ][
            "enabled"
        ] = 1

        with self.assertRaises(
            ValueError
        ):
            runtime_candidate_exact_promotion_apply_settings(
                collection
            )

    def test_unknown_apply_setting_fails_closed(
        self,
    ) -> None:
        collection = self.collection()

        collection[
            "runtime_candidate"
        ][
            "exact_promotion_apply"
        ][
            "publish_active"
        ] = True

        with self.assertRaises(
            ValueError
        ):
            runtime_candidate_exact_promotion_apply_settings(
                collection
            )

    def test_disabled_apply_does_not_require_promotion(
        self,
    ) -> None:
        collection = self.collection()

        collection[
            "runtime_candidate"
        ][
            "exact_promotion"
        ][
            "enabled"
        ] = False

        collection[
            "runtime_candidate"
        ][
            "exact_promotion_apply"
        ][
            "enabled"
        ] = False

        result = (
            runtime_candidate_exact_promotion_apply_settings(
                collection
            )
        )

        self.assertEqual(
            result,
            {
                "enabled": False,
            },
        )

    def test_load_config_rejects_apply_without_promotion(
        self,
    ) -> None:
        collection = self.collection()

        collection[
            "runtime_candidate"
        ][
            "exact_promotion"
        ][
            "enabled"
        ] = False

        config = {
            "version": 1,
            "collections": [
                collection
            ],
        }

        with tempfile.TemporaryDirectory() as tmp:
            path = (
                Path(tmp)
                / "dns-maintenance-v1.json"
            )

            path.write_text(
                json.dumps(
                    config
                ),
                encoding="utf-8",
            )

            with self.assertRaisesRegex(
                ValueError,
                "exact_promotion_apply.enabled requires "
                "runtime_candidate.exact_promotion.enabled",
            ):
                load_config(
                    path
                )

    def test_load_config_accepts_valid_apply(
        self,
    ) -> None:
        config = {
            "version": 1,
            "collections": [
                self.collection()
            ],
        }

        with tempfile.TemporaryDirectory() as tmp:
            path = (
                Path(tmp)
                / "dns-maintenance-v1.json"
            )

            path.write_text(
                json.dumps(
                    config
                ),
                encoding="utf-8",
            )

            loaded = load_config(
                path
            )

        runtime_cfg = (
            loaded[
                "collections"
            ][0][
                "runtime_candidate"
            ]
        )

        self.assertEqual(
            runtime_cfg[
                "exact_promotion"
            ],
            {
                "enabled": True,
            },
        )

        self.assertEqual(
            runtime_cfg[
                "exact_promotion_apply"
            ],
            {
                "enabled": True,
            },
        )


if __name__ == "__main__":
    unittest.main()
