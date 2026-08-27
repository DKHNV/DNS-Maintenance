from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from dns_maintenance.config import (
    collection_paths,
    load_config,
    runtime_candidate_exact_promotion_settings,
)


class RuntimeCandidateExactPromotionConfigTests(
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
            },
        }

    def test_exact_promotion_is_disabled_by_default(
        self,
    ) -> None:
        collection = self.collection()

        collection[
            "runtime_candidate"
        ].pop(
            "exact_promotion"
        )

        result = (
            runtime_candidate_exact_promotion_settings(
                collection
            )
        )

        self.assertEqual(
            result,
            {
                "enabled": False,
            },
        )

    def test_exact_promotion_can_be_enabled(
        self,
    ) -> None:
        result = (
            runtime_candidate_exact_promotion_settings(
                self.collection()
            )
        )

        self.assertEqual(
            result,
            {
                "enabled": True,
            },
        )

    def test_exact_promotion_requires_runtime_intake(
        self,
    ) -> None:
        collection = self.collection()

        collection[
            "runtime_candidate"
        ][
            "enabled"
        ] = False

        with self.assertRaisesRegex(
            ValueError,
            "exact_promotion.enabled requires "
            "runtime_candidate.enabled",
        ):
            runtime_candidate_exact_promotion_settings(
                collection
            )

    def test_exact_promotion_requires_classification(
        self,
    ) -> None:
        collection = self.collection()

        collection[
            "runtime_candidate"
        ][
            "classification"
        ][
            "enabled"
        ] = False

        with self.assertRaisesRegex(
            ValueError,
            "exact_promotion.enabled requires "
            "runtime_candidate.classification.enabled",
        ):
            runtime_candidate_exact_promotion_settings(
                collection
            )

    def test_exact_promotion_requires_eligibility(
        self,
    ) -> None:
        collection = self.collection()

        collection[
            "runtime_candidate"
        ][
            "classification"
        ][
            "candidate_eligibility"
        ][
            "enabled"
        ] = False

        with self.assertRaisesRegex(
            ValueError,
            "candidate_eligibility.enabled",
        ):
            runtime_candidate_exact_promotion_settings(
                collection
            )

    def test_exact_promotion_requires_maturity(
        self,
    ) -> None:
        collection = self.collection()

        collection[
            "runtime_candidate"
        ][
            "classification"
        ][
            "candidate_maturity"
        ][
            "enabled"
        ] = False

        with self.assertRaisesRegex(
            ValueError,
            "candidate_maturity.enabled",
        ):
            runtime_candidate_exact_promotion_settings(
                collection
            )

    def test_exact_promotion_enabled_must_be_boolean(
        self,
    ) -> None:
        collection = self.collection()

        collection[
            "runtime_candidate"
        ][
            "exact_promotion"
        ][
            "enabled"
        ] = 1

        with self.assertRaises(
            ValueError
        ):
            runtime_candidate_exact_promotion_settings(
                collection
            )

    def test_unknown_exact_promotion_setting_fails_closed(
        self,
    ) -> None:
        collection = self.collection()

        collection[
            "runtime_candidate"
        ][
            "exact_promotion"
        ][
            "write_exact_dns"
        ] = True

        with self.assertRaises(
            ValueError
        ):
            runtime_candidate_exact_promotion_settings(
                collection
            )

    def test_exact_promotion_path_is_managed_data_path(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            paths = collection_paths(
                Path(tmp),
                self.collection(),
            )

            self.assertTrue(
                str(
                    paths.runtime_candidate_exact_promotion
                ).endswith(
                    "dns/youtube/"
                    "runtime_candidate_exact_promotion.json"
                )
            )

    def test_load_config_validates_exact_promotion(
        self,
    ) -> None:
        collection = self.collection()

        collection[
            "runtime_candidate"
        ][
            "classification"
        ][
            "candidate_maturity"
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
                "candidate_maturity.enabled",
            ):
                load_config(
                    path
                )

    def test_load_config_accepts_valid_exact_promotion(
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

        self.assertEqual(
            loaded[
                "collections"
            ][0][
                "runtime_candidate"
            ][
                "exact_promotion"
            ],
            {
                "enabled": True,
            },
        )


if __name__ == "__main__":
    unittest.main()
