from __future__ import annotations

import io
import tempfile
import unittest
from contextlib import redirect_stdout
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

from dns_maintenance.config import (
    runtime_candidate_maturity_settings,
)
from dns_maintenance.runner import run
from dns_maintenance.runtime_candidate_classification import (
    classify_runtime_candidate,
    classify_runtime_candidate_state,
    write_runtime_candidate_classification_snapshot,
)


NOW = datetime(
    2026,
    8,
    25,
    18,
    0,
    tzinfo=timezone.utc,
)


def candidate() -> dict:
    return {
        "candidate_id": "candidate-1",
        "hostname": "video.example.com",
        "suffix": "example.com",
        "state": "observed",
        "first_intake_at": "2026-08-25T10:00:00Z",
        "last_intake_at": "2026-08-25T17:00:00Z",
        "feed_present": True,
        "first_observed": "2026-08-24T08:00:00Z",
        "last_observed": "2026-08-25T17:00:00Z",
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
        "last_external_at": "2026-08-25T17:00:00Z",
    }


def runtime_state(
    item: dict | None = None,
) -> dict:
    runtime_candidate = (
        candidate()
        if item is None
        else item
    )

    return {
        "schema_version": 1,
        "service": "demo",
        "source_content_hash": "a" * 64,
        "source_generated_at": "2026-08-25T17:00:00Z",
        "last_intake_at": "2026-08-25T17:30:00Z",
        "candidates": {
            runtime_candidate["candidate_id"]:
                runtime_candidate,
        },
    }


def policy_disabled() -> dict:
    return {
        "enabled": False,
        "allow": [],
        "exclude": [],
    }


def policy_excluding_example() -> dict:
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


def eligibility_enabled() -> dict:
    return {
        "enabled": True,
        "min_seen_days": 2,
        "min_observation_count": 2,
    }


def maturity_enabled() -> dict:
    return {
        "enabled": True,
        "min_candidate_age_hours": 24,
        "min_additional_seen_days": 1,
        "min_additional_observation_count": 1,
    }


def maturity_tracking() -> dict:
    return {
        "version": 1,
        "mode": "shadow",
        "state": "tracking",
        "reason": "candidate_maturity_tracking_started",
        "candidate_since": "2026-08-24T18:00:00Z",
        "criteria": maturity_enabled(),
        "baseline": {
            "seen_days": 2,
            "observation_count": 3,
        },
        "evidence": {
            "feed_present": True,
            "candidate_age_hours": 0.0,
            "seen_days": 2,
            "observation_count": 3,
            "additional_seen_days": 0,
            "additional_observation_count": 0,
        },
    }


class RuntimeCandidateMaturityConfigTests(
    unittest.TestCase
):
    def collection(self) -> dict:
        return {
            "name": "demo",
            "active_file": "Demo_DNS",
            "data_dir": "dns/demo",
        }

    def test_maturity_is_disabled_by_default(
        self,
    ) -> None:
        self.assertEqual(
            runtime_candidate_maturity_settings(
                self.collection()
            ),
            {
                "enabled": False,
                "min_candidate_age_hours": 24.0,
                "min_additional_seen_days": 1,
                "min_additional_observation_count": 1,
            },
        )

    def test_maturity_can_be_enabled(
        self,
    ) -> None:
        collection = self.collection()
        collection["runtime_candidate"] = {
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
                    "min_candidate_age_hours": 48,
                    "min_additional_seen_days": 2,
                    "min_additional_observation_count": 3,
                },
            },
        }

        self.assertEqual(
            runtime_candidate_maturity_settings(
                collection
            ),
            {
                "enabled": True,
                "min_candidate_age_hours": 48.0,
                "min_additional_seen_days": 2,
                "min_additional_observation_count": 3,
            },
        )

    def test_maturity_requires_classification(
        self,
    ) -> None:
        collection = self.collection()
        collection["runtime_candidate"] = {
            "enabled": True,
            "classification": {
                "enabled": False,
                "candidate_eligibility": {
                    "enabled": True,
                },
                "candidate_maturity": {
                    "enabled": True,
                },
            },
        }

        with self.assertRaisesRegex(
            ValueError,
            "candidate_maturity.enabled requires",
        ):
            runtime_candidate_maturity_settings(
                collection
            )

    def test_maturity_requires_eligibility(
        self,
    ) -> None:
        collection = self.collection()
        collection["runtime_candidate"] = {
            "enabled": True,
            "classification": {
                "enabled": True,
                "candidate_eligibility": {
                    "enabled": False,
                },
                "candidate_maturity": {
                    "enabled": True,
                },
            },
        }

        with self.assertRaisesRegex(
            ValueError,
            "candidate_eligibility.enabled",
        ):
            runtime_candidate_maturity_settings(
                collection
            )

    def test_unknown_maturity_setting_fails_closed(
        self,
    ) -> None:
        collection = self.collection()
        collection["runtime_candidate"] = {
            "enabled": True,
            "classification": {
                "enabled": True,
                "candidate_eligibility": {
                    "enabled": True,
                },
                "candidate_maturity": {
                    "enabled": False,
                    "magic": 42,
                },
            },
        }

        with self.assertRaisesRegex(
            ValueError,
            "Unknown candidate_maturity",
        ):
            runtime_candidate_maturity_settings(
                collection
            )


class RuntimeCandidateMaturityClassificationTests(
    unittest.TestCase
):
    def test_first_candidate_cycle_starts_tracking(
        self,
    ) -> None:
        result = classify_runtime_candidate(
            candidate(),
            {"hosts": {}},
            policy_disabled(),
            NOW,
            candidate_eligibility_cfg=(
                eligibility_enabled()
            ),
            candidate_maturity_cfg=(
                maturity_enabled()
            ),
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
            result["maturity"]["state"],
            "tracking",
        )
        self.assertEqual(
            result["maturity"]["reason"],
            "candidate_maturity_tracking_started",
        )
        self.assertNotEqual(
            result["decision"],
            "promoted_exact",
        )

    def test_ready_maturity_still_is_candidate(
        self,
    ) -> None:
        item = candidate()
        item["seen_dates"].append(
            "2026-08-26"
        )
        item["observation_count"] = 4

        result = classify_runtime_candidate(
            item,
            {"hosts": {}},
            policy_disabled(),
            NOW + timedelta(hours=24),
            candidate_eligibility_cfg=(
                eligibility_enabled()
            ),
            candidate_maturity_cfg=(
                maturity_enabled()
            ),
            previous_decision="candidate",
            previous_maturity=(
                maturity_tracking()
            ),
        )

        self.assertEqual(
            result["decision"],
            "candidate",
        )
        self.assertEqual(
            result["maturity"]["state"],
            "ready",
        )
        self.assertEqual(
            result["maturity"]["reason"],
            "candidate_maturity_met",
        )
        self.assertNotIn(
            "promoted_exact",
            result,
        )

    def test_policy_exclusion_overrides_maturity(
        self,
    ) -> None:
        result = classify_runtime_candidate(
            candidate(),
            {"hosts": {}},
            policy_excluding_example(),
            NOW,
            candidate_eligibility_cfg=(
                eligibility_enabled()
            ),
            candidate_maturity_cfg=(
                maturity_enabled()
            ),
            previous_decision="candidate",
            previous_maturity=(
                maturity_tracking()
            ),
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
            "maturity",
            result,
        )

    def test_exact_dns_overrides_maturity(
        self,
    ) -> None:
        result = classify_runtime_candidate(
            candidate(),
            {
                "hosts": {
                    "video.example.com": {
                        "status": "pending",
                    }
                }
            },
            policy_disabled(),
            NOW,
            candidate_eligibility_cfg=(
                eligibility_enabled()
            ),
            candidate_maturity_cfg=(
                maturity_enabled()
            ),
            previous_decision="candidate",
            previous_maturity=(
                maturity_tracking()
            ),
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
            "maturity",
            result,
        )

    def test_state_snapshot_retains_tracking_history(
        self,
    ) -> None:
        previous_snapshot = {
            "version": 1,
            "mode": "shadow",
            "service": "demo",
            "candidates": {
                "candidate-1": {
                    "decision": "candidate",
                    "maturity": maturity_tracking(),
                }
            },
        }

        result = classify_runtime_candidate_state(
            runtime_state(),
            {"hosts": {}},
            policy_disabled(),
            NOW,
            candidate_eligibility_cfg=(
                eligibility_enabled()
            ),
            candidate_maturity_cfg=(
                maturity_enabled()
            ),
            previous_snapshot=(
                previous_snapshot
            ),
        )

        item = result["candidates"][
            "candidate-1"
        ]

        self.assertEqual(
            result["counts"]["candidate"],
            1,
        )
        self.assertEqual(
            item["decision"],
            "candidate",
        )
        self.assertEqual(
            item["maturity"]["state"],
            "tracking",
        )
        self.assertEqual(
            item["maturity"]["candidate_since"],
            "2026-08-24T18:00:00Z",
        )

    def test_malformed_persisted_maturity_fails_closed(
        self,
    ) -> None:
        previous_snapshot = {
            "version": 1,
            "mode": "shadow",
            "service": "demo",
            "candidates": {
                "candidate-1": {
                    "decision": "candidate",
                    "maturity": {
                        "version": 999,
                        "mode": "shadow",
                        "state": "tracking",
                        "candidate_since": (
                            "2026-08-24T18:00:00Z"
                        ),
                        "baseline": {
                            "seen_days": 2,
                            "observation_count": 3,
                        },
                    },
                }
            },
        }

        with self.assertRaisesRegex(
            ValueError,
            "version is unsupported",
        ):
            classify_runtime_candidate_state(
                runtime_state(),
                {"hosts": {}},
                policy_disabled(),
                NOW,
                candidate_eligibility_cfg=(
                    eligibility_enabled()
                ),
                candidate_maturity_cfg=(
                    maturity_enabled()
                ),
                previous_snapshot=(
                    previous_snapshot
                ),
            )


class RuntimeCandidateMaturityPersistenceTests(
    unittest.TestCase
):
    def test_snapshot_persists_maturity_history(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as td:
            path = (
                Path(td)
                / "runtime_candidate_classification.json"
            )

            first = (
                write_runtime_candidate_classification_snapshot(
                    runtime_state(),
                    {"hosts": {}},
                    policy_disabled(),
                    path,
                    False,
                    NOW,
                    candidate_eligibility_cfg=(
                        eligibility_enabled()
                    ),
                    candidate_maturity_cfg=(
                        maturity_enabled()
                    ),
                )
            )

            self.assertEqual(
                first["status"],
                "ok",
            )
            self.assertTrue(
                first["written"]
            )

            first_item = first["state"][
                "candidates"
            ]["candidate-1"]

            self.assertEqual(
                first_item["decision"],
                "candidate",
            )
            self.assertEqual(
                first_item["maturity"]["state"],
                "tracking",
            )

            second_candidate = candidate()
            second_candidate["seen_dates"].append(
                "2026-08-26"
            )
            second_candidate[
                "observation_count"
            ] = 4

            second = (
                write_runtime_candidate_classification_snapshot(
                    runtime_state(
                        second_candidate
                    ),
                    {"hosts": {}},
                    policy_disabled(),
                    path,
                    False,
                    NOW + timedelta(hours=24),
                    candidate_eligibility_cfg=(
                        eligibility_enabled()
                    ),
                    candidate_maturity_cfg=(
                        maturity_enabled()
                    ),
                )
            )

            self.assertEqual(
                second["status"],
                "ok",
            )

            second_item = second["state"][
                "candidates"
            ]["candidate-1"]

            self.assertEqual(
                second_item["decision"],
                "candidate",
            )
            self.assertEqual(
                second_item["maturity"]["state"],
                "ready",
            )

    def test_corrupt_previous_maturity_is_preserved(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as td:
            path = (
                Path(td)
                / "runtime_candidate_classification.json"
            )

            original = (
                '{"version":1,"mode":"shadow",'
                '"service":"demo","candidates":{'
                '"candidate-1":{"decision":"candidate",'
                '"maturity":{"version":999}}}}\n'
            )

            path.write_text(
                original,
                encoding="utf-8",
            )

            result = (
                write_runtime_candidate_classification_snapshot(
                    runtime_state(),
                    {"hosts": {}},
                    policy_disabled(),
                    path,
                    False,
                    NOW,
                    candidate_eligibility_cfg=(
                        eligibility_enabled()
                    ),
                    candidate_maturity_cfg=(
                        maturity_enabled()
                    ),
                )
            )

            self.assertEqual(
                result["status"],
                "state_error",
            )
            self.assertFalse(
                result["written"],
            )
            self.assertEqual(
                path.read_text(
                    encoding="utf-8"
                ),
                original,
            )


class RuntimeCandidateMaturityRunnerTests(
    unittest.TestCase
):
    def collection(self) -> dict:
        return {
            "name": "demo",
            "active_file": "Demo_DNS",
            "data_dir": "dns/demo",
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
            },
        }

    def test_runner_passes_maturity_and_reports_tracking(
        self,
    ) -> None:
        cfg = {
            "version": 1,
            "collections": [
                self.collection()
            ],
        }

        classification_state = {
            "counts": {
                "observed": 0,
                "candidate": 1,
                "observe_only": 0,
                "rejected": 0,
            },
            "candidates": {
                "candidate-1": {
                    "decision": "candidate",
                    "maturity": {
                        "state": "tracking",
                    },
                }
            },
        }

        classification_result = {
            "status": "ok",
            "written": False,
            "state": classification_state,
        }

        intake_result = {
            "status": "ok",
            "written": False,
            "state": runtime_state(),
        }

        with tempfile.TemporaryDirectory() as td:
            root = Path(td)

            output = io.StringIO()

            with (
                patch(
                    "dns_maintenance.runner."
                    "intake_runtime_candidate_feed",
                    return_value=intake_result,
                ),
                patch(
                    "dns_maintenance.runner.discover",
                    return_value=(
                        set(),
                        {},
                        False,
                    ),
                ),
                patch(
                    "dns_maintenance.runner.maintain_dns",
                    return_value=(
                        {"hosts": {}},
                        False,
                    ),
                ),
                patch(
                    "dns_maintenance.runner."
                    "apply_hostname_policy",
                    return_value=(
                        {"hosts": {}},
                        False,
                    ),
                ),
                patch(
                    "dns_maintenance.runner."
                    "write_runtime_candidate_classification_snapshot",
                    return_value=(
                        classification_result
                    ),
                ) as classification_mock,
                patch(
                    "dns_maintenance.runner.probe_services",
                    return_value=(
                        {},
                        False,
                    ),
                ),
                patch(
                    "dns_maintenance.runner.write_report",
                    return_value="report",
                ),
                redirect_stdout(output),
            ):
                result = run(
                    root,
                    cfg,
                    None,
                    True,
                )

        self.assertEqual(
            result,
            0,
        )

        self.assertEqual(
            classification_mock.call_count,
            1,
        )

        kwargs = (
            classification_mock.call_args.kwargs
        )

        self.assertEqual(
            kwargs["candidate_maturity_cfg"],
            maturity_enabled(),
        )

        text = output.getvalue()

        self.assertIn(
            "candidate=1",
            text,
        )
        self.assertIn(
            "maturity_tracking=1",
            text,
        )
        self.assertIn(
            "maturity_ready=0",
            text,
        )

    def test_runner_reports_ready_without_promotion(
        self,
    ) -> None:
        cfg = {
            "version": 1,
            "collections": [
                self.collection()
            ],
        }

        classification_result = {
            "status": "ok",
            "written": False,
            "state": {
                "counts": {
                    "observed": 0,
                    "candidate": 1,
                    "observe_only": 0,
                    "rejected": 0,
                },
                "candidates": {
                    "candidate-1": {
                        "decision": "candidate",
                        "maturity": {
                            "state": "ready",
                        },
                    }
                },
            },
        }

        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            output = io.StringIO()

            with (
                patch(
                    "dns_maintenance.runner."
                    "intake_runtime_candidate_feed",
                    return_value={
                        "status": "ok",
                        "written": False,
                        "state": runtime_state(),
                    },
                ),
                patch(
                    "dns_maintenance.runner.discover",
                    return_value=(
                        set(),
                        {},
                        False,
                    ),
                ),
                patch(
                    "dns_maintenance.runner.maintain_dns",
                    return_value=(
                        {"hosts": {}},
                        False,
                    ),
                ),
                patch(
                    "dns_maintenance.runner."
                    "apply_hostname_policy",
                    return_value=(
                        {"hosts": {}},
                        False,
                    ),
                ),
                patch(
                    "dns_maintenance.runner."
                    "write_runtime_candidate_classification_snapshot",
                    return_value=(
                        classification_result
                    ),
                ),
                patch(
                    "dns_maintenance.runner.probe_services",
                    return_value=(
                        {},
                        False,
                    ),
                ),
                patch(
                    "dns_maintenance.runner.write_report",
                    return_value="report",
                ),
                redirect_stdout(output),
            ):
                result = run(
                    root,
                    cfg,
                    None,
                    True,
                )

        self.assertEqual(
            result,
            0,
        )

        text = output.getvalue()

        self.assertIn(
            "candidate=1",
            text,
        )
        self.assertIn(
            "maturity_tracking=0",
            text,
        )
        self.assertIn(
            "maturity_ready=1",
            text,
        )
        self.assertNotIn(
            "promoted_exact",
            text,
        )


if __name__ == "__main__":
    unittest.main()
