from __future__ import annotations

import io
import unittest
from contextlib import ExitStack, redirect_stdout
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from dns_maintenance.runner import run


NOW = datetime(
    2026,
    8,
    27,
    12,
    0,
    tzinfo=timezone.utc,
)


def runtime_candidate_state() -> dict:
    return {
        "schema_version": 1,
        "service": "youtube",
        "source_content_hash": "a" * 64,
        "source_generated_at": (
            "2026-08-27T11:50:00Z"
        ),
        "last_intake_at": (
            "2026-08-27T11:55:00Z"
        ),
        "candidates": {
            "candidate-1": {
                "candidate_id": "candidate-1",
                "hostname": "video.example.com",
                "suffix": "example.com",
                "state": "observed",
                "feed_present": True,
                "current_presence": True,
                "current_routing_status": "active",
                "observation_count": 5,
                "presence_cycles": 10,
                "active_cycles": 8,
                "reactivation_count": 1,
                "seen_dates": [
                    "2026-08-25",
                    "2026-08-26",
                    "2026-08-27",
                ],
            },
        },
    }


def classification_state() -> dict:
    return {
        "version": 1,
        "mode": "shadow",
        "service": "youtube",
        "classified_at": (
            "2026-08-27T12:00:00Z"
        ),
        "source_content_hash": "a" * 64,
        "counts": {
            "observed": 0,
            "candidate": 1,
            "observe_only": 0,
            "rejected": 0,
        },
        "candidates": {
            "candidate-1": {
                "version": 1,
                "mode": "shadow",
                "decision": "candidate",
                "maturity": {
                    "version": 1,
                    "mode": "shadow",
                    "state": "ready",
                },
            },
        },
    }


class RuntimeCandidateExactPromotionRunnerTests(
    unittest.TestCase
):
    def setUp(self) -> None:
        self.repo_root = Path(
            "/repo"
        )

        self.collection = {
            "name": "youtube",
            "active_file": "YouTube_DNS",
        }

        self.paths = SimpleNamespace(
            runtime_candidate_state=Path(
                "/repo/dns/youtube/"
                "runtime_candidate_state.json"
            ),
            runtime_candidate_classification=Path(
                "/repo/dns/youtube/"
                "runtime_candidate_classification.json"
            ),
            runtime_candidate_exact_promotion=Path(
                "/repo/dns/youtube/"
                "runtime_candidate_exact_promotion.json"
            ),
        )

        self.runtime_state = (
            runtime_candidate_state()
        )

        self.classification_state = (
            classification_state()
        )

        self.dns_before_policy = {
            "hosts": {
                "www.youtube.com": {
                    "status": "active",
                },
            },
        }

        self.dns_after_policy = {
            "hosts": {
                "www.youtube.com": {
                    "status": "active",
                },
            },
        }

        self.policy_cfg = {
            "enabled": False,
            "allow": [],
            "exclude": [],
        }

        self.discovered_candidates = {
            "www.youtube.com",
        }

    def intake_ok(
        self,
        *,
        dry_run: bool = False,
    ) -> dict:
        return {
            "status": "ok",
            "written": not dry_run,
            "dry_run": dry_run,
            "state": self.runtime_state,
        }

    def classification_ok(
        self,
        *,
        dry_run: bool = False,
    ) -> dict:
        return {
            "status": "ok",
            "written": not dry_run,
            "dry_run": dry_run,
            "state": self.classification_state,
        }

    def promotion_ok(
        self,
        *,
        dry_run: bool = False,
    ) -> dict:
        return {
            "status": "ok",
            "written": not dry_run,
            "dry_run": dry_run,
            "state": {
                "counts": {
                    "hold": 0,
                    "eligible": 1,
                },
            },
        }

    def run_case(
        self,
        *,
        promotion_enabled: bool,
        dry_run: bool = False,
        intake_result: dict | None = None,
        classification_result: dict | None = None,
        classification_side_effect=None,
        promotion_result: dict | None = None,
        promotion_side_effect=None,
    ) -> dict:
        if intake_result is None:
            intake_result = self.intake_ok(
                dry_run=dry_run
            )

        if classification_result is None:
            classification_result = (
                self.classification_ok(
                    dry_run=dry_run
                )
            )

        if promotion_result is None:
            promotion_result = (
                self.promotion_ok(
                    dry_run=dry_run
                )
            )

        eligibility_cfg = {
            "enabled": True,
            "min_seen_days": 2,
            "min_observation_count": 2,
        }

        maturity_cfg = {
            "enabled": True,
            "min_candidate_age_hours": 24.0,
            "min_additional_seen_days": 1,
            "min_additional_observation_count": 1,
        }

        promotion_cfg = {
            "enabled": promotion_enabled,
        }

        with ExitStack() as stack:
            stack.enter_context(
                patch(
                    "dns_maintenance.runner.utc_now",
                    return_value=NOW,
                )
            )

            stack.enter_context(
                patch(
                    "dns_maintenance.runner.collections_for",
                    return_value=[
                        self.collection
                    ],
                )
            )

            stack.enter_context(
                patch(
                    "dns_maintenance.runner.collection_paths",
                    return_value=self.paths,
                )
            )

            stack.enter_context(
                patch(
                    "dns_maintenance.runner."
                    "runtime_candidate_settings",
                    return_value={
                        "enabled": True,
                    },
                )
            )

            stack.enter_context(
                patch(
                    "dns_maintenance.runner."
                    "runtime_candidate_classification_settings",
                    return_value={
                        "enabled": True,
                    },
                )
            )

            stack.enter_context(
                patch(
                    "dns_maintenance.runner."
                    "runtime_candidate_eligibility_settings",
                    return_value=eligibility_cfg,
                )
            )

            stack.enter_context(
                patch(
                    "dns_maintenance.runner."
                    "runtime_candidate_maturity_settings",
                    return_value=maturity_cfg,
                )
            )

            exact_settings = stack.enter_context(
                patch(
                    "dns_maintenance.runner."
                    "runtime_candidate_exact_promotion_settings",
                    return_value=promotion_cfg,
                )
            )

            intake = stack.enter_context(
                patch(
                    "dns_maintenance.runner."
                    "intake_runtime_candidate_feed",
                    return_value=intake_result,
                )
            )

            stack.enter_context(
                patch(
                    "dns_maintenance.runner.discovery_settings",
                    return_value={},
                )
            )

            stack.enter_context(
                patch(
                    "dns_maintenance.runner.discover",
                    return_value=(
                        self.discovered_candidates,
                        {},
                        None,
                    ),
                )
            )

            stack.enter_context(
                patch(
                    "dns_maintenance.runner.dns_settings",
                    return_value={},
                )
            )

            maintain = stack.enter_context(
                patch(
                    "dns_maintenance.runner.maintain_dns",
                    return_value=(
                        self.dns_before_policy,
                        None,
                    ),
                )
            )

            stack.enter_context(
                patch(
                    "dns_maintenance.runner."
                    "hostname_policy_settings",
                    return_value=self.policy_cfg,
                )
            )

            apply_policy = stack.enter_context(
                patch(
                    "dns_maintenance.runner."
                    "apply_hostname_policy",
                    return_value=(
                        self.dns_after_policy,
                        None,
                    ),
                )
            )

            classify = stack.enter_context(
                patch(
                    "dns_maintenance.runner."
                    "write_runtime_candidate_"
                    "classification_snapshot"
                )
            )

            if (
                classification_side_effect
                is not None
            ):
                classify.side_effect = (
                    classification_side_effect
                )
            else:
                classify.return_value = (
                    classification_result
                )

            promote = stack.enter_context(
                patch(
                    "dns_maintenance.runner."
                    "write_exact_promotion_snapshot"
                )
            )

            if (
                promotion_side_effect
                is not None
            ):
                promote.side_effect = (
                    promotion_side_effect
                )
            else:
                promote.return_value = (
                    promotion_result
                )

            stack.enter_context(
                patch(
                    "dns_maintenance.runner.service_settings",
                    return_value={},
                )
            )

            probe = stack.enter_context(
                patch(
                    "dns_maintenance.runner.probe_services",
                    return_value=(
                        {},
                        None,
                    ),
                )
            )

            stack.enter_context(
                patch(
                    "dns_maintenance.runner.write_report",
                    return_value="report",
                )
            )

            output = io.StringIO()

            with redirect_stdout(
                output
            ):
                result = run(
                    self.repo_root,
                    {},
                    None,
                    dry_run,
                )

        return {
            "result": result,
            "intake": intake,
            "maintain": maintain,
            "apply_policy": apply_policy,
            "classify": classify,
            "promote": promote,
            "probe": probe,
            "exact_settings": exact_settings,
            "promotion_cfg": promotion_cfg,
            "output": output.getvalue(),
        }

    def test_disabled_exact_promotion_is_not_called(
        self,
    ) -> None:
        result = self.run_case(
            promotion_enabled=False,
        )

        self.assertEqual(
            result["result"],
            0,
        )

        result[
            "promote"
        ].assert_not_called()

    def test_enabled_exact_promotion_uses_current_states(
        self,
    ) -> None:
        result = self.run_case(
            promotion_enabled=True,
        )

        result[
            "promote"
        ].assert_called_once_with(
            self.runtime_state,
            self.classification_state,
            self.dns_after_policy,
            self.policy_cfg,
            self.paths.runtime_candidate_exact_promotion,
            False,
            NOW,
            settings={
                "enabled": True,
            },
        )

        self.assertIn(
            "exact promotion: "
            "status=ok mode=shadow "
            "hold=0 eligible=1",
            result["output"],
        )

    def test_exact_promotion_uses_post_policy_dns_state(
        self,
    ) -> None:
        result = self.run_case(
            promotion_enabled=True,
        )

        call = result[
            "promote"
        ].call_args

        self.assertIs(
            call.args[2],
            self.dns_after_policy,
        )

        self.assertIs(
            call.args[3],
            self.policy_cfg,
        )

    def test_classification_failure_skips_exact_promotion(
        self,
    ) -> None:
        result = self.run_case(
            promotion_enabled=True,
            classification_result={
                "status": "state_error",
                "written": False,
                "dry_run": False,
                "state": None,
                "error": "bad snapshot",
            },
        )

        result[
            "promote"
        ].assert_not_called()

        self.assertIn(
            "exact promotion: "
            "status=skipped "
            "reason=classification_state_error",
            result["output"],
        )

        self.assertEqual(
            result["result"],
            0,
        )

    def test_intake_failure_skips_exact_promotion(
        self,
    ) -> None:
        result = self.run_case(
            promotion_enabled=True,
            intake_result={
                "status": "feed_error",
                "written": False,
                "dry_run": False,
                "state": None,
                "error": "bad feed",
            },
        )

        result[
            "promote"
        ].assert_not_called()

        self.assertIn(
            "exact promotion: "
            "status=skipped "
            "reason=intake_feed_error",
            result["output"],
        )

        self.assertEqual(
            result["result"],
            0,
        )

    def test_exact_promotion_write_error_is_isolated(
        self,
    ) -> None:
        result = self.run_case(
            promotion_enabled=True,
            promotion_result={
                "status": "write_error",
                "written": False,
                "dry_run": False,
                "state": None,
                "error": "disk failed",
            },
        )

        self.assertEqual(
            result["result"],
            0,
        )

        result[
            "probe"
        ].assert_called_once()

        self.assertIn(
            "exact promotion: "
            "status=write_error "
            "error=disk failed",
            result["output"],
        )

    def test_exact_promotion_exception_is_isolated(
        self,
    ) -> None:
        result = self.run_case(
            promotion_enabled=True,
            promotion_side_effect=RuntimeError(
                "promotion exploded"
            ),
        )

        self.assertEqual(
            result["result"],
            0,
        )

        result[
            "probe"
        ].assert_called_once()

        self.assertIn(
            "exact promotion: "
            "status=error "
            "error=promotion exploded",
            result["output"],
        )

    def test_dry_run_is_forwarded_to_exact_promotion(
        self,
    ) -> None:
        result = self.run_case(
            promotion_enabled=True,
            dry_run=True,
        )

        call = result[
            "promote"
        ].call_args

        self.assertTrue(
            call.args[5]
        )

        self.assertIn(
            "written=False dry_run=True",
            result["output"],
        )

    def test_runtime_candidates_still_do_not_enter_maintain_dns(
        self,
    ) -> None:
        result = self.run_case(
            promotion_enabled=True,
        )

        maintain = result[
            "maintain"
        ]

        maintain.assert_called_once()

        self.assertEqual(
            maintain.call_args.args[4],
            self.discovered_candidates,
        )

        self.assertNotIn(
            "video.example.com",
            maintain.call_args.args[4],
        )


if __name__ == "__main__":
    unittest.main()
