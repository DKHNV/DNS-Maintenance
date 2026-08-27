from __future__ import annotations

import io
import unittest
from contextlib import (
    ExitStack,
    redirect_stdout,
)
from datetime import (
    datetime,
    timezone,
)
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from dns_maintenance.runner import run


NOW = datetime(
    2026,
    8,
    28,
    8,
    0,
    tzinfo=timezone.utc,
)


class RuntimeCandidateExactPromotionApplyRunnerTests(
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
            state=Path(
                "/repo/dns/youtube/state.json"
            ),
            pending=Path(
                "/repo/dns/youtube/pending.txt"
            ),
        )

        self.runtime_state = {
            "service": "youtube",
            "source_content_hash": (
                "a" * 64
            ),
            "candidates": {
                "candidate-1": {
                    "candidate_id": (
                        "candidate-1"
                    ),
                    "hostname": (
                        "video.example.com"
                    ),
                },
            },
        }

        self.classification_state = {
            "version": 1,
            "mode": "shadow",
            "service": "youtube",
            "classified_at": (
                "2026-08-28T08:00:00Z"
            ),
            "source_content_hash": (
                "a" * 64
            ),
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
                },
            },
        }

        self.promotion_state = {
            "version": 1,
            "mode": "shadow",
            "service": "youtube",
            "evaluated_at": (
                "2026-08-28T08:00:00Z"
            ),
            "source_content_hash": (
                "a" * 64
            ),
            "source_classified_at": (
                "2026-08-28T08:00:00Z"
            ),
            "counts": {
                "hold": 0,
                "eligible": 1,
            },
            "candidates": {
                "candidate-1": {
                    "state": "eligible",
                },
            },
        }

        self.dns_before_policy = {
            "version": 2,
            "updated_at": (
                "2026-08-28T08:00:00Z"
            ),
            "hosts": {
                "www.youtube.com": {
                    "status": "active",
                },
            },
        }

        self.dns_after_policy = {
            "version": 2,
            "updated_at": (
                "2026-08-28T08:00:00Z"
            ),
            "hosts": {
                "www.youtube.com": {
                    "status": "active",
                },
            },
        }

        self.dns_after_apply = {
            "version": 2,
            "updated_at": (
                "2026-08-28T08:00:00Z"
            ),
            "hosts": {
                "www.youtube.com": {
                    "status": "active",
                },
                "video.example.com": {
                    "status": "pending",
                    "ever_validated": False,
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

    def run_case(
        self,
        *,
        apply_enabled: bool,
        dry_run: bool = False,
        promotion_result: dict | None = None,
        apply_result: dict | None = None,
        apply_side_effect=None,
    ) -> dict:
        if promotion_result is None:
            promotion_result = {
                "status": "ok",
                "written": not dry_run,
                "dry_run": dry_run,
                "state": (
                    self.promotion_state
                ),
            }

        if apply_result is None:
            apply_result = {
                "status": "ok",
                "written": (
                    apply_enabled
                    and not dry_run
                ),
                "dry_run": dry_run,
                "result": {
                    "counts": {
                        "hold": 0,
                        "created_pending": 1,
                    },
                    "dns_state": (
                        self.dns_after_apply
                    ),
                },
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
                    "dns_maintenance.runner."
                    "collections_for",
                    return_value=[
                        self.collection
                    ],
                )
            )

            stack.enter_context(
                patch(
                    "dns_maintenance.runner."
                    "collection_paths",
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
                    return_value={
                        "enabled": True,
                        "min_seen_days": 2,
                        "min_observation_count": 2,
                    },
                )
            )

            stack.enter_context(
                patch(
                    "dns_maintenance.runner."
                    "runtime_candidate_maturity_settings",
                    return_value={
                        "enabled": True,
                        "min_candidate_age_hours": 24.0,
                        "min_additional_seen_days": 1,
                        "min_additional_observation_count": 1,
                    },
                )
            )

            stack.enter_context(
                patch(
                    "dns_maintenance.runner."
                    "runtime_candidate_exact_promotion_settings",
                    return_value={
                        "enabled": True,
                    },
                )
            )

            stack.enter_context(
                patch(
                    "dns_maintenance.runner."
                    "runtime_candidate_exact_promotion_apply_settings",
                    return_value={
                        "enabled": (
                            apply_enabled
                        ),
                    },
                )
            )

            stack.enter_context(
                patch(
                    "dns_maintenance.runner."
                    "intake_runtime_candidate_feed",
                    return_value={
                        "status": "ok",
                        "written": (
                            not dry_run
                        ),
                        "dry_run": dry_run,
                        "state": (
                            self.runtime_state
                        ),
                    },
                )
            )

            stack.enter_context(
                patch(
                    "dns_maintenance.runner."
                    "discovery_settings",
                    return_value={},
                )
            )

            stack.enter_context(
                patch(
                    "dns_maintenance.runner."
                    "discover",
                    return_value=(
                        self.discovered_candidates,
                        {},
                        None,
                    ),
                )
            )

            stack.enter_context(
                patch(
                    "dns_maintenance.runner."
                    "dns_settings",
                    return_value={},
                )
            )

            maintain = stack.enter_context(
                patch(
                    "dns_maintenance.runner."
                    "maintain_dns",
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
                    return_value=(
                        self.policy_cfg
                    ),
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

            stack.enter_context(
                patch(
                    "dns_maintenance.runner."
                    "write_runtime_candidate_"
                    "classification_snapshot",
                    return_value={
                        "status": "ok",
                        "written": (
                            not dry_run
                        ),
                        "dry_run": dry_run,
                        "state": (
                            self.classification_state
                        ),
                    },
                )
            )

            promote = stack.enter_context(
                patch(
                    "dns_maintenance.runner."
                    "write_exact_promotion_snapshot",
                    return_value=(
                        promotion_result
                    ),
                )
            )

            apply_pending = stack.enter_context(
                patch(
                    "dns_maintenance.runner."
                    "apply_exact_promotion_pending"
                )
            )

            if apply_side_effect is not None:
                apply_pending.side_effect = (
                    apply_side_effect
                )

            else:
                apply_pending.return_value = (
                    apply_result
                )

            stack.enter_context(
                patch(
                    "dns_maintenance.runner."
                    "service_settings",
                    return_value={},
                )
            )

            probe = stack.enter_context(
                patch(
                    "dns_maintenance.runner."
                    "probe_services",
                    return_value=(
                        {},
                        None,
                    ),
                )
            )

            report = stack.enter_context(
                patch(
                    "dns_maintenance.runner."
                    "write_report",
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
            "maintain": maintain,
            "apply_policy": (
                apply_policy
            ),
            "promote": promote,
            "apply_pending": (
                apply_pending
            ),
            "probe": probe,
            "report": report,
            "output": output.getvalue(),
        }

    def test_disabled_apply_is_not_called(
        self,
    ) -> None:
        result = self.run_case(
            apply_enabled=False,
        )

        self.assertEqual(
            result["result"],
            0,
        )

        result[
            "apply_pending"
        ].assert_not_called()

    def test_enabled_apply_uses_current_states(
        self,
    ) -> None:
        result = self.run_case(
            apply_enabled=True,
        )

        result[
            "apply_pending"
        ].assert_called_once_with(
            self.runtime_state,
            self.classification_state,
            self.promotion_state,
            self.dns_after_policy,
            self.policy_cfg,
            self.paths.state,
            self.paths.pending,
            False,
            NOW,
            settings={
                "enabled": True,
            },
        )

    def test_apply_uses_post_policy_dns_state(
        self,
    ) -> None:
        result = self.run_case(
            apply_enabled=True,
        )

        call = result[
            "apply_pending"
        ].call_args

        self.assertIs(
            call.args[3],
            self.dns_after_policy,
        )

        self.assertIs(
            call.args[4],
            self.policy_cfg,
        )

        result[
            "apply_policy"
        ].assert_called_once()

    def test_apply_does_not_reenter_maintain_dns(
        self,
    ) -> None:
        result = self.run_case(
            apply_enabled=True,
        )

        result[
            "maintain"
        ].assert_called_once()

        self.assertNotIn(
            "video.example.com",
            result[
                "maintain"
            ].call_args.args[4],
        )

        result[
            "apply_pending"
        ].assert_called_once()

    def test_apply_result_is_used_for_probe_and_report(
        self,
    ) -> None:
        result = self.run_case(
            apply_enabled=True,
        )

        probe_call = result[
            "probe"
        ].call_args

        self.assertIs(
            probe_call.args[2],
            self.dns_after_apply,
        )

        report_call = result[
            "report"
        ].call_args

        self.assertIs(
            report_call.args[3],
            self.dns_after_apply,
        )

        self.assertIn(
            "exact promotion apply: "
            "status=ok mode=apply "
            "hold=0 created_pending=1",
            result["output"],
        )

    def test_promotion_failure_skips_apply(
        self,
    ) -> None:
        result = self.run_case(
            apply_enabled=True,
            promotion_result={
                "status": "write_error",
                "written": False,
                "dry_run": False,
                "state": (
                    self.promotion_state
                ),
                "error": "disk failed",
            },
        )

        result[
            "apply_pending"
        ].assert_not_called()

        self.assertIn(
            "exact promotion apply: "
            "status=skipped "
            "reason=promotion_write_error",
            result["output"],
        )

        result[
            "probe"
        ].assert_called_once()

    def test_apply_write_error_is_isolated(
        self,
    ) -> None:
        result = self.run_case(
            apply_enabled=True,
            apply_result={
                "status": "write_error",
                "written": False,
                "dry_run": False,
                "result": {
                    "counts": {
                        "hold": 0,
                        "created_pending": 1,
                    },
                    "dns_state": (
                        self.dns_after_apply
                    ),
                },
                "error": "pending failed",
            },
        )

        self.assertEqual(
            result["result"],
            0,
        )

        result[
            "probe"
        ].assert_called_once()

        self.assertIs(
            result[
                "probe"
            ].call_args.args[2],
            self.dns_after_policy,
        )

        self.assertIn(
            "exact promotion apply: "
            "status=write_error "
            "error=pending failed",
            result["output"],
        )

    def test_apply_exception_is_isolated(
        self,
    ) -> None:
        result = self.run_case(
            apply_enabled=True,
            apply_side_effect=RuntimeError(
                "apply exploded"
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
            "exact promotion apply: "
            "status=error "
            "error=apply exploded",
            result["output"],
        )

    def test_dry_run_is_forwarded_to_apply(
        self,
    ) -> None:
        result = self.run_case(
            apply_enabled=True,
            dry_run=True,
        )

        call = result[
            "apply_pending"
        ].call_args

        self.assertTrue(
            call.args[7]
        )

        self.assertIn(
            "written=False dry_run=True",
            result["output"],
        )


if __name__ == "__main__":
    unittest.main()
