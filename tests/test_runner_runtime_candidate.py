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
    25,
    10,
    30,
    tzinfo=timezone.utc,
)


class RunnerRuntimeCandidateTests(unittest.TestCase):
    def setUp(self):
        self.repo_root = Path("/repo")
        self.collection = {
            "name": "netflix",
            "active_file": "Netflix_DNS",
        }
        self.paths = SimpleNamespace(
            runtime_candidate_state=Path(
                "/repo/dns/netflix/runtime_candidate_state.json"
            )
        )

    def run_case(
        self,
        enabled,
        intake_result=None,
        intake_side_effect=None,
    ):
        discovered_candidates = {
            "api.netflix.com",
            "www.netflix.com",
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
                    return_value=[self.collection],
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
                    "dns_maintenance.runner.runtime_candidate_settings",
                    return_value={"enabled": enabled},
                )
            )

            intake = stack.enter_context(
                patch(
                    "dns_maintenance.runner.intake_runtime_candidate_feed"
                )
            )
            if intake_side_effect is not None:
                intake.side_effect = intake_side_effect
            else:
                intake.return_value = intake_result

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
                        discovered_candidates,
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
                    return_value=({}, None),
                )
            )

            stack.enter_context(
                patch(
                    "dns_maintenance.runner.hostname_policy_settings",
                    return_value={},
                )
            )
            stack.enter_context(
                patch(
                    "dns_maintenance.runner.apply_hostname_policy",
                    return_value=({}, None),
                )
            )
            stack.enter_context(
                patch(
                    "dns_maintenance.runner.service_settings",
                    return_value={},
                )
            )
            stack.enter_context(
                patch(
                    "dns_maintenance.runner.probe_services",
                    return_value=({}, None),
                )
            )
            stack.enter_context(
                patch(
                    "dns_maintenance.runner.write_report",
                    return_value="report",
                )
            )

            output = io.StringIO()

            with redirect_stdout(output):
                result = run(
                    self.repo_root,
                    {},
                    None,
                    False,
                )

        return (
            result,
            intake,
            maintain,
            discovered_candidates,
            output.getvalue(),
        )

    def test_runtime_candidate_is_not_called_when_disabled(self):
        result, intake, maintain, _, _ = self.run_case(
            enabled=False,
        )

        self.assertEqual(result, 0)
        intake.assert_not_called()
        maintain.assert_called_once()

    def test_runtime_candidates_do_not_enter_maintain_dns(self):
        runtime_state = {
            "candidates": {
                "runtime-id": {
                    "hostname": "runtime.netflix.example",
                }
            }
        }

        (
            result,
            intake,
            maintain,
            discovered_candidates,
            _,
        ) = self.run_case(
            enabled=True,
            intake_result={
                "status": "ok",
                "written": True,
                "dry_run": False,
                "state": runtime_state,
            },
        )

        self.assertEqual(result, 0)

        intake.assert_called_once_with(
            self.repo_root,
            "netflix",
            self.paths.runtime_candidate_state,
            False,
            NOW,
        )

        maintain_candidates = maintain.call_args.args[4]

        self.assertIs(
            maintain_candidates,
            discovered_candidates,
        )
        self.assertNotIn(
            "runtime.netflix.example",
            maintain_candidates,
        )

    def test_runtime_candidate_failure_does_not_stop_dns_pipeline(self):
        (
            result,
            intake,
            maintain,
            _,
            output,
        ) = self.run_case(
            enabled=True,
            intake_side_effect=RuntimeError(
                "runtime intake failed"
            ),
        )

        self.assertEqual(result, 0)
        intake.assert_called_once()
        maintain.assert_called_once()

        self.assertIn(
            "runtime candidate intake: status=error",
            output,
        )
        self.assertIn(
            "runtime intake failed",
            output,
        )
