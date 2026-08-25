from __future__ import annotations

import io
import tempfile
import unittest
from contextlib import ExitStack, redirect_stdout
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from dns_maintenance.config import (
    collection_paths,
    runtime_candidate_classification_settings,
)
from dns_maintenance.runner import run
from dns_maintenance.runtime_candidate_classification import (
    write_runtime_candidate_classification_snapshot,
)


NOW = datetime(
    2026,
    8,
    25,
    15,
    0,
    tzinfo=timezone.utc,
)


def runtime_candidate() -> dict:
    return {
        "candidate_id": "candidate-1",
        "hostname": "video.example.com",
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


def runtime_state() -> dict:
    candidate = runtime_candidate()

    return {
        "schema_version": 1,
        "service": "netflix",
        "source_content_hash": "a" * 64,
        "source_generated_at": "2026-08-25T14:00:00Z",
        "last_intake_at": "2026-08-25T14:30:00Z",
        "candidates": {
            candidate["candidate_id"]: candidate,
        },
    }


class RuntimeCandidateClassificationConfigTests(
    unittest.TestCase
):
    def collection(self) -> dict:
        return {
            "name": "netflix",
            "active_file": "Netflix_DNS",
            "data_dir": "dns/netflix",
        }

    def test_classification_is_disabled_by_default(self):
        self.assertEqual(
            runtime_candidate_classification_settings(
                self.collection()
            ),
            {"enabled": False},
        )

    def test_classification_can_be_enabled(self):
        collection = self.collection()
        collection["runtime_candidate"] = {
            "enabled": True,
            "classification": {
                "enabled": True,
            },
        }

        self.assertEqual(
            runtime_candidate_classification_settings(
                collection
            ),
            {"enabled": True},
        )

    def test_classification_requires_runtime_intake(self):
        collection = self.collection()
        collection["runtime_candidate"] = {
            "enabled": False,
            "classification": {
                "enabled": True,
            },
        }

        with self.assertRaisesRegex(
            ValueError,
            "requires runtime_candidate.enabled",
        ):
            runtime_candidate_classification_settings(
                collection
            )

    def test_classification_enabled_must_be_boolean(self):
        collection = self.collection()
        collection["runtime_candidate"] = {
            "enabled": True,
            "classification": {
                "enabled": "true",
            },
        }

        with self.assertRaisesRegex(
            ValueError,
            "classification.enabled must be boolean",
        ):
            runtime_candidate_classification_settings(
                collection
            )

    def test_classification_path_is_managed_data_path(self):
        with tempfile.TemporaryDirectory() as td:
            paths = collection_paths(
                Path(td),
                self.collection(),
            )

            self.assertTrue(
                str(
                    paths.runtime_candidate_classification
                ).endswith(
                    "dns/netflix/"
                    "runtime_candidate_classification.json"
                )
            )


class RuntimeCandidateClassificationPersistenceTests(
    unittest.TestCase
):
    def test_snapshot_is_written(self):
        with tempfile.TemporaryDirectory() as td:
            path = (
                Path(td)
                / "runtime_candidate_classification.json"
            )

            result = (
                write_runtime_candidate_classification_snapshot(
                    runtime_state(),
                    {"hosts": {}},
                    {
                        "enabled": False,
                        "allow": [],
                        "exclude": [],
                    },
                    path,
                    False,
                    NOW,
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
                path.exists()
            )

            snapshot = result["state"]

            self.assertEqual(
                snapshot["mode"],
                "shadow",
            )
            self.assertEqual(
                snapshot["source_content_hash"],
                "a" * 64,
            )
            self.assertEqual(
                snapshot["counts"],
                {
                    "observed": 1,
                    "observe_only": 0,
                    "rejected": 0,
                },
            )

    def test_dry_run_does_not_write(self):
        with tempfile.TemporaryDirectory() as td:
            path = (
                Path(td)
                / "runtime_candidate_classification.json"
            )

            result = (
                write_runtime_candidate_classification_snapshot(
                    runtime_state(),
                    {"hosts": {}},
                    {
                        "enabled": False,
                        "allow": [],
                        "exclude": [],
                    },
                    path,
                    True,
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
                path.exists()
            )

    def test_write_error_fails_closed(self):
        with patch(
            "dns_maintenance."
            "runtime_candidate_classification.save_json",
            side_effect=OSError("disk failed"),
        ):
            result = (
                write_runtime_candidate_classification_snapshot(
                    runtime_state(),
                    {"hosts": {}},
                    {
                        "enabled": False,
                        "allow": [],
                        "exclude": [],
                    },
                    Path(
                        "/repo/dns/netflix/"
                        "runtime_candidate_classification.json"
                    ),
                    False,
                    NOW,
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


class RuntimeCandidateClassificationRunnerTests(
    unittest.TestCase
):
    def setUp(self):
        self.repo_root = Path("/repo")

        self.collection = {
            "name": "netflix",
            "active_file": "Netflix_DNS",
        }

        self.paths = SimpleNamespace(
            runtime_candidate_state=Path(
                "/repo/dns/netflix/"
                "runtime_candidate_state.json"
            ),
            runtime_candidate_classification=Path(
                "/repo/dns/netflix/"
                "runtime_candidate_classification.json"
            ),
        )

    def run_case(
        self,
        *,
        classification_enabled: bool,
        intake_result: dict | None,
        classification_result: dict | None = None,
        classification_side_effect=None,
        dry_run: bool = False,
    ):
        discovered_candidates = {
            "www.netflix.com",
        }

        dns_before_policy = {
            "hosts": {
                "www.netflix.com": {
                    "status": "active",
                }
            }
        }

        dns_after_policy = {
            "hosts": {
                "www.netflix.com": {
                    "status": "active",
                },
                "video.example.com": {
                    "status": "pending",
                },
            }
        }

        policy_cfg = {
            "enabled": False,
            "allow": [],
            "exclude": [],
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
                    "dns_maintenance.runner."
                    "runtime_candidate_settings",
                    return_value={"enabled": True},
                )
            )

            stack.enter_context(
                patch(
                    "dns_maintenance.runner."
                    "runtime_candidate_classification_settings",
                    return_value={
                        "enabled": classification_enabled
                    },
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
                    return_value=(
                        dns_before_policy,
                        None,
                    ),
                )
            )

            stack.enter_context(
                patch(
                    "dns_maintenance.runner."
                    "hostname_policy_settings",
                    return_value=policy_cfg,
                )
            )

            apply_policy = stack.enter_context(
                patch(
                    "dns_maintenance.runner."
                    "apply_hostname_policy",
                    return_value=(
                        dns_after_policy,
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

            if classification_side_effect is not None:
                classify.side_effect = (
                    classification_side_effect
                )
            elif classification_result is not None:
                classify.return_value = (
                    classification_result
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
                    dry_run,
                )

        return {
            "result": result,
            "intake": intake,
            "maintain": maintain,
            "apply_policy": apply_policy,
            "classify": classify,
            "probe": probe,
            "discovered_candidates": discovered_candidates,
            "dns_after_policy": dns_after_policy,
            "policy_cfg": policy_cfg,
            "output": output.getvalue(),
        }

    def ok_intake(self):
        return {
            "status": "ok",
            "written": True,
            "dry_run": False,
            "state": runtime_state(),
        }

    def ok_classification(self, written=True):
        return {
            "status": "ok",
            "written": written,
            "dry_run": not written,
            "state": {
                "counts": {
                    "observed": 0,
                    "observe_only": 1,
                    "rejected": 0,
                }
            },
        }

    def test_disabled_classification_is_not_called(self):
        result = self.run_case(
            classification_enabled=False,
            intake_result=self.ok_intake(),
        )

        self.assertEqual(
            result["result"],
            0,
        )
        result["classify"].assert_not_called()

    def test_classification_uses_post_policy_dns_state(self):
        intake_state = runtime_state()

        result = self.run_case(
            classification_enabled=True,
            intake_result={
                "status": "ok",
                "written": True,
                "dry_run": False,
                "state": intake_state,
            },
            classification_result=self.ok_classification(),
        )

        result["classify"].assert_called_once_with(
            intake_state,
            result["dns_after_policy"],
            result["policy_cfg"],
            self.paths.runtime_candidate_classification,
            False,
            NOW,
        )

        self.assertIn(
            "runtime candidate classification: "
            "status=ok mode=shadow",
            result["output"],
        )

        self.assertIn(
            "observe_only=1",
            result["output"],
        )

    def test_absent_intake_skips_classification(self):
        result = self.run_case(
            classification_enabled=True,
            intake_result={
                "status": "absent",
                "written": False,
                "dry_run": False,
                "state": None,
            },
        )

        result["classify"].assert_not_called()

        self.assertIn(
            "classification: status=skipped "
            "reason=intake_absent",
            result["output"],
        )

        result["probe"].assert_called_once()

    def test_classification_exception_does_not_stop_pipeline(
        self,
    ):
        result = self.run_case(
            classification_enabled=True,
            intake_result=self.ok_intake(),
            classification_side_effect=RuntimeError(
                "classification failed"
            ),
        )

        self.assertEqual(
            result["result"],
            0,
        )

        self.assertIn(
            "classification: status=error",
            result["output"],
        )

        self.assertIn(
            "classification failed",
            result["output"],
        )

        result["probe"].assert_called_once()

    def test_classification_write_error_does_not_stop_pipeline(
        self,
    ):
        result = self.run_case(
            classification_enabled=True,
            intake_result=self.ok_intake(),
            classification_result={
                "status": "write_error",
                "written": False,
                "dry_run": False,
                "state": {},
                "error": "disk failed",
            },
        )

        self.assertIn(
            "classification: status=write_error",
            result["output"],
        )

        self.assertIn(
            "disk failed",
            result["output"],
        )

        result["probe"].assert_called_once()

    def test_dry_run_is_forwarded_to_classification(self):
        intake_state = runtime_state()

        result = self.run_case(
            classification_enabled=True,
            intake_result={
                "status": "ok",
                "written": False,
                "dry_run": True,
                "state": intake_state,
            },
            classification_result=self.ok_classification(
                written=False
            ),
            dry_run=True,
        )

        result["classify"].assert_called_once_with(
            intake_state,
            result["dns_after_policy"],
            result["policy_cfg"],
            self.paths.runtime_candidate_classification,
            True,
            NOW,
        )

        self.assertIn(
            "written=False dry_run=True",
            result["output"],
        )

    def test_runtime_candidates_still_do_not_enter_maintain_dns(
        self,
    ):
        result = self.run_case(
            classification_enabled=True,
            intake_result=self.ok_intake(),
            classification_result=self.ok_classification(),
        )

        maintain_candidates = (
            result["maintain"].call_args.args[4]
        )

        self.assertIs(
            maintain_candidates,
            result["discovered_candidates"],
        )

        self.assertNotIn(
            "video.example.com",
            maintain_candidates,
        )


if __name__ == "__main__":
    unittest.main()
