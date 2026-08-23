import json
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from dns_maintenance.config import collection_paths, hostname_policy_settings, load_config
from dns_maintenance.policy import apply_hostname_policy, evaluate_hostname
from dns_maintenance.report import render_report

UTC = timezone.utc
NOW = datetime(2026, 8, 23, 5, 0, tzinfo=UTC)
STAMP = "2026-08-23T05:00:00Z"


class HostnamePolicyTests(unittest.TestCase):
    def collection(self, policy=None):
        result = {"name": "grok", "active_file": "Grok_DNS", "data_dir": "dns/grok"}
        if policy is not None:
            result["hostname_policy"] = policy
        return result

    def policy(self):
        return hostname_policy_settings(self.collection({
            "enabled": True,
            "allow": [
                {"id": "keep-chat", "match": "exact", "value": "grok-chat.hades-api.grok-sandbox.com"}
            ],
            "exclude": [
                {
                    "id": "drop-hades",
                    "match": "suffix",
                    "value": "hades-api.grok-sandbox.com",
                    "reason": "sandbox host not required for public routing",
                }
            ],
        }))

    def entry(self, status="active", *, sources=None, last_result="OK"):
        return {
            "hostname": "x",
            "status": status,
            "sources": list(sources or ["certspotter:grok-sandbox.com"]),
            "ever_validated": True,
            "last_check": STAMP,
            "last_result": last_result,
            "policy_excluded_at": None,
            "policy_rule": None,
            "policy_reason": None,
        }

    def test_policy_disabled_by_default(self):
        cfg = hostname_policy_settings(self.collection())
        self.assertFalse(cfg["enabled"])
        self.assertEqual(cfg["allow"], [])
        self.assertEqual(cfg["exclude"], [])

    def test_invalid_policy_is_rejected_at_config_load(self):
        cfg = {
            "version": 1,
            "collections": [self.collection({
                "enabled": True,
                "exclude": [{"match": "suffix", "value": "grok.com"}],
            })],
        }
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "config.json"
            path.write_text(json.dumps(cfg), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "requires a reason"):
                load_config(path)

    def test_allow_exception_wins_over_suffix_exclude(self):
        cfg = self.policy()
        allowed = evaluate_hostname("grok-chat.hades-api.grok-sandbox.com", cfg)
        excluded = evaluate_hostname("francischong.hades-api.grok-sandbox.com", cfg)
        self.assertFalse(allowed.excluded)
        self.assertEqual(allowed.rule, "keep-chat")
        self.assertTrue(excluded.excluded)
        self.assertEqual(excluded.rule, "drop-hades")

    def test_suffix_matching_is_domain_boundary_safe(self):
        cfg = self.policy()
        self.assertTrue(evaluate_hostname("a.hades-api.grok-sandbox.com", cfg).excluded)
        self.assertFalse(evaluate_hostname("evilhades-api.grok-sandbox.com", cfg).excluded)

    def test_manual_source_bypasses_semantic_policy(self):
        cfg = self.policy()
        result = evaluate_hostname(
            "francischong.hades-api.grok-sandbox.com",
            cfg,
            manual_override=True,
        )
        self.assertFalse(result.excluded)
        self.assertTrue(result.manual_override)

    def test_active_host_moves_to_excluded_and_files_sync(self):
        cfg = self.policy()
        state = {"version": 2, "hosts": {
            "francischong.hades-api.grok-sandbox.com": self.entry(),
            "grok.com": self.entry(),
        }}
        with tempfile.TemporaryDirectory() as td:
            paths = collection_paths(Path(td), self.collection())
            new_state, stats = apply_hostname_policy("grok", paths, state, cfg, NOW, False)
            excluded = new_state["hosts"]["francischong.hades-api.grok-sandbox.com"]
            self.assertEqual(excluded["status"], "excluded")
            self.assertEqual(excluded["policy_rule"], "drop-hades")
            self.assertEqual(stats["excluded"], 1)
            self.assertEqual(paths.excluded.read_text().strip(), "francischong.hades-api.grok-sandbox.com")
            self.assertEqual(paths.active.read_text().strip(), "grok.com")

    def test_manual_override_requires_fresh_dns_ok_to_republish(self):
        cfg = self.policy()
        entry = self.entry(status="active", sources=["manual"], last_result="NEGATIVE")
        entry["policy_excluded_at"] = "2026-08-22T05:00:00Z"
        entry["policy_rule"] = "drop-hades"
        entry["policy_reason"] = "old exclusion"
        state = {"version": 2, "hosts": {"francischong.hades-api.grok-sandbox.com": entry}}
        with tempfile.TemporaryDirectory() as td:
            paths = collection_paths(Path(td), self.collection())
            new_state, _ = apply_hostname_policy("grok", paths, state, cfg, NOW, True)
        released = new_state["hosts"]["francischong.hades-api.grok-sandbox.com"]
        self.assertEqual(released["status"], "pending")
        self.assertFalse(released["ever_validated"])
        self.assertIsNone(released["policy_excluded_at"])

    def test_manual_override_with_fresh_ok_republishes(self):
        cfg = self.policy()
        entry = self.entry(status="active", sources=["manual"], last_result="OK")
        entry["policy_excluded_at"] = "2026-08-22T05:00:00Z"
        entry["policy_rule"] = "drop-hades"
        entry["policy_reason"] = "old exclusion"
        state = {"version": 2, "hosts": {"francischong.hades-api.grok-sandbox.com": entry}}
        with tempfile.TemporaryDirectory() as td:
            paths = collection_paths(Path(td), self.collection())
            new_state, _ = apply_hostname_policy("grok", paths, state, cfg, NOW, True)
        released = new_state["hosts"]["francischong.hades-api.grok-sandbox.com"]
        self.assertEqual(released["status"], "active")
        self.assertTrue(released["ever_validated"])
        self.assertIsNone(released["policy_excluded_at"])

    def test_quarantine_is_never_overridden_by_policy_or_manual(self):
        cfg = self.policy()
        entry = self.entry(status="quarantine", sources=["manual"])
        entry["policy_excluded_at"] = "2026-08-22T05:00:00Z"
        state = {"version": 2, "hosts": {"francischong.hades-api.grok-sandbox.com": entry}}
        with tempfile.TemporaryDirectory() as td:
            paths = collection_paths(Path(td), self.collection())
            new_state, _ = apply_hostname_policy("grok", paths, state, cfg, NOW, True)
        result = new_state["hosts"]["francischong.hades-api.grok-sandbox.com"]
        self.assertEqual(result["status"], "quarantine")
        self.assertIsNone(result["policy_excluded_at"])

    def test_disabled_policy_is_noop_for_never_managed_state(self):
        state = {"version": 2, "hosts": {"grok.com": self.entry()}}
        with tempfile.TemporaryDirectory() as td:
            paths = collection_paths(Path(td), self.collection())
            new_state, stats = apply_hostname_policy(
                "grok", paths, state, hostname_policy_settings(self.collection()), NOW, False
            )
            self.assertFalse(paths.excluded.exists())
        self.assertEqual(new_state["hosts"]["grok.com"]["status"], "active")
        self.assertEqual(stats["transitions"], 0)

    def test_report_counts_only_current_public_dns_hosts_for_https(self):
        dns_state = {"hosts": {
            "grok.com": {"status": "active", "ever_validated": True},
            "old.grok.com": {"status": "excluded", "ever_validated": True},
        }}
        service_state = {"hosts": {
            "grok.com": {"status": "alive", "stability_score": 100.0, "last_result": "SUCCESS"},
            "old.grok.com": {
                "status": "unknown",
                "stability_score": 0.0,
                "last_result": "FAILURE",
                "last_failure": {"type": "TIMEOUT"},
            },
        }}
        report = render_report("grok", "Grok_DNS", dns_state, service_state, {}, NOW)
        self.assertIn("| Excluded | 1 |", report)
        self.assertIn("| Alive | 1 |", report)
        self.assertIn("| Unknown | 0 |", report)
        self.assertNotIn("TIMEOUT | 1", report)


if __name__ == "__main__":
    unittest.main()
