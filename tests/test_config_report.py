import json
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from dns_maintenance.config import collection_paths, dns_settings, load_config, service_settings
from dns_maintenance.report import render_report


class ConfigReportTests(unittest.TestCase):
    def sample(self):
        return {
            "version": 1,
            "collections": [{"name": "telegram", "active_file": "Telegram_DNS", "data_dir": "dns/telegram"}],
        }

    def test_load_config(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "config.json"
            p.write_text(json.dumps(self.sample()))
            self.assertEqual(load_config(p)["version"], 1)

    def test_default_dns_thresholds_are_time_based(self):
        cfg = self.sample()
        s = dns_settings(cfg, cfg["collections"][0])
        self.assertEqual(s.suspect_after_hours, 72)
        self.assertEqual(s.quarantine_after_hours, 168)

    def test_default_service_history_is_14_days(self):
        cfg = self.sample()
        s = service_settings(cfg, cfg["collections"][0])
        self.assertEqual(s["history_days"], 14.0)

    def test_paths_are_standardized(self):
        with tempfile.TemporaryDirectory() as td:
            c = self.sample()["collections"][0]
            paths = collection_paths(Path(td), c)
            self.assertTrue(str(paths.report).endswith("dns/telegram/report.md"))

    def test_report_has_no_trailing_whitespace(self):
        report = render_report("telegram", "Telegram_DNS", {"hosts": {}}, {"hosts": {}}, {"updated_at": "2026-08-20T00:00:00Z"}, datetime(2026, 8, 20, tzinfo=timezone.utc))
        self.assertFalse(any(line.endswith(" ") or line.endswith("\t") for line in report.splitlines()))

    def test_report_mentions_time_based_lifecycle(self):
        report = render_report("telegram", "Telegram_DNS", {"hosts": {}}, {"hosts": {}}, {}, datetime(2026, 8, 20, tzinfo=timezone.utc))
        self.assertIn("time-based", report)
