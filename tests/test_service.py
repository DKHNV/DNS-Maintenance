import unittest
from datetime import datetime, timedelta, timezone

from dns_maintenance.service import apply_service_result, new_service_state, normalize_service_entry, update_history

UTC = timezone.utc
BASE = datetime(2026, 8, 20, 0, 0, tzinfo=UTC)
CFG = {
    "failure_streak_max_gap_hours": 48.0,
    "suspect_after_hours": 72.0,
    "dead_after_hours": 168.0,
    "suspect_min_failure_observations": 3,
    "dead_min_failure_observations": 7,
    "history_days": 14.0,
    "history_max_entries": 256,
}
FAIL_ATTEMPTS = [{"ip": "1.2.3.4", "port": 443, "status": "TIMEOUT"}]
OK_ATTEMPTS = [{"ip": "1.2.3.4", "port": 443, "status": "HTTPS_OK", "http_status": 200, "tls_version": "TLSv1.3"}]


class ServiceTests(unittest.TestCase):
    def test_first_failure_stays_unknown(self):
        s = new_service_state("example.com", BASE)
        _, new = apply_service_result(s, "FAILURE", FAIL_ATTEMPTS, ["1.2.3.4"], BASE, CFG)
        self.assertEqual(new, "unknown")
        self.assertEqual(s["failure_observations"], 1)

    def test_suspect_after_72_hours(self):
        s = new_service_state("example.com", BASE)
        s.update({"failure_since": "2026-08-20T00:00:00Z", "last_failure": {"at": "2026-08-22T00:00:00Z"}, "failure_observations": 2})
        _, new = apply_service_result(s, "FAILURE", FAIL_ATTEMPTS, ["1.2.3.4"], BASE + timedelta(hours=72), CFG)
        self.assertEqual(new, "suspect")

    def test_dead_after_168_hours(self):
        s = new_service_state("example.com", BASE)
        s.update({"status": "suspect", "failure_since": "2026-08-20T00:00:00Z", "last_failure": {"at": "2026-08-26T18:00:00Z"}, "failure_observations": 6})
        _, new = apply_service_result(s, "FAILURE", FAIL_ATTEMPTS, ["1.2.3.4"], BASE + timedelta(hours=168), CFG)
        self.assertEqual(new, "dead")

    def test_alive_resets_failure_window(self):
        s = new_service_state("example.com", BASE)
        s.update({"status": "suspect", "failure_since": "2026-08-20T00:00:00Z", "failure_observations": 8})
        _, new = apply_service_result(s, "ALIVE", OK_ATTEMPTS, ["1.2.3.4"], BASE, CFG)
        self.assertEqual(new, "alive")
        self.assertIsNone(s["failure_since"])
        self.assertEqual(s["failure_observations"], 0)

    def test_skipped_does_not_increment_failure(self):
        s = new_service_state("example.com", BASE)
        s["failure_observations"] = 2
        apply_service_result(s, "SKIPPED", [], [], BASE, CFG)
        self.assertEqual(s["failure_observations"], 2)

    def test_large_gap_restarts_failure_window(self):
        s = new_service_state("example.com", BASE)
        s.update({"failure_since": "2026-08-20T00:00:00Z", "last_failure": {"at": "2026-08-20T01:00:00Z"}, "failure_observations": 5})
        apply_service_result(s, "FAILURE", FAIL_ATTEMPTS, ["1.2.3.4"], BASE + timedelta(hours=72), CFG)
        self.assertEqual(s["failure_observations"], 1)

    def test_history_is_calendar_window_not_sample_count(self):
        s = new_service_state("example.com", BASE)
        for i in range(20):
            event = {"at": (BASE + timedelta(hours=i)).isoformat().replace("+00:00", "Z"), "result": "ALIVE"}
            update_history(s, event, BASE + timedelta(hours=20), CFG)
        self.assertEqual(len(s["history"]), 20)
        self.assertEqual(s["stability_score"], 100.0)

    def test_history_drops_older_than_14_days(self):
        s = new_service_state("example.com", BASE)
        s["history"] = [
            {"at": "2026-07-01T00:00:00Z", "result": "FAILURE"},
            {"at": "2026-08-19T00:00:00Z", "result": "ALIVE"},
        ]
        update_history(s, {"at": "2026-08-20T00:00:00Z", "result": "ALIVE"}, BASE, CFG)
        self.assertEqual(len(s["history"]), 2)
        self.assertEqual(s["stability_score"], 100.0)

    def test_legacy_failure_string_is_migrated(self):
        s = {"last_failure": "2026-08-20T00:00:00Z"}
        normalize_service_entry(s)
        self.assertEqual(s["last_failure"]["type"], "LEGACY")
        self.assertIsNone(s["failure_since"])
