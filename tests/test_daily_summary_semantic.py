from __future__ import annotations

import unittest
from datetime import datetime, timezone

from dns_maintenance import daily_summary_semantic_schedule as semantic


LEGACY_REPORT = """# Demo DNS Maintenance Report

Generated: `2026-08-23T12:00:00Z`

## DNS lifecycle

| State | Hosts |
|---|---:|
| Active | 10 |
| Pending | 2 |
| Suspect | 0 |
| Quarantine | 1 |
| Expired | 0 |

## HTTPS/TLS observation

| State | Hosts |
|---|---:|
| Alive | 9 |
| Unknown | 1 |
| Suspect | 0 |
| Dead | 0 |
"""

POLICY_REPORT = """# Demo DNS Maintenance Report

Generated: `2026-08-23T12:00:00Z`

## DNS lifecycle

| State | Hosts |
|---|---:|
| Active | 7 |
| Pending | 1 |
| Suspect | 0 |
| Quarantine | 0 |
| Excluded | 4 |
| Expired | 0 |

## HTTPS/TLS observation

| State | Hosts |
|---|---:|
| Alive | 7 |
| Unknown | 0 |
| Suspect | 0 |
| Dead | 0 |
"""


class DailySummarySemanticTests(unittest.TestCase):
    def test_legacy_report_defaults_excluded_to_zero(self) -> None:
        _, dns, _ = semantic.core.parse_report(LEGACY_REPORT)
        self.assertEqual(dns["active"], 10)
        self.assertEqual(dns["excluded"], 0)

    def test_policy_report_reads_excluded(self) -> None:
        _, dns, _ = semantic.core.parse_report(POLICY_REPORT)
        self.assertEqual(dns["active"], 7)
        self.assertEqual(dns["excluded"], 4)

    def test_missing_non_optional_counter_still_fails(self) -> None:
        broken = LEGACY_REPORT.replace("| Pending | 2 |\n", "")
        with self.assertRaises(ValueError):
            semantic.core.parse_report(broken)

    def test_summary_renders_excluded_delta_and_keeps_health_green(self) -> None:
        record = semantic.core.ServiceRecord(
            key="DKHNV/Grok#grok",
            repo="DKHNV/Grok",
            collection="grok",
            report_url="https://example.invalid/report",
            report_generated_at="2026-08-23T12:00:00Z",
            dns={
                "active": 83,
                "pending": 27,
                "suspect": 0,
                "quarantine": 0,
                "excluded": 18,
                "expired": 0,
            },
            https={"alive": 41, "unknown": 42, "suspect": 0, "dead": 0},
        )
        previous = {
            "version": 1,
            "created_at": "2026-08-22T12:00:00Z",
            "services": {
                "DKHNV/Grok#grok": {
                    "repo": "DKHNV/Grok",
                    "collection": "grok",
                    "active": 96,
                    "pending": 32,
                    "suspect": 0,
                    "quarantine": 0,
                    "expired": 0,
                    "https_alive": 41,
                    "https_unknown": 55,
                    "https_suspect": 0,
                    "https_dead": 0,
                }
            },
        }
        body, snapshot = semantic.core.render_summary(
            [record],
            previous,
            now_utc=datetime(2026, 8, 23, 12, 30, tzinfo=timezone.utc),
            local_timezone="Europe/Helsinki",
            stale_after_hours=12,
            mention=None,
        )
        self.assertIn("| Service | Active | Pending | Suspect | Quarantine | Excluded | HTTPS | Health |", body)
        self.assertIn("0 → **18** (+18)", body)
        self.assertIn("| Excluded | 0 → **18** (+18) |", body)
        self.assertIn("✅ current", body)
        self.assertEqual(snapshot["services"]["DKHNV/Grok#grok"]["excluded"], 18)


if __name__ == "__main__":
    unittest.main()
