from __future__ import annotations

import unittest
from datetime import datetime, timezone

from dns_maintenance.daily_summary import (
    ServiceRecord,
    extract_snapshot,
    format_delta,
    parse_report,
    render_summary,
)


REPORT = """# Demo DNS Maintenance Report

Generated: `2026-08-21T18:00:00Z`

## DNS lifecycle

| State | Hosts |
|---|---:|
| Active | 43 |
| Pending | 26 |
| Suspect | 1 |
| Quarantine | 2 |
| Expired | 3 |

## HTTPS/TLS observation

| State | Hosts |
|---|---:|
| Alive | 40 |
| Unknown | 2 |
| Suspect | 1 |
| Dead | 0 |

## Discovery

Discovery state updated: `2026-08-21T18:00:00Z`
"""


class DailySummaryTests(unittest.TestCase):
    def test_parse_report(self) -> None:
        generated, dns, https = parse_report(REPORT)
        self.assertEqual(generated, "2026-08-21T18:00:00Z")
        self.assertEqual(dns["active"], 43)
        self.assertEqual(dns["pending"], 26)
        self.assertEqual(dns["quarantine"], 2)
        self.assertEqual(https["alive"], 40)
        self.assertEqual(https["suspect"], 1)

    def test_format_delta(self) -> None:
        self.assertEqual(format_delta(None, 43), "— → **43**")
        self.assertEqual(format_delta(43, 45), "43 → **45** (+2)")
        self.assertEqual(format_delta(45, 43), "45 → **43** (-2)")
        self.assertEqual(format_delta(43, 43), "43 → **43** (0)")

    def test_snapshot_round_trip(self) -> None:
        record = ServiceRecord(
            key="DKHNV/Meta#meta",
            repo="DKHNV/Meta",
            collection="meta",
            report_url="https://example.invalid/report",
            report_generated_at="2026-08-21T18:00:00Z",
            dns={"active": 43, "pending": 26, "suspect": 0, "quarantine": 0, "expired": 0},
            https={"alive": 42, "unknown": 1, "suspect": 0, "dead": 0},
        )
        body, snapshot = render_summary(
            [record],
            None,
            now_utc=datetime(2026, 8, 21, 18, 30, tzinfo=timezone.utc),
            local_timezone="Europe/Helsinki",
            stale_after_hours=12,
            mention="DKHNV",
        )
        restored = extract_snapshot(body)
        self.assertEqual(restored, snapshot)
        self.assertIn("Meta", body)
        self.assertIn("43", body)
        self.assertIn("первый snapshot", body)

    def test_previous_delta_is_rendered(self) -> None:
        record = ServiceRecord(
            key="DKHNV/Meta#meta",
            repo="DKHNV/Meta",
            collection="meta",
            report_url="https://example.invalid/report",
            report_generated_at="2026-08-21T18:00:00Z",
            dns={"active": 45, "pending": 20, "suspect": 0, "quarantine": 0, "expired": 0},
            https={"alive": 44, "unknown": 1, "suspect": 0, "dead": 0},
        )
        previous = {
            "version": 1,
            "created_at": "2026-08-20T18:30:00Z",
            "services": {
                "DKHNV/Meta#meta": {
                    "repo": "DKHNV/Meta",
                    "collection": "meta",
                    "active": 43,
                    "pending": 26,
                    "suspect": 0,
                    "quarantine": 0,
                    "expired": 0,
                    "https_alive": 42,
                    "https_unknown": 1,
                    "https_suspect": 0,
                    "https_dead": 0,
                }
            },
        }
        body, _ = render_summary(
            [record],
            previous,
            now_utc=datetime(2026, 8, 21, 18, 30, tzinfo=timezone.utc),
            local_timezone="Europe/Helsinki",
            stale_after_hours=12,
            mention=None,
        )
        self.assertIn("43 → **45** (+2)", body)
        self.assertIn("26 → **20** (-6)", body)


if __name__ == "__main__":
    unittest.main()
