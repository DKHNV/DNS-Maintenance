from __future__ import annotations

import unittest

from dns_maintenance.daily_summary_schedule import body_has_summary_for_local_date


class DailySummaryScheduleTests(unittest.TestCase):
    def test_visible_heading_detects_existing_summary(self) -> None:
        body = """@DKHNV

## DNS Maintenance · 2026-08-22 00:17 EEST
"""
        self.assertTrue(
            body_has_summary_for_local_date(
                body,
                "2026-08-22",
                "Europe/Helsinki",
            )
        )

    def test_snapshot_timestamp_uses_local_date(self) -> None:
        body = (
            '<!-- dns-maintenance-snapshot:'
            '{"version":1,"created_at":"2026-08-21T21:30:00Z","services":{}}'
            '-->'
        )
        self.assertTrue(
            body_has_summary_for_local_date(
                body,
                "2026-08-22",
                "Europe/Helsinki",
            )
        )

    def test_wrong_date_is_not_duplicate(self) -> None:
        body = """## DNS Maintenance · 2026-08-21 12:13 EEST"""
        self.assertFalse(
            body_has_summary_for_local_date(
                body,
                "2026-08-22",
                "Europe/Helsinki",
            )
        )


if __name__ == "__main__":
    unittest.main()
