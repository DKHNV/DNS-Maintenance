import unittest
from datetime import datetime, timedelta, timezone

from dns_maintenance.config import DNSSettings
from dns_maintenance.dns_engine import (
    DNSResult,
    aggregate_resolver_results,
    apply_dns_result,
    new_host_state,
    normalize_dns_entry,
    partition_public_unicast_ipv4,
)

UTC = timezone.utc
BASE = datetime(2026, 8, 20, 0, 0, tzinfo=UTC)
SETTINGS = DNSSettings(
    resolvers=("1.1.1.1", "8.8.8.8", "9.9.9.9"), timeout_seconds=2, lifetime_seconds=4,
    negative_votes_required=2, suspect_after_hours=72, quarantine_after_hours=168,
    expire_after_hours=720, negative_streak_max_gap_hours=48,
    suspect_min_negative_observations=3, quarantine_min_negative_observations=7, max_workers=20,
)
NEG = DNSResult("NEGATIVE", tuple(), None, {"1.1.1.1": {"status": "NXDOMAIN"}, "8.8.8.8": {"status": "NXDOMAIN"}})
OK = DNSResult("OK", ("1.2.3.4",), "example.com", {"1.1.1.1": {"status": "OK", "ipv4": ["1.2.3.4"]}})
TRANSIENT = DNSResult("TRANSIENT", tuple(), None, {"1.1.1.1": {"status": "TIMEOUT"}})


class DNSTests(unittest.TestCase):
    def test_public_unicast_filter_rejects_non_routable_ranges(self):
        public, rejected = partition_public_unicast_ipv4([
            "8.8.8.8",
            "10.104.0.5",
            "100.64.0.1",
            "127.0.0.1",
            "169.254.1.1",
            "192.0.2.1",
            "224.0.0.1",
            "242.243.0.66",
            "0.0.0.0",
        ])
        self.assertEqual(public, ["8.8.8.8"])
        self.assertEqual(
            set(rejected),
            {
                "10.104.0.5",
                "100.64.0.1",
                "127.0.0.1",
                "169.254.1.1",
                "192.0.2.1",
                "224.0.0.1",
                "242.243.0.66",
                "0.0.0.0",
            },
        )

    def test_aggregate_any_public_ipv4_wins(self):
        r = aggregate_resolver_results({"a": {"status": "NXDOMAIN"}, "b": {"status": "OK", "ipv4": ["2.2.2.2"]}}, 2)
        self.assertEqual(r.aggregate, "OK")

    def test_aggregate_mixed_public_private_keeps_only_public(self):
        r = aggregate_resolver_results({
            "a": {"status": "OK", "ipv4": ["8.8.8.8", "10.104.0.5"], "canonical_name": "example.com"},
            "b": {"status": "NXDOMAIN"},
        }, 2)
        self.assertEqual(r.aggregate, "OK")
        self.assertEqual(r.ipv4, ("8.8.8.8",))
        self.assertEqual(r.resolver_results["a"]["ipv4"], ["8.8.8.8"])
        self.assertEqual(r.resolver_results["a"]["non_global_ipv4"], ["10.104.0.5"])
        self.assertFalse(r.unroutable)

    def test_aggregate_private_only_is_negative_and_unroutable(self):
        r = aggregate_resolver_results({
            "a": {"status": "OK", "ipv4": ["10.104.0.5"]},
            "b": {"status": "OK", "ipv4": ["10.104.0.6"]},
            "c": {"status": "TIMEOUT"},
        }, 2)
        self.assertEqual(r.aggregate, "NEGATIVE")
        self.assertEqual(r.ipv4, tuple())
        self.assertTrue(r.unroutable)
        self.assertEqual(r.resolver_results["a"]["status"], "NON_GLOBAL_A")
        self.assertEqual(r.resolver_results["b"]["status"], "NON_GLOBAL_A")

    def test_one_private_vote_without_consensus_is_transient(self):
        r = aggregate_resolver_results({
            "a": {"status": "OK", "ipv4": ["10.104.0.5"]},
            "b": {"status": "TIMEOUT"},
            "c": {"status": "TIMEOUT"},
        }, 2)
        self.assertEqual(r.aggregate, "TRANSIENT")
        self.assertFalse(r.unroutable)

    def test_aggregate_two_negative_votes(self):
        r = aggregate_resolver_results({"a": {"status": "NXDOMAIN"}, "b": {"status": "NO_A"}, "c": {"status": "TIMEOUT"}}, 2)
        self.assertEqual(r.aggregate, "NEGATIVE")

    def test_aggregate_mixed_uncertain_is_transient(self):
        r = aggregate_resolver_results({"a": {"status": "NXDOMAIN"}, "b": {"status": "TIMEOUT"}, "c": {"status": "TIMEOUT"}}, 2)
        self.assertEqual(r.aggregate, "TRANSIENT")

    def test_first_negative_does_not_suspect(self):
        s = new_host_state("example.com", BASE, "legacy_active", True)
        _, new = apply_dns_result(s, NEG, BASE, SETTINGS)
        self.assertEqual(new, "active")
        self.assertEqual(s["negative_observations"], 1)

    def test_unroutable_immediately_quarantines_published_host(self):
        s = new_host_state("example.com", BASE, "legacy_active", True)
        unroutable = DNSResult(
            "NEGATIVE",
            tuple(),
            None,
            {
                "1.1.1.1": {"status": "NON_GLOBAL_A", "non_global_ipv4": ["10.104.0.5"]},
                "8.8.8.8": {"status": "NON_GLOBAL_A", "non_global_ipv4": ["10.104.0.6"]},
            },
            True,
        )
        _, new = apply_dns_result(s, unroutable, BASE, SETTINGS)
        self.assertEqual(new, "quarantine")
        self.assertEqual(s["status"], "quarantine")
        self.assertEqual(s["safety_reason"], "NON_GLOBAL_A")
        self.assertEqual(s["quarantined_at"], "2026-08-20T00:00:00Z")

    def test_unroutable_new_candidate_is_not_published(self):
        s = new_host_state("example.com", BASE, "certspotter:test", False)
        unroutable = DNSResult(
            "NEGATIVE",
            tuple(),
            None,
            {
                "1.1.1.1": {"status": "NON_GLOBAL_A", "non_global_ipv4": ["10.104.0.5"]},
                "8.8.8.8": {"status": "NON_GLOBAL_A", "non_global_ipv4": ["10.104.0.6"]},
            },
            True,
        )
        _, new = apply_dns_result(s, unroutable, BASE, SETTINGS)
        self.assertEqual(new, "pending")
        self.assertFalse(s["ever_validated"])
        self.assertEqual(s["safety_reason"], "NON_GLOBAL_A")

    def test_suspect_requires_time_and_observations(self):
        s = new_host_state("example.com", BASE, "legacy_active", True)
        s.update({"negative_since": "2026-08-20T00:00:00Z", "last_negative": "2026-08-22T00:00:00Z", "negative_observations": 2})
        _, new = apply_dns_result(s, NEG, BASE + timedelta(hours=72), SETTINGS)
        self.assertEqual(new, "suspect")

    def test_time_without_enough_observations_does_not_suspect(self):
        s = new_host_state("example.com", BASE, "legacy_active", True)
        s.update({"negative_since": "2026-08-20T00:00:00Z", "last_negative": "2026-08-22T18:00:00Z", "negative_observations": 1})
        _, new = apply_dns_result(s, NEG, BASE + timedelta(hours=72), SETTINGS)
        self.assertEqual(new, "active")

    def test_quarantine_after_week_and_evidence(self):
        s = new_host_state("example.com", BASE, "legacy_active", True)
        s.update({"status": "suspect", "negative_since": "2026-08-20T00:00:00Z", "last_negative": "2026-08-26T18:00:00Z", "negative_observations": 6})
        _, new = apply_dns_result(s, NEG, BASE + timedelta(hours=168), SETTINGS)
        self.assertEqual(new, "quarantine")

    def test_gap_restarts_negative_window(self):
        s = new_host_state("example.com", BASE, "legacy_active", True)
        s.update({"negative_since": "2026-08-20T00:00:00Z", "last_negative": "2026-08-20T06:00:00Z", "negative_observations": 9})
        apply_dns_result(s, NEG, BASE + timedelta(hours=72), SETTINGS)
        self.assertEqual(s["negative_observations"], 1)
        self.assertEqual(s["negative_since"], "2026-08-23T00:00:00Z")

    def test_transient_does_not_advance_negative_window(self):
        s = new_host_state("example.com", BASE, "legacy_active", True)
        s.update({"negative_since": "2026-08-20T00:00:00Z", "last_negative": "2026-08-20T06:00:00Z", "negative_observations": 2})
        apply_dns_result(s, TRANSIENT, BASE + timedelta(hours=24), SETTINGS)
        self.assertEqual(s["negative_observations"], 2)
        self.assertEqual(s["status"], "active")

    def test_ok_resets_and_revives(self):
        s = new_host_state("example.com", BASE, "legacy_active", True)
        s.update({
            "status": "quarantine",
            "negative_since": "2026-08-10T00:00:00Z",
            "negative_observations": 10,
            "quarantined_at": "2026-08-15T00:00:00Z",
            "safety_reason": "NON_GLOBAL_A",
        })
        _, new = apply_dns_result(s, OK, BASE, SETTINGS)
        self.assertEqual(new, "active")
        self.assertIsNone(s["negative_since"])
        self.assertEqual(s["ipv4"], ["1.2.3.4"])
        self.assertIsNone(s["safety_reason"])

    def test_quarantine_expires_by_elapsed_time(self):
        s = new_host_state("example.com", BASE, "legacy_active", True)
        s.update({"status": "quarantine", "quarantined_at": "2026-07-21T00:00:00Z"})
        _, new = apply_dns_result(s, NEG, BASE, SETTINGS)
        self.assertEqual(new, "expired")

    def test_v1_migration_does_not_infer_negative_since(self):
        s = {"consecutive_negative_checks": 6, "last_failure": "2026-08-19T00:00:00Z"}
        normalize_dns_entry(s)
        self.assertIsNone(s["negative_since"])
        self.assertEqual(s["last_negative"], "2026-08-19T00:00:00Z")
        self.assertIsNone(s["safety_reason"])
