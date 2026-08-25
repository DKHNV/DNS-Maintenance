import hashlib
import json
import unittest
import uuid

from dns_maintenance.runtime_candidate import (
    runtime_candidate_id,
    validate_runtime_candidate_feed,
)


class RuntimeCandidateTests(unittest.TestCase):
    def candidate(self, service="netflix"):
        hostname = "ipv4-c001-rix001-retn-isp.1.oca.nflxvideo.net"
        suffix = "nflxvideo.net"
        return {
            "id_version": 1,
            "candidate_id": runtime_candidate_id(
                service,
                suffix,
                hostname,
            ),
            "hostname": hostname,
            "suffix": suffix,
            "state": "observed",
            "first_observed": "2026-08-25T08:28:56Z",
            "last_observed": "2026-08-25T08:29:01Z",
            "current_presence": True,
            "current_routing_status": "expired",
            "observation_count": 2,
            "presence_cycles": 14,
            "active_cycles": 0,
            "reactivation_count": 0,
            "seen_dates": ["2026-08-24"],
            "last_external_at": "2026-08-24T19:12:05Z",
        }

    def feed(self, service="netflix"):
        feed = {
            "schema_version": 1,
            "service": service,
            "observer_id": str(uuid.uuid4()),
            "history_scope": "since_analytics_start",
            "candidates": [self.candidate(service)],
            "generated_at": "2026-08-25T09:00:00Z",
            "hash_algorithm": "sha256",
        }
        self.rehash(feed)
        return feed

    def rehash(self, feed):
        core = {
            "schema_version": feed["schema_version"],
            "service": feed["service"],
            "observer_id": feed["observer_id"],
            "history_scope": feed["history_scope"],
            "candidates": feed["candidates"],
        }
        canonical = json.dumps(
            core,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")
        feed["content_hash"] = hashlib.sha256(canonical).hexdigest()

    def test_valid_feed_is_accepted(self):
        feed = self.feed()
        self.assertIs(
            validate_runtime_candidate_feed(feed, "netflix"),
            feed,
        )

    def test_wrong_service_is_rejected(self):
        feed = self.feed()
        with self.assertRaisesRegex(ValueError, "service mismatch"):
            validate_runtime_candidate_feed(feed, "youtube")

    def test_wrong_schema_is_rejected(self):
        feed = self.feed()
        feed["schema_version"] = 2
        with self.assertRaisesRegex(ValueError, "schema_version"):
            validate_runtime_candidate_feed(feed, "netflix")

    def test_bad_observer_uuid_is_rejected(self):
        feed = self.feed()
        feed["observer_id"] = "not-a-uuid"
        self.rehash(feed)
        with self.assertRaisesRegex(ValueError, "UUIDv4"):
            validate_runtime_candidate_feed(feed, "netflix")

    def test_bad_content_hash_is_rejected(self):
        feed = self.feed()
        feed["content_hash"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "content_hash mismatch"):
            validate_runtime_candidate_feed(feed, "netflix")

    def test_bad_candidate_id_is_rejected(self):
        feed = self.feed()
        feed["candidates"][0]["candidate_id"] = "0" * 64
        self.rehash(feed)
        with self.assertRaisesRegex(
            ValueError,
            "candidate_id does not match",
        ):
            validate_runtime_candidate_feed(feed, "netflix")

    def test_duplicate_candidate_id_is_rejected(self):
        feed = self.feed()
        duplicate = dict(feed["candidates"][0])
        feed["candidates"].append(duplicate)
        self.rehash(feed)
        with self.assertRaisesRegex(ValueError, "duplicate candidate_id"):
            validate_runtime_candidate_feed(feed, "netflix")

    def test_duplicate_hostname_is_rejected(self):
        feed = self.feed()
        duplicate = dict(feed["candidates"][0])
        duplicate["suffix"] = "oca.nflxvideo.net"
        duplicate["candidate_id"] = runtime_candidate_id(
            "netflix",
            duplicate["suffix"],
            duplicate["hostname"],
        )
        feed["candidates"].append(duplicate)
        self.rehash(feed)
        with self.assertRaisesRegex(
            ValueError,
            "duplicate candidate hostname",
        ):
            validate_runtime_candidate_feed(feed, "netflix")

    def test_hostname_must_be_inside_suffix(self):
        feed = self.feed()
        candidate = feed["candidates"][0]
        candidate["suffix"] = "nflxso.net"
        candidate["candidate_id"] = runtime_candidate_id(
            "netflix",
            candidate["suffix"],
            candidate["hostname"],
        )
        self.rehash(feed)
        with self.assertRaisesRegex(ValueError, "outside suffix"):
            validate_runtime_candidate_feed(feed, "netflix")

    def test_candidate_state_must_be_observed(self):
        feed = self.feed()
        feed["candidates"][0]["state"] = "candidate"
        self.rehash(feed)
        with self.assertRaisesRegex(ValueError, "state must be observed"):
            validate_runtime_candidate_feed(feed, "netflix")

    def test_current_presence_must_be_boolean(self):
        feed = self.feed()
        feed["candidates"][0]["current_presence"] = 1
        self.rehash(feed)
        with self.assertRaisesRegex(ValueError, "current_presence"):
            validate_runtime_candidate_feed(feed, "netflix")

    def test_counters_reject_bool_and_negative_values(self):
        for value in (True, -1):
            with self.subTest(value=value):
                feed = self.feed()
                feed["candidates"][0]["observation_count"] = value
                self.rehash(feed)
                with self.assertRaisesRegex(
                    ValueError,
                    "observation_count",
                ):
                    validate_runtime_candidate_feed(feed, "netflix")

    def test_seen_dates_must_be_array(self):
        feed = self.feed()
        feed["candidates"][0]["seen_dates"] = "2026-08-24"
        self.rehash(feed)
        with self.assertRaisesRegex(ValueError, "seen_dates"):
            validate_runtime_candidate_feed(feed, "netflix")

    def test_forbidden_routing_keys_are_rejected_recursively(self):
        for key in (
            "ipv4",
            "ipv4_seen",
            "network",
            "networks_seen",
            "cidr",
            "ttl",
            "ttl_min",
            "ttl_max",
            "last_ttl_min",
            "last_ttl_max",
        ):
            with self.subTest(key=key):
                feed = self.feed()
                feed["candidates"][0]["nested"] = {
                    "deeper": {
                        key: "forbidden",
                    }
                }
                self.rehash(feed)
                with self.assertRaisesRegex(
                    ValueError,
                    "forbidden routing key",
                ):
                    validate_runtime_candidate_feed(feed, "netflix")
