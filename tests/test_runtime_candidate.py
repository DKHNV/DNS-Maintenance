import hashlib
import json
import unittest
import uuid
from datetime import datetime, timezone

from dns_maintenance.runtime_candidate import (
    merge_runtime_candidate_state,
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

    def now(self):
        return datetime(2026, 8, 25, 10, 30, tzinfo=timezone.utc)

    def test_state_adds_new_candidate(self):
        feed = self.feed()
        validate_runtime_candidate_feed(feed, "netflix")

        state = merge_runtime_candidate_state(
            {},
            feed,
            self.now(),
        )

        candidate = feed["candidates"][0]
        stored = state["candidates"][candidate["candidate_id"]]

        self.assertEqual(state["schema_version"], 1)
        self.assertEqual(state["service"], "netflix")
        self.assertEqual(state["observer_id"], feed["observer_id"])
        self.assertEqual(
            state["source_content_hash"],
            feed["content_hash"],
        )
        self.assertEqual(state["last_intake_status"], "ok")

        self.assertEqual(stored["state"], "observed")
        self.assertTrue(stored["feed_present"])
        self.assertEqual(
            stored["first_intake_at"],
            "2026-08-25T10:30:00Z",
        )
        self.assertEqual(
            stored["last_intake_at"],
            "2026-08-25T10:30:00Z",
        )

    def test_existing_candidate_updates_runtime_metrics(self):
        feed = self.feed()
        state = merge_runtime_candidate_state(
            {},
            feed,
            self.now(),
        )

        candidate = feed["candidates"][0]
        candidate_id = candidate["candidate_id"]

        feed["candidates"][0]["observation_count"] = 9
        feed["candidates"][0]["presence_cycles"] = 20
        self.rehash(feed)

        later = datetime(
            2026,
            8,
            25,
            11,
            0,
            tzinfo=timezone.utc,
        )

        updated = merge_runtime_candidate_state(
            state,
            feed,
            later,
        )

        stored = updated["candidates"][candidate_id]

        self.assertEqual(stored["observation_count"], 9)
        self.assertEqual(stored["presence_cycles"], 20)
        self.assertEqual(
            stored["first_intake_at"],
            "2026-08-25T10:30:00Z",
        )
        self.assertEqual(
            stored["last_intake_at"],
            "2026-08-25T11:00:00Z",
        )
        self.assertTrue(stored["feed_present"])

    def test_missing_candidate_is_retained_and_marked_absent(self):
        feed = self.feed()
        state = merge_runtime_candidate_state(
            {},
            feed,
            self.now(),
        )

        candidate_id = feed["candidates"][0]["candidate_id"]
        original_last_intake = (
            state["candidates"][candidate_id]["last_intake_at"]
        )

        feed["candidates"] = []
        self.rehash(feed)

        later = datetime(
            2026,
            8,
            25,
            11,
            0,
            tzinfo=timezone.utc,
        )

        updated = merge_runtime_candidate_state(
            state,
            feed,
            later,
        )

        self.assertIn(candidate_id, updated["candidates"])
        stored = updated["candidates"][candidate_id]

        self.assertFalse(stored["feed_present"])
        self.assertEqual(
            stored["last_intake_at"],
            original_last_intake,
        )

    def test_feed_does_not_reset_central_candidate_state(self):
        feed = self.feed()
        state = merge_runtime_candidate_state(
            {},
            feed,
            self.now(),
        )

        candidate_id = feed["candidates"][0]["candidate_id"]
        state["candidates"][candidate_id]["state"] = "candidate"

        later = datetime(
            2026,
            8,
            25,
            11,
            0,
            tzinfo=timezone.utc,
        )

        updated = merge_runtime_candidate_state(
            state,
            feed,
            later,
        )

        self.assertEqual(
            updated["candidates"][candidate_id]["state"],
            "candidate",
        )

    def test_observer_change_is_rejected(self):
        feed = self.feed()
        state = merge_runtime_candidate_state(
            {},
            feed,
            self.now(),
        )

        feed["observer_id"] = str(uuid.uuid4())
        self.rehash(feed)

        with self.assertRaisesRegex(
            ValueError,
            "observer_id mismatch",
        ):
            merge_runtime_candidate_state(
                state,
                feed,
                self.now(),
            )

    def test_bad_existing_state_schema_is_rejected(self):
        feed = self.feed()

        previous = {
            "schema_version": 2,
            "service": "netflix",
            "observer_id": feed["observer_id"],
            "candidates": {},
        }

        with self.assertRaisesRegex(
            ValueError,
            "state schema_version",
        ):
            merge_runtime_candidate_state(
                previous,
                feed,
                self.now(),
            )

    def test_merge_does_not_mutate_previous_state(self):
        feed = self.feed()
        previous = merge_runtime_candidate_state(
            {},
            feed,
            self.now(),
        )

        snapshot = json.loads(json.dumps(previous))

        merge_runtime_candidate_state(
            previous,
            feed,
            self.now(),
        )

        self.assertEqual(previous, snapshot)
    
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
