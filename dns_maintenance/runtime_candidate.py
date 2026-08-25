from __future__ import annotations

import copy
import hashlib
import json
import re
import uuid
from datetime import datetime
from typing import Any

from .utils import iso, normalize_hostname


FEED_SCHEMA_VERSION = 1
CANDIDATE_ID_VERSION = 1
HISTORY_SCOPE = "since_analytics_start"
HASH_ALGORITHM = "sha256"
CANDIDATE_ID_NAMESPACE = "runtime-candidate:v1"

HEX64_RE = re.compile(r"^[0-9a-f]{64}$")

FORBIDDEN_ROUTING_KEYS = {
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
}

REQUIRED_CANDIDATE_KEYS = {
    "id_version",
    "candidate_id",
    "hostname",
    "suffix",
    "state",
    "first_observed",
    "last_observed",
    "current_presence",
    "current_routing_status",
    "observation_count",
    "presence_cycles",
    "active_cycles",
    "reactivation_count",
    "seen_dates",
    "last_external_at",
}

COUNTER_KEYS = {
    "observation_count",
    "presence_cycles",
    "active_cycles",
    "reactivation_count",
}


RUNTIME_METRIC_FIELDS = (
    "first_observed",
    "last_observed",
    "current_presence",
    "current_routing_status",
    "observation_count",
    "presence_cycles",
    "active_cycles",
    "reactivation_count",
    "seen_dates",
    "last_external_at",
)

RUNTIME_CANDIDATE_STATE_VERSION = 1


def runtime_candidate_id(
    service: str,
    suffix: str,
    hostname: str,
) -> str:
    payload = (
        CANDIDATE_ID_NAMESPACE
        + "\0"
        + service
        + "\0"
        + suffix
        + "\0"
        + hostname
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _canonical_core(feed: dict[str, Any]) -> bytes:
    core = {
        "schema_version": feed["schema_version"],
        "service": feed["service"],
        "observer_id": feed["observer_id"],
        "history_scope": feed["history_scope"],
        "candidates": feed["candidates"],
    }
    return json.dumps(
        core,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def _contains_forbidden_routing_key(value: Any) -> str | None:
    if isinstance(value, dict):
        for key, child in value.items():
            key_text = str(key).lower()
            if key_text in FORBIDDEN_ROUTING_KEYS:
                return key_text
            found = _contains_forbidden_routing_key(child)
            if found:
                return found
    elif isinstance(value, list):
        for child in value:
            found = _contains_forbidden_routing_key(child)
            if found:
                return found
    return None


def _validate_uuid4(value: Any) -> None:
    if not isinstance(value, str) or not value:
        raise ValueError("observer_id must be UUIDv4")
    try:
        parsed = uuid.UUID(value)
    except (ValueError, AttributeError) as exc:
        raise ValueError("observer_id must be UUIDv4") from exc
    if parsed.version != 4 or parsed.variant != uuid.RFC_4122:
        raise ValueError("observer_id must be UUIDv4")


def _validate_normalized_hostname(value: Any, field: str) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{field} must be a normalized hostname")
    normalized = normalize_hostname(value)
    if normalized is None or normalized != value:
        raise ValueError(f"{field} must be a normalized hostname")
    return normalized


def _validate_candidate(
    candidate: Any,
    service: str,
) -> dict[str, Any]:
    if not isinstance(candidate, dict):
        raise ValueError("candidate must be an object")

    missing = REQUIRED_CANDIDATE_KEYS - set(candidate)
    if missing:
        raise ValueError(
            "candidate missing required field(s): "
            + ", ".join(sorted(missing))
        )

    forbidden = _contains_forbidden_routing_key(candidate)
    if forbidden:
        raise ValueError(
            f"candidate contains forbidden routing key: {forbidden}"
        )

    if type(candidate["id_version"]) is not int:
        raise ValueError("candidate.id_version must be integer")
    if candidate["id_version"] != CANDIDATE_ID_VERSION:
        raise ValueError("unsupported candidate.id_version")

    candidate_id = candidate["candidate_id"]
    if not isinstance(candidate_id, str) or not HEX64_RE.fullmatch(candidate_id):
        raise ValueError("candidate_id must be lowercase hex64")

    hostname = _validate_normalized_hostname(
        candidate["hostname"],
        "candidate.hostname",
    )
    suffix = _validate_normalized_hostname(
        candidate["suffix"],
        "candidate.suffix",
    )

    if hostname != suffix and not hostname.endswith("." + suffix):
        raise ValueError("candidate hostname is outside suffix")

    expected_id = runtime_candidate_id(
        service,
        suffix,
        hostname,
    )
    if candidate_id != expected_id:
        raise ValueError("candidate_id does not match candidate identity")

    if candidate["state"] != "observed":
        raise ValueError("candidate.state must be observed")

    if not isinstance(candidate["current_presence"], bool):
        raise ValueError("candidate.current_presence must be boolean")

    for key in COUNTER_KEYS:
        value = candidate[key]
        if type(value) is not int or value < 0:
            raise ValueError(f"candidate.{key} must be integer >= 0")

    if not isinstance(candidate["seen_dates"], list):
        raise ValueError("candidate.seen_dates must be an array")

    return candidate


def validate_runtime_candidate_feed(
    feed: Any,
    expected_service: str,
) -> dict[str, Any]:
    if not isinstance(feed, dict):
        raise ValueError("Runtime Candidate Feed must be an object")

    if type(feed.get("schema_version")) is not int:
        raise ValueError("schema_version must be integer")
    if feed["schema_version"] != FEED_SCHEMA_VERSION:
        raise ValueError("unsupported Runtime Candidate Feed schema_version")

    service = feed.get("service")
    if service != expected_service:
        raise ValueError("Runtime Candidate Feed service mismatch")

    _validate_uuid4(feed.get("observer_id"))

    if feed.get("history_scope") != HISTORY_SCOPE:
        raise ValueError("unsupported Runtime Candidate Feed history_scope")

    generated_at = feed.get("generated_at")
    if not isinstance(generated_at, str) or not generated_at:
        raise ValueError("generated_at is required")

    if feed.get("hash_algorithm") != HASH_ALGORITHM:
        raise ValueError("hash_algorithm must be sha256")

    content_hash = feed.get("content_hash")
    if not isinstance(content_hash, str) or not HEX64_RE.fullmatch(content_hash):
        raise ValueError("content_hash must be lowercase hex64")

    candidates = feed.get("candidates")
    if not isinstance(candidates, list):
        raise ValueError("candidates must be an array")

    actual_hash = hashlib.sha256(_canonical_core(feed)).hexdigest()
    if content_hash != actual_hash:
        raise ValueError("Runtime Candidate Feed content_hash mismatch")

    seen_candidate_ids: set[str] = set()
    seen_hostnames: set[str] = set()

    for candidate in candidates:
        validated = _validate_candidate(candidate, service)
        candidate_id = validated["candidate_id"]
        hostname = validated["hostname"]

        if candidate_id in seen_candidate_ids:
            raise ValueError("duplicate candidate_id")
        if hostname in seen_hostnames:
            raise ValueError("duplicate candidate hostname")

        seen_candidate_ids.add(candidate_id)
        seen_hostnames.add(hostname)

    return feed


def merge_runtime_candidate_state(
    previous: Any,
    feed: dict[str, Any],
    now: datetime,
) -> dict[str, Any]:
    service = feed["service"]
    observer_id = feed["observer_id"]
    intake_at = iso(now)

    if previous is None:
        previous = {}

    if not isinstance(previous, dict):
        raise ValueError("Runtime Candidate state must be an object")

    if previous:
        if previous.get("schema_version") != RUNTIME_CANDIDATE_STATE_VERSION:
            raise ValueError("unsupported Runtime Candidate state schema_version")

        if previous.get("service") != service:
            raise ValueError("Runtime Candidate state service mismatch")

        previous_observer = previous.get("observer_id")
        if previous_observer and previous_observer != observer_id:
            raise ValueError("Runtime Candidate state observer_id mismatch")

        if not isinstance(previous.get("candidates"), dict):
            raise ValueError("Runtime Candidate state candidates must be an object")

    state = copy.deepcopy(previous)

    state["schema_version"] = RUNTIME_CANDIDATE_STATE_VERSION
    state["service"] = service
    state["observer_id"] = observer_id
    state["source_content_hash"] = feed["content_hash"]
    state["source_generated_at"] = feed["generated_at"]
    state["last_intake_at"] = intake_at
    state["last_intake_status"] = "ok"

    candidates = state.setdefault("candidates", {})

    for candidate_id, existing in candidates.items():
        if not isinstance(existing, dict):
            raise ValueError(
                f"Runtime Candidate state entry is invalid: {candidate_id}"
            )
        existing["feed_present"] = False

    for source in feed["candidates"]:
        candidate_id = source["candidate_id"]
        existing = candidates.get(candidate_id)

        if existing is None:
            existing = {
                "candidate_id": candidate_id,
                "hostname": source["hostname"],
                "suffix": source["suffix"],
                "state": "observed",
                "first_intake_at": intake_at,
            }
            candidates[candidate_id] = existing
        else:
            if existing.get("candidate_id") != candidate_id:
                raise ValueError("Runtime Candidate state candidate_id mismatch")
            if existing.get("hostname") != source["hostname"]:
                raise ValueError("Runtime Candidate state hostname mismatch")
            if existing.get("suffix") != source["suffix"]:
                raise ValueError("Runtime Candidate state suffix mismatch")

            if not isinstance(existing.get("state"), str) or not existing["state"]:
                raise ValueError("Runtime Candidate state candidate state is invalid")

        existing["last_intake_at"] = intake_at
        existing["feed_present"] = True

        for field in RUNTIME_METRIC_FIELDS:
            existing[field] = copy.deepcopy(source[field])

    return state
