from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .runtime_candidate_eligibility import (
    candidate_eligibility_settings as normalize_candidate_eligibility_settings,
)
from .runtime_candidate_maturity import (
    candidate_maturity_settings as normalize_candidate_maturity_settings,
)
from .utils import load_json, normalize_hostname, safe_path


ELIGIBILITY_VERSION = 1
ELIGIBILITY_MODE = "shadow"

DEFAULT_MIN_SEEN_DAYS = 2
DEFAULT_MIN_OBSERVATION_COUNT = 2

ELIGIBILITY_DECISIONS = frozenset(
    {
        "observed",
        "candidate",
    }
)

_PREVIOUS_DECISIONS = frozenset(
    {
        "observed",
        "candidate",
        "observe_only",
        "rejected",
    }
)

_ALLOWED_SETTINGS = frozenset(
    {
        "enabled",
        "min_seen_days",
        "min_observation_count",
    }
)


def candidate_eligibility_settings(
    raw: dict[str, Any] | None,
) -> dict[str, Any]:
    """
    Validate and normalize Candidate Eligibility v1 settings.

    Candidate Eligibility is default-off and only decides whether an
    otherwise-unclassified Runtime Candidate may move from observed to
    candidate in shadow mode.
    """

    if raw is None:
        raw = {}

    if not isinstance(raw, dict):
        raise ValueError(
            "candidate_eligibility must be an object"
        )

    unknown = set(raw) - _ALLOWED_SETTINGS

    if unknown:
        raise ValueError(
            "Unknown candidate_eligibility setting(s): "
            + ", ".join(sorted(unknown))
        )

    enabled = raw.get("enabled", False)
    min_seen_days = raw.get(
        "min_seen_days",
        DEFAULT_MIN_SEEN_DAYS,
    )
    min_observation_count = raw.get(
        "min_observation_count",
        DEFAULT_MIN_OBSERVATION_COUNT,
    )

    if not isinstance(enabled, bool):
        raise ValueError(
            "candidate_eligibility.enabled must be boolean"
        )

    if (
        type(min_seen_days) is not int
        or min_seen_days < 1
    ):
        raise ValueError(
            "candidate_eligibility.min_seen_days "
            "must be integer >= 1"
        )

    if (
        type(min_observation_count) is not int
        or min_observation_count < 1
    ):
        raise ValueError(
            "candidate_eligibility.min_observation_count "
            "must be integer >= 1"
        )

    return {
        "enabled": enabled,
        "min_seen_days": min_seen_days,
        "min_observation_count": min_observation_count,
    }


def _runtime_evidence(
    candidate: dict[str, Any],
) -> dict[str, Any]:
    if not isinstance(candidate, dict):
        raise ValueError(
            "Runtime Candidate entry must be an object"
        )

    feed_present = candidate.get("feed_present")

    if not isinstance(feed_present, bool):
        raise ValueError(
            "Runtime Candidate feed_present must be boolean"
        )

    observation_count = candidate.get(
        "observation_count"
    )

    if (
        type(observation_count) is not int
        or observation_count < 0
    ):
        raise ValueError(
            "Runtime Candidate observation_count "
            "must be integer >= 0"
        )

    seen_dates = candidate.get("seen_dates")

    if not isinstance(seen_dates, list):
        raise ValueError(
            "Runtime Candidate seen_dates must be an array"
        )

    if any(
        not isinstance(value, str)
        for value in seen_dates
    ):
        raise ValueError(
            "Runtime Candidate seen_dates entries "
            "must be strings"
        )

    return {
        "feed_present": feed_present,
        "seen_days": len(set(seen_dates)),
        "observation_count": observation_count,
    }


def evaluate_candidate_eligibility(
    candidate: dict[str, Any],
    *,
    previous_decision: str | None = None,
    settings: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """
    Evaluate observed -> candidate eligibility in shadow mode.

    This function has no authority over Exact DNS, Routing Suffixes,
    covered_by_suffix, or promoted_exact.

    A previously reached candidate state is retained when runtime
    observation temporarily disappears. Observer absence is therefore
    never treated as negative evidence.
    """

    normalized_settings = candidate_eligibility_settings(
        settings
    )
    evidence = _runtime_evidence(candidate)

    if (
        previous_decision is not None
        and previous_decision not in _PREVIOUS_DECISIONS
    ):
        raise ValueError(
            "Unsupported previous Runtime Candidate "
            f"classification decision: {previous_decision}"
        )

    if previous_decision == "candidate":
        decision = "candidate"
        reason = "candidate_retained"

    elif not normalized_settings["enabled"]:
        decision = "observed"
        reason = "candidate_eligibility_disabled"

    elif not evidence["feed_present"]:
        decision = "observed"
        reason = "candidate_eligibility_feed_absent"

    elif (
        evidence["seen_days"]
        < normalized_settings["min_seen_days"]
    ):
        decision = "observed"
        reason = "candidate_eligibility_insufficient_seen_days"

    elif (
        evidence["observation_count"]
        < normalized_settings["min_observation_count"]
    ):
        decision = "observed"
        reason = (
            "candidate_eligibility_insufficient_observation_count"
        )

    else:
        decision = "candidate"
        reason = "candidate_eligibility_met"

    if decision not in ELIGIBILITY_DECISIONS:
        raise RuntimeError(
            "Unsupported Candidate Eligibility decision: "
            f"{decision}"
        )

    return {
        "version": ELIGIBILITY_VERSION,
        "mode": ELIGIBILITY_MODE,
        "decision": decision,
        "reason": reason,
        "criteria": normalized_settings,
        "evidence": evidence,
    }
