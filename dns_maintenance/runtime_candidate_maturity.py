from __future__ import annotations

from datetime import datetime
from typing import Any

from .utils import hours_between, iso, parse_iso


MATURITY_VERSION = 1
MATURITY_MODE = "shadow"

DEFAULT_MIN_CANDIDATE_AGE_HOURS = 24.0
DEFAULT_MIN_ADDITIONAL_SEEN_DAYS = 1
DEFAULT_MIN_ADDITIONAL_OBSERVATION_COUNT = 1

MATURITY_STATES = frozenset(
    {
        "tracking",
        "ready",
    }
)

_ALLOWED_SETTINGS = frozenset(
    {
        "enabled",
        "min_candidate_age_hours",
        "min_additional_seen_days",
        "min_additional_observation_count",
    }
)


def candidate_maturity_settings(
    raw: dict[str, Any] | None,
) -> dict[str, Any]:
    """
    Validate and normalize Candidate Maturity v1 settings.

    Candidate Maturity is default-off. It never promotes a Runtime
    Candidate into Exact DNS. It only records whether an existing
    candidate is still tracking or has accumulated enough additional
    evidence to be considered ready for a later promotion policy.
    """

    if raw is None:
        raw = {}

    if not isinstance(raw, dict):
        raise ValueError(
            "candidate_maturity must be an object"
        )

    unknown = set(raw) - _ALLOWED_SETTINGS

    if unknown:
        raise ValueError(
            "Unknown candidate_maturity setting(s): "
            + ", ".join(sorted(unknown))
        )

    enabled = raw.get("enabled", False)
    min_candidate_age_hours = raw.get(
        "min_candidate_age_hours",
        DEFAULT_MIN_CANDIDATE_AGE_HOURS,
    )
    min_additional_seen_days = raw.get(
        "min_additional_seen_days",
        DEFAULT_MIN_ADDITIONAL_SEEN_DAYS,
    )
    min_additional_observation_count = raw.get(
        "min_additional_observation_count",
        DEFAULT_MIN_ADDITIONAL_OBSERVATION_COUNT,
    )

    if not isinstance(enabled, bool):
        raise ValueError(
            "candidate_maturity.enabled must be boolean"
        )

    if (
        isinstance(min_candidate_age_hours, bool)
        or not isinstance(
            min_candidate_age_hours,
            (int, float),
        )
        or float(min_candidate_age_hours) <= 0
    ):
        raise ValueError(
            "candidate_maturity.min_candidate_age_hours "
            "must be number > 0"
        )

    if (
        type(min_additional_seen_days) is not int
        or min_additional_seen_days < 1
    ):
        raise ValueError(
            "candidate_maturity.min_additional_seen_days "
            "must be integer >= 1"
        )

    if (
        type(min_additional_observation_count) is not int
        or min_additional_observation_count < 1
    ):
        raise ValueError(
            "candidate_maturity.min_additional_observation_count "
            "must be integer >= 1"
        )

    return {
        "enabled": enabled,
        "min_candidate_age_hours": float(
            min_candidate_age_hours
        ),
        "min_additional_seen_days": (
            min_additional_seen_days
        ),
        "min_additional_observation_count": (
            min_additional_observation_count
        ),
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


def validate_candidate_maturity_history(
    raw: dict[str, Any],
) -> dict[str, Any]:
    """Validate persisted Candidate Maturity decision history."""

    if not isinstance(raw, dict):
        raise ValueError(
            "Previous Candidate Maturity state must be an object"
        )

    if raw.get("version") != MATURITY_VERSION:
        raise ValueError(
            "Previous Candidate Maturity version is unsupported"
        )

    if raw.get("mode") != MATURITY_MODE:
        raise ValueError(
            "Previous Candidate Maturity mode is unsupported"
        )

    state = raw.get("state")

    if state not in MATURITY_STATES:
        raise ValueError(
            "Previous Candidate Maturity state is unsupported"
        )

    candidate_since = raw.get("candidate_since")

    if not isinstance(candidate_since, str):
        raise ValueError(
            "Previous Candidate Maturity candidate_since "
            "must be a timestamp"
        )

    candidate_since_dt = parse_iso(candidate_since)

    if candidate_since_dt is None:
        raise ValueError(
            "Previous Candidate Maturity candidate_since "
            "is invalid"
        )

    baseline = raw.get("baseline")

    if not isinstance(baseline, dict):
        raise ValueError(
            "Previous Candidate Maturity baseline "
            "must be an object"
        )

    baseline_seen_days = baseline.get("seen_days")
    baseline_observation_count = baseline.get(
        "observation_count"
    )

    if (
        type(baseline_seen_days) is not int
        or baseline_seen_days < 0
    ):
        raise ValueError(
            "Previous Candidate Maturity baseline.seen_days "
            "must be integer >= 0"
        )

    if (
        type(baseline_observation_count) is not int
        or baseline_observation_count < 0
    ):
        raise ValueError(
            "Previous Candidate Maturity "
            "baseline.observation_count must be integer >= 0"
        )

    return {
        "state": state,
        "candidate_since": candidate_since,
        "candidate_since_dt": candidate_since_dt,
        "baseline": {
            "seen_days": baseline_seen_days,
            "observation_count": (
                baseline_observation_count
            ),
        },
    }


def evaluate_candidate_maturity(
    candidate: dict[str, Any],
    now: datetime,
    *,
    previous_maturity: dict[str, Any] | None = None,
    settings: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """
    Evaluate Candidate Maturity v1 in shadow mode.

    The first evaluation records a baseline and can never return ready.
    Only evidence accumulated after that baseline can satisfy maturity.
    Observer absence does not erase history, but a tracking candidate
    cannot newly become ready while it is absent from the current feed.
    """

    normalized_settings = candidate_maturity_settings(
        settings
    )
    runtime_evidence = _runtime_evidence(candidate)

    if previous_maturity is None:
        candidate_since = iso(now)
        baseline = {
            "seen_days": runtime_evidence["seen_days"],
            "observation_count": (
                runtime_evidence["observation_count"]
            ),
        }
        state = "tracking"
        reason = (
            "candidate_maturity_tracking_started"
            if normalized_settings["enabled"]
            else "candidate_maturity_disabled"
        )
        candidate_age_hours = 0.0
        additional_seen_days = 0
        additional_observation_count = 0

    else:
        history = validate_candidate_maturity_history(
            previous_maturity
        )
        candidate_since = history["candidate_since"]
        candidate_since_dt = history[
            "candidate_since_dt"
        ]

        if candidate_since_dt > now:
            raise ValueError(
                "Previous Candidate Maturity candidate_since "
                "cannot be in the future"
            )

        baseline = history["baseline"]
        candidate_age_hours = round(
            hours_between(
                candidate_since_dt,
                now,
            ),
            6,
        )
        additional_seen_days = max(
            0,
            runtime_evidence["seen_days"]
            - baseline["seen_days"],
        )
        additional_observation_count = max(
            0,
            runtime_evidence["observation_count"]
            - baseline["observation_count"],
        )

        if history["state"] == "ready":
            state = "ready"
            reason = "candidate_maturity_ready_retained"

        elif not normalized_settings["enabled"]:
            state = "tracking"
            reason = "candidate_maturity_disabled_retained"

        elif not runtime_evidence["feed_present"]:
            state = "tracking"
            reason = "candidate_maturity_feed_absent"

        elif (
            candidate_age_hours
            < normalized_settings[
                "min_candidate_age_hours"
            ]
        ):
            state = "tracking"
            reason = (
                "candidate_maturity_insufficient_candidate_age"
            )

        elif (
            additional_seen_days
            < normalized_settings[
                "min_additional_seen_days"
            ]
        ):
            state = "tracking"
            reason = (
                "candidate_maturity_insufficient_additional_seen_days"
            )

        elif (
            additional_observation_count
            < normalized_settings[
                "min_additional_observation_count"
            ]
        ):
            state = "tracking"
            reason = (
                "candidate_maturity_insufficient_"
                "additional_observation_count"
            )

        else:
            state = "ready"
            reason = "candidate_maturity_met"

    if state not in MATURITY_STATES:
        raise RuntimeError(
            "Unsupported Candidate Maturity state: "
            f"{state}"
        )

    return {
        "version": MATURITY_VERSION,
        "mode": MATURITY_MODE,
        "state": state,
        "reason": reason,
        "candidate_since": candidate_since,
        "criteria": normalized_settings,
        "baseline": baseline,
        "evidence": {
            "feed_present": runtime_evidence[
                "feed_present"
            ],
            "candidate_age_hours": candidate_age_hours,
            "seen_days": runtime_evidence["seen_days"],
            "observation_count": runtime_evidence[
                "observation_count"
            ],
            "additional_seen_days": additional_seen_days,
            "additional_observation_count": (
                additional_observation_count
            ),
        },
    }
