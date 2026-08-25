from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Any

from .policy import evaluate_hostname
from .runtime_candidate_eligibility import (
    candidate_eligibility_settings,
    evaluate_candidate_eligibility,
)
from .runtime_candidate_maturity import (
    candidate_maturity_settings,
    evaluate_candidate_maturity,
    validate_candidate_maturity_history,
)
from .utils import (
    iso,
    load_json,
    normalize_hostname,
    save_json,
)


CLASSIFICATION_VERSION = 1
CLASSIFICATION_MODE = "shadow"

SHADOW_DECISIONS = frozenset(
    {
        "observed",
        "candidate",
        "observe_only",
        "rejected",
    }
)


def _validated_hostname(
    candidate: dict[str, Any],
) -> str:
    raw = candidate.get("hostname")

    if not isinstance(raw, str):
        raise ValueError(
            "Runtime Candidate hostname must be "
            "a normalized hostname"
        )

    normalized = normalize_hostname(raw)

    if normalized is None or normalized != raw:
        raise ValueError(
            "Runtime Candidate hostname must be "
            "a normalized hostname"
        )

    return normalized


def _runtime_evidence(
    candidate: dict[str, Any],
) -> dict[str, Any]:
    feed_present = candidate.get(
        "feed_present"
    )

    if not isinstance(
        feed_present,
        bool,
    ):
        raise ValueError(
            "Runtime Candidate feed_present "
            "must be boolean"
        )

    current_presence = candidate.get(
        "current_presence"
    )

    if not isinstance(
        current_presence,
        bool,
    ):
        raise ValueError(
            "Runtime Candidate current_presence "
            "must be boolean"
        )

    counters: dict[str, int] = {}

    for key in (
        "observation_count",
        "presence_cycles",
        "active_cycles",
        "reactivation_count",
    ):
        value = candidate.get(key)

        if (
            type(value) is not int
            or value < 0
        ):
            raise ValueError(
                f"Runtime Candidate {key} "
                "must be integer >= 0"
            )

        counters[key] = value

    seen_dates = candidate.get(
        "seen_dates"
    )

    if not isinstance(
        seen_dates,
        list,
    ):
        raise ValueError(
            "Runtime Candidate seen_dates "
            "must be an array"
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
        "current_presence": current_presence,
        "current_routing_status": candidate.get(
            "current_routing_status"
        ),
        "observation_count": (
            counters["observation_count"]
        ),
        "presence_cycles": (
            counters["presence_cycles"]
        ),
        "active_cycles": (
            counters["active_cycles"]
        ),
        "reactivation_count": (
            counters["reactivation_count"]
        ),
        "seen_days": len(
            set(seen_dates)
        ),
    }


def _normalized_eligibility_settings(
    raw: dict[str, Any] | None,
) -> dict[str, Any] | None:
    if raw is None:
        return None

    return candidate_eligibility_settings(
        raw
    )


def _normalized_maturity_settings(
    raw: dict[str, Any] | None,
) -> dict[str, Any] | None:
    if raw is None:
        return None

    return candidate_maturity_settings(
        raw
    )


def _validate_previous_snapshot(
    runtime_state: dict[str, Any],
    previous_snapshot: dict[str, Any],
) -> dict[str, Any]:
    if not isinstance(
        previous_snapshot,
        dict,
    ):
        raise ValueError(
            "Previous Runtime Candidate "
            "classification snapshot "
            "must be an object"
        )

    if (
        previous_snapshot.get("version")
        != CLASSIFICATION_VERSION
    ):
        raise ValueError(
            "Previous Runtime Candidate "
            "classification version is unsupported"
        )

    if (
        previous_snapshot.get("mode")
        != CLASSIFICATION_MODE
    ):
        raise ValueError(
            "Previous Runtime Candidate "
            "classification mode is unsupported"
        )

    runtime_service = runtime_state.get(
        "service"
    )

    if (
        previous_snapshot.get("service")
        != runtime_service
    ):
        raise ValueError(
            "Previous Runtime Candidate "
            "classification service mismatch"
        )

    candidates = previous_snapshot.get(
        "candidates"
    )

    if not isinstance(
        candidates,
        dict,
    ):
        raise ValueError(
            "Previous Runtime Candidate "
            "classification candidates "
            "must be an object"
        )

    for candidate_id, result in candidates.items():
        if (
            not isinstance(
                candidate_id,
                str,
            )
            or not candidate_id
        ):
            raise ValueError(
                "Previous Runtime Candidate "
                "classification candidate_id "
                "must be non-empty"
            )

        if not isinstance(
            result,
            dict,
        ):
            raise ValueError(
                "Previous Runtime Candidate "
                "classification entry "
                "must be an object"
            )

        decision = result.get(
            "decision"
        )

        if not isinstance(
            decision,
            str,
        ):
            raise ValueError(
                "Previous Runtime Candidate "
                "classification decision "
                "must be a string"
            )

        if decision not in SHADOW_DECISIONS:
            raise ValueError(
                "Previous Runtime Candidate "
                "classification decision "
                f"is unsupported: {decision}"
            )

        maturity = result.get(
            "maturity"
        )

        if maturity is not None:
            if decision != "candidate":
                raise ValueError(
                    "Previous Candidate Maturity "
                    "requires candidate decision"
                )

            validate_candidate_maturity_history(
                maturity
            )

    return candidates


def _previous_has_candidate(
    previous_candidates: dict[str, Any],
) -> bool:
    for result in previous_candidates.values():
        if (
            isinstance(result, dict)
            and result.get("decision")
            == "candidate"
        ):
            return True

    return False


def classify_runtime_candidate(
    candidate: dict[str, Any],
    dns_state: dict[str, Any],
    hostname_policy_cfg: dict[str, Any],
    now: datetime,
    *,
    candidate_eligibility_cfg: (
        dict[str, Any] | None
    ) = None,
    candidate_maturity_cfg: (
        dict[str, Any] | None
    ) = None,
    previous_decision: str | None = None,
    previous_maturity: (
        dict[str, Any] | None
    ) = None,
) -> dict[str, Any]:
    """
    Classify one Runtime Candidate in shadow mode.

    Runtime evidence is informational only.
    Candidate Maturity is also shadow-only.
    This function cannot promote a Runtime Candidate
    into Exact DNS and does not mutate either input
    state.
    """

    if not isinstance(
        candidate,
        dict,
    ):
        raise ValueError(
            "Runtime Candidate entry "
            "must be an object"
        )

    if not isinstance(
        dns_state,
        dict,
    ):
        raise ValueError(
            "DNS state must be an object"
        )

    if not isinstance(
        hostname_policy_cfg,
        dict,
    ):
        raise ValueError(
            "Hostname Policy config "
            "must be an object"
        )

    if (
        previous_maturity is not None
        and previous_decision != "candidate"
    ):
        raise ValueError(
            "Previous Candidate Maturity "
            "requires previous candidate decision"
        )

    normalized_eligibility_cfg = (
        _normalized_eligibility_settings(
            candidate_eligibility_cfg
        )
    )

    normalized_maturity_cfg = (
        _normalized_maturity_settings(
            candidate_maturity_cfg
        )
    )

    hostname = _validated_hostname(
        candidate
    )
    evidence = _runtime_evidence(
        candidate
    )

    hosts = dns_state.get(
        "hosts",
        {},
    )

    if not isinstance(
        hosts,
        dict,
    ):
        raise ValueError(
            "DNS state hosts "
            "must be an object"
        )

    exact_entry = hosts.get(
        hostname
    )

    if (
        exact_entry is not None
        and not isinstance(
            exact_entry,
            dict,
        )
    ):
        raise ValueError(
            "Exact DNS state entry "
            "must be an object"
        )

    policy_decision = evaluate_hostname(
        hostname,
        hostname_policy_cfg,
    )

    exact_dns_present = (
        exact_entry is not None
    )

    exact_dns_status = (
        exact_entry.get("status")
        if isinstance(
            exact_entry,
            dict,
        )
        else None
    )

    evidence.update(
        {
            "exact_dns_present": (
                exact_dns_present
            ),
            "exact_dns_status": (
                exact_dns_status
            ),
            "policy_excluded": (
                policy_decision.excluded
            ),
            "policy_rule": (
                policy_decision.rule
            ),
        }
    )

    eligibility = None

    if policy_decision.excluded:
        decision = "rejected"
        reason = (
            "hostname_policy_excluded"
        )

    elif exact_dns_present:
        decision = "observe_only"
        reason = "exact_dns_existing"

    else:
        eligibility_enabled = (
            (
                normalized_eligibility_cfg
                is not None
                and normalized_eligibility_cfg[
                    "enabled"
                ]
            )
            or previous_decision
            == "candidate"
        )

        if eligibility_enabled:
            eligibility = (
                evaluate_candidate_eligibility(
                    candidate,
                    previous_decision=(
                        previous_decision
                    ),
                    settings=(
                        normalized_eligibility_cfg
                    ),
                )
            )

            decision = eligibility[
                "decision"
            ]
            reason = eligibility[
                "reason"
            ]

        else:
            decision = "observed"
            reason = (
                "awaiting_classification_policy"
            )

    if decision not in SHADOW_DECISIONS:
        raise RuntimeError(
            "Unsupported shadow "
            "classification decision: "
            f"{decision}"
        )

    result = {
        "version": (
            CLASSIFICATION_VERSION
        ),
        "mode": (
            CLASSIFICATION_MODE
        ),
        "classified_at": iso(now),
        "decision": decision,
        "reason": reason,
        "policy_reason": (
            policy_decision.reason
        ),
        "evidence": evidence,
    }

    if eligibility is not None:
        result["eligibility"] = (
            eligibility
        )

    if decision == "candidate":
        maturity_enabled = (
            normalized_maturity_cfg
            is not None
            and normalized_maturity_cfg[
                "enabled"
            ]
        )

        maturity_active = (
            maturity_enabled
            or previous_maturity is not None
        )

        if maturity_active:
            result["maturity"] = (
                evaluate_candidate_maturity(
                    candidate,
                    now,
                    previous_maturity=(
                        previous_maturity
                    ),
                    settings=(
                        normalized_maturity_cfg
                    ),
                )
            )

    return result


def classify_runtime_candidate_state(
    runtime_state: dict[str, Any],
    dns_state: dict[str, Any],
    hostname_policy_cfg: dict[str, Any],
    now: datetime,
    *,
    candidate_eligibility_cfg: (
        dict[str, Any] | None
    ) = None,
    candidate_maturity_cfg: (
        dict[str, Any] | None
    ) = None,
    previous_snapshot: (
        dict[str, Any] | None
    ) = None,
) -> dict[str, Any]:
    """
    Produce a read-only shadow-classification
    snapshot.
    """

    if not isinstance(
        runtime_state,
        dict,
    ):
        raise ValueError(
            "Runtime Candidate state "
            "must be an object"
        )

    candidates = runtime_state.get(
        "candidates"
    )

    if not isinstance(
        candidates,
        dict,
    ):
        raise ValueError(
            "Runtime Candidate state candidates "
            "must be an object"
        )

    normalized_eligibility_cfg = (
        _normalized_eligibility_settings(
            candidate_eligibility_cfg
        )
    )

    normalized_maturity_cfg = (
        _normalized_maturity_settings(
            candidate_maturity_cfg
        )
    )

    previous_candidates: dict[
        str,
        Any,
    ] = {}

    if previous_snapshot is not None:
        previous_candidates = (
            _validate_previous_snapshot(
                runtime_state,
                previous_snapshot,
            )
        )

    previous_candidate_exists = (
        _previous_has_candidate(
            previous_candidates
        )
    )

    eligibility_enabled = (
        normalized_eligibility_cfg
        is not None
        and normalized_eligibility_cfg[
            "enabled"
        ]
    )

    eligibility_active = (
        eligibility_enabled
        or previous_candidate_exists
    )

    classified: dict[
        str,
        dict[str, Any],
    ] = {}

    counts = {
        "observed": 0,
        "observe_only": 0,
        "rejected": 0,
    }

    if eligibility_active:
        counts["candidate"] = 0

    for candidate_id, candidate in sorted(
        candidates.items()
    ):
        if (
            not isinstance(
                candidate_id,
                str,
            )
            or not candidate_id
        ):
            raise ValueError(
                "Runtime Candidate state "
                "candidate_id must be non-empty"
            )

        if not isinstance(
            candidate,
            dict,
        ):
            raise ValueError(
                "Runtime Candidate state "
                "entry is invalid: "
                f"{candidate_id}"
            )

        stored_id = candidate.get(
            "candidate_id"
        )

        if stored_id != candidate_id:
            raise ValueError(
                "Runtime Candidate state "
                "candidate_id mismatch"
            )

        previous_decision = None
        previous_maturity = None

        previous_result = (
            previous_candidates.get(
                candidate_id
            )
        )

        if previous_result is not None:
            previous_decision = (
                previous_result[
                    "decision"
                ]
            )

            previous_maturity = (
                previous_result.get(
                    "maturity"
                )
            )

        result = classify_runtime_candidate(
            candidate,
            dns_state,
            hostname_policy_cfg,
            now,
            candidate_eligibility_cfg=(
                normalized_eligibility_cfg
            ),
            candidate_maturity_cfg=(
                normalized_maturity_cfg
            ),
            previous_decision=(
                previous_decision
            ),
            previous_maturity=(
                previous_maturity
            ),
        )

        decision = result[
            "decision"
        ]

        if (
            decision == "candidate"
            and "candidate"
            not in counts
        ):
            counts["candidate"] = 0

        if decision not in counts:
            raise RuntimeError(
                "Unsupported shadow "
                "classification decision: "
                f"{decision}"
            )

        counts[decision] += 1

        classified[candidate_id] = (
            result
        )

    return {
        "version": (
            CLASSIFICATION_VERSION
        ),
        "mode": (
            CLASSIFICATION_MODE
        ),
        "service": runtime_state.get(
            "service"
        ),
        "classified_at": iso(now),
        "source_content_hash": (
            runtime_state.get(
                "source_content_hash"
            )
        ),
        "source_generated_at": (
            runtime_state.get(
                "source_generated_at"
            )
        ),
        "source_last_intake_at": (
            runtime_state.get(
                "last_intake_at"
            )
        ),
        "counts": counts,
        "candidates": classified,
    }


def write_runtime_candidate_classification_snapshot(
    runtime_state: dict[str, Any],
    dns_state: dict[str, Any],
    hostname_policy_cfg: dict[str, Any],
    state_path: Path,
    dry_run: bool,
    now: datetime,
    *,
    candidate_eligibility_cfg: (
        dict[str, Any] | None
    ) = None,
    candidate_maturity_cfg: (
        dict[str, Any] | None
    ) = None,
) -> dict[str, Any]:
    """
    Compute and optionally persist a
    shadow-classification snapshot.

    The previous classification snapshot is
    read only as central decision history.
    A malformed previous snapshot fails closed
    and is never overwritten.

    Classification and Candidate Maturity never
    write to Runtime Candidate state or Exact DNS state.
    """

    previous_snapshot = None

    try:
        if state_path.exists():
            previous_snapshot = load_json(
                state_path,
                None,
            )

            if not isinstance(
                previous_snapshot,
                dict,
            ):
                raise ValueError(
                    "Previous Runtime Candidate "
                    "classification snapshot "
                    "must be an object"
                )

        snapshot = (
            classify_runtime_candidate_state(
                runtime_state,
                dns_state,
                hostname_policy_cfg,
                now,
                candidate_eligibility_cfg=(
                    candidate_eligibility_cfg
                ),
                candidate_maturity_cfg=(
                    candidate_maturity_cfg
                ),
                previous_snapshot=(
                    previous_snapshot
                ),
            )
        )

    except (
        OSError,
        ValueError,
    ) as exc:
        return {
            "status": "state_error",
            "written": False,
            "dry_run": dry_run,
            "state_path": str(
                state_path
            ),
            "state": None,
            "error": str(exc),
        }

    if dry_run:
        return {
            "status": "ok",
            "written": False,
            "dry_run": True,
            "state_path": str(
                state_path
            ),
            "state": snapshot,
        }

    try:
        save_json(
            state_path,
            snapshot,
        )

    except OSError as exc:
        return {
            "status": "write_error",
            "written": False,
            "dry_run": False,
            "state_path": str(
                state_path
            ),
            "state": snapshot,
            "error": str(exc),
        }

    return {
        "status": "ok",
        "written": True,
        "dry_run": False,
        "state_path": str(
            state_path
        ),
        "state": snapshot,
    }
