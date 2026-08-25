from __future__ import annotations

from datetime import datetime
from typing import Any

from .policy import evaluate_hostname
from .utils import iso, normalize_hostname


CLASSIFICATION_VERSION = 1
CLASSIFICATION_MODE = "shadow"

SHADOW_DECISIONS = frozenset(
    {
        "observed",
        "observe_only",
        "rejected",
    }
)


def _validated_hostname(candidate: dict[str, Any]) -> str:
    raw = candidate.get("hostname")

    if not isinstance(raw, str):
        raise ValueError(
            "Runtime Candidate hostname must be a normalized hostname"
        )

    normalized = normalize_hostname(raw)

    if normalized is None or normalized != raw:
        raise ValueError(
            "Runtime Candidate hostname must be a normalized hostname"
        )

    return normalized


def _runtime_evidence(candidate: dict[str, Any]) -> dict[str, Any]:
    feed_present = candidate.get("feed_present")

    if not isinstance(feed_present, bool):
        raise ValueError(
            "Runtime Candidate feed_present must be boolean"
        )

    current_presence = candidate.get("current_presence")

    if not isinstance(current_presence, bool):
        raise ValueError(
            "Runtime Candidate current_presence must be boolean"
        )

    counters: dict[str, int] = {}

    for key in (
        "observation_count",
        "presence_cycles",
        "active_cycles",
        "reactivation_count",
    ):
        value = candidate.get(key)

        if type(value) is not int or value < 0:
            raise ValueError(
                f"Runtime Candidate {key} must be integer >= 0"
            )

        counters[key] = value

    seen_dates = candidate.get("seen_dates")

    if not isinstance(seen_dates, list):
        raise ValueError(
            "Runtime Candidate seen_dates must be an array"
        )

    if any(not isinstance(value, str) for value in seen_dates):
        raise ValueError(
            "Runtime Candidate seen_dates entries must be strings"
        )

    return {
        "feed_present": feed_present,
        "current_presence": current_presence,
        "current_routing_status": candidate.get(
            "current_routing_status"
        ),
        "observation_count": counters["observation_count"],
        "presence_cycles": counters["presence_cycles"],
        "active_cycles": counters["active_cycles"],
        "reactivation_count": counters["reactivation_count"],
        "seen_days": len(set(seen_dates)),
    }


def classify_runtime_candidate(
    candidate: dict[str, Any],
    dns_state: dict[str, Any],
    hostname_policy_cfg: dict[str, Any],
    now: datetime,
) -> dict[str, Any]:
    """
    Classify one Runtime Candidate in shadow mode.

    This function is intentionally non-promoting.

    Runtime observation metrics are recorded as evidence only.
    They cannot produce candidate/promoted_exact or modify Exact DNS.
    """

    if not isinstance(candidate, dict):
        raise ValueError(
            "Runtime Candidate entry must be an object"
        )

    if not isinstance(dns_state, dict):
        raise ValueError(
            "DNS state must be an object"
        )

    if not isinstance(hostname_policy_cfg, dict):
        raise ValueError(
            "Hostname Policy config must be an object"
        )

    hostname = _validated_hostname(candidate)
    evidence = _runtime_evidence(candidate)

    hosts = dns_state.get("hosts", {})

    if not isinstance(hosts, dict):
        raise ValueError(
            "DNS state hosts must be an object"
        )

    exact_entry = hosts.get(hostname)

    if exact_entry is not None and not isinstance(
        exact_entry,
        dict,
    ):
        raise ValueError(
            "Exact DNS state entry must be an object"
        )

    policy_decision = evaluate_hostname(
        hostname,
        hostname_policy_cfg,
    )

    exact_dns_present = exact_entry is not None
    exact_dns_status = (
        exact_entry.get("status")
        if isinstance(exact_entry, dict)
        else None
    )

    evidence.update(
        {
            "exact_dns_present": exact_dns_present,
            "exact_dns_status": exact_dns_status,
            "policy_excluded": policy_decision.excluded,
            "policy_rule": policy_decision.rule,
        }
    )

    if policy_decision.excluded:
        decision = "rejected"
        reason = "hostname_policy_excluded"

    elif exact_dns_present:
        decision = "observe_only"
        reason = "exact_dns_existing"

    else:
        decision = "observed"
        reason = "awaiting_classification_policy"

    if decision not in SHADOW_DECISIONS:
        raise RuntimeError(
            f"Unsupported shadow classification decision: {decision}"
        )

    return {
        "version": CLASSIFICATION_VERSION,
        "mode": CLASSIFICATION_MODE,
        "classified_at": iso(now),
        "decision": decision,
        "reason": reason,
        "policy_reason": policy_decision.reason,
        "evidence": evidence,
    }


def classify_runtime_candidate_state(
    runtime_state: dict[str, Any],
    dns_state: dict[str, Any],
    hostname_policy_cfg: dict[str, Any],
    now: datetime,
) -> dict[str, Any]:
    """
    Produce a read-only classification snapshot for a Runtime Candidate state.

    The supplied Runtime Candidate state and DNS state are never mutated.
    """

    if not isinstance(runtime_state, dict):
        raise ValueError(
            "Runtime Candidate state must be an object"
        )

    candidates = runtime_state.get("candidates")

    if not isinstance(candidates, dict):
        raise ValueError(
            "Runtime Candidate state candidates must be an object"
        )

    classified: dict[str, dict[str, Any]] = {}

    for candidate_id, candidate in sorted(candidates.items()):
        if not isinstance(candidate_id, str) or not candidate_id:
            raise ValueError(
                "Runtime Candidate state candidate_id must be non-empty"
            )

        if not isinstance(candidate, dict):
            raise ValueError(
                f"Runtime Candidate state entry is invalid: {candidate_id}"
            )

        stored_id = candidate.get("candidate_id")

        if stored_id != candidate_id:
            raise ValueError(
                "Runtime Candidate state candidate_id mismatch"
            )

        classified[candidate_id] = classify_runtime_candidate(
            candidate,
            dns_state,
            hostname_policy_cfg,
            now,
        )

    return {
        "version": CLASSIFICATION_VERSION,
        "mode": CLASSIFICATION_MODE,
        "service": runtime_state.get("service"),
        "classified_at": iso(now),
        "candidates": classified,
    }
