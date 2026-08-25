from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Any

from .policy import evaluate_hostname
from .runtime_candidate_eligibility import (
    evaluate_candidate_eligibility,
)
from .utils import iso, normalize_hostname, save_json


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
    *,
    candidate_eligibility_cfg: dict[str, Any] | None = None,
    previous_decision: str | None = None,
) -> dict[str, Any]:
    """
    Classify one Runtime Candidate in shadow mode.

    Runtime evidence is informational only. This function cannot promote a
    Runtime Candidate into Exact DNS and does not mutate either input state.
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

    eligibility = None

    if policy_decision.excluded:
        decision = "rejected"
        reason = "hostname_policy_excluded"

    elif exact_dns_present:
        decision = "observe_only"
        reason = "exact_dns_existing"

    else:
        eligibility = evaluate_candidate_eligibility(
            candidate,
            previous_decision=previous_decision,
            settings=candidate_eligibility_cfg,
        )
        decision = eligibility["decision"]
        reason = eligibility["reason"]

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
    Produce a read-only shadow-classification snapshot.
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
    counts = {
        "observed": 0,
        "observe_only": 0,
        "rejected": 0,
    }

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

        result = classify_runtime_candidate(
            candidate,
            dns_state,
            hostname_policy_cfg,
            now,
        )

        decision = result["decision"]

        if decision not in counts:
            raise RuntimeError(
                f"Unsupported shadow classification decision: {decision}"
            )

        counts[decision] += 1
        classified[candidate_id] = result

    return {
        "version": CLASSIFICATION_VERSION,
        "mode": CLASSIFICATION_MODE,
        "service": runtime_state.get("service"),
        "classified_at": iso(now),
        "source_content_hash": runtime_state.get(
            "source_content_hash"
        ),
        "source_generated_at": runtime_state.get(
            "source_generated_at"
        ),
        "source_last_intake_at": runtime_state.get(
            "last_intake_at"
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
) -> dict[str, Any]:
    """
    Compute and optionally persist a shadow-classification snapshot.

    Classification never writes to Runtime Candidate state or Exact DNS state.
    """

    snapshot = classify_runtime_candidate_state(
        runtime_state,
        dns_state,
        hostname_policy_cfg,
        now,
    )

    if dry_run:
        return {
            "status": "ok",
            "written": False,
            "dry_run": True,
            "state_path": str(state_path),
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
            "state_path": str(state_path),
            "state": snapshot,
            "error": str(exc),
        }

    return {
        "status": "ok",
        "written": True,
        "dry_run": False,
        "state_path": str(state_path),
        "state": snapshot,
    }
