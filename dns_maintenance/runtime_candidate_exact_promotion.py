from __future__ import annotations

from typing import Any

from .policy import evaluate_hostname
from .runtime_candidate_maturity import (
    MATURITY_MODE,
    MATURITY_VERSION,
    validate_candidate_maturity_history,
)
from .utils import normalize_hostname


EXACT_PROMOTION_VERSION = 1
EXACT_PROMOTION_MODE = "shadow"

EXACT_PROMOTION_STATES = frozenset(
    {
        "hold",
        "eligible",
    }
)

_ALLOWED_SETTINGS = frozenset(
    {
        "enabled",
    }
)


def exact_promotion_settings(
    raw: dict[str, Any] | None,
) -> dict[str, Any]:
    """
    Validate and normalize Exact Promotion v1 settings.

    v1 is shadow-only. Even when enabled, this layer can only decide
    whether a mature Runtime Candidate would be eligible for later
    promotion into Exact DNS. It never mutates Exact DNS state.
    """

    if raw is None:
        raw = {}

    if not isinstance(raw, dict):
        raise ValueError(
            "exact_promotion must be an object"
        )

    unknown = set(raw) - _ALLOWED_SETTINGS

    if unknown:
        raise ValueError(
            "Unknown exact_promotion setting(s): "
            + ", ".join(sorted(unknown))
        )

    enabled = raw.get(
        "enabled",
        False,
    )

    if not isinstance(
        enabled,
        bool,
    ):
        raise ValueError(
            "exact_promotion.enabled must be boolean"
        )

    return {
        "enabled": enabled,
    }


def _validated_candidate_id(
    candidate: dict[str, Any],
) -> str:
    raw = candidate.get(
        "candidate_id"
    )

    if (
        not isinstance(raw, str)
        or not raw
    ):
        raise ValueError(
            "Runtime Candidate candidate_id "
            "must be non-empty"
        )

    return raw


def _validated_hostname(
    candidate: dict[str, Any],
) -> str:
    if not isinstance(
        candidate,
        dict,
    ):
        raise ValueError(
            "Runtime Candidate entry "
            "must be an object"
        )

    raw = candidate.get(
        "hostname"
    )

    if not isinstance(
        raw,
        str,
    ):
        raise ValueError(
            "Runtime Candidate hostname must be "
            "a normalized hostname"
        )

    hostname = normalize_hostname(
        raw
    )

    if (
        hostname is None
        or hostname != raw
    ):
        raise ValueError(
            "Runtime Candidate hostname must be "
            "a normalized hostname"
        )

    return hostname


def _validated_feed_present(
    candidate: dict[str, Any],
) -> bool:
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

    return feed_present


def _validated_classification(
    classification: dict[str, Any],
) -> dict[str, Any]:
    if not isinstance(
        classification,
        dict,
    ):
        raise ValueError(
            "Runtime Candidate classification "
            "must be an object"
        )

    if (
        classification.get("version")
        != 1
    ):
        raise ValueError(
            "Runtime Candidate classification "
            "version is unsupported"
        )

    if (
        classification.get("mode")
        != "shadow"
    ):
        raise ValueError(
            "Runtime Candidate classification "
            "mode is unsupported"
        )

    decision = classification.get(
        "decision"
    )

    if not isinstance(
        decision,
        str,
    ):
        raise ValueError(
            "Runtime Candidate classification "
            "decision must be a string"
        )

    if decision not in {
        "observed",
        "candidate",
        "observe_only",
        "rejected",
    }:
        raise ValueError(
            "Runtime Candidate classification "
            "decision is unsupported"
        )

    evidence = classification.get(
        "evidence"
    )

    if not isinstance(
        evidence,
        dict,
    ):
        raise ValueError(
            "Runtime Candidate classification "
            "evidence must be an object"
        )

    exact_dns_present = evidence.get(
        "exact_dns_present"
    )

    policy_excluded = evidence.get(
        "policy_excluded"
    )

    if not isinstance(
        exact_dns_present,
        bool,
    ):
        raise ValueError(
            "Runtime Candidate classification "
            "exact_dns_present must be boolean"
        )

    if not isinstance(
        policy_excluded,
        bool,
    ):
        raise ValueError(
            "Runtime Candidate classification "
            "policy_excluded must be boolean"
        )

    maturity = classification.get(
        "maturity"
    )

    if maturity is not None:
        if decision != "candidate":
            raise ValueError(
                "Candidate Maturity requires "
                "candidate classification decision"
            )

        history = (
            validate_candidate_maturity_history(
                maturity
            )
        )

        if (
            maturity.get("version")
            != MATURITY_VERSION
        ):
            raise ValueError(
                "Candidate Maturity version "
                "is unsupported"
            )

        if (
            maturity.get("mode")
            != MATURITY_MODE
        ):
            raise ValueError(
                "Candidate Maturity mode "
                "is unsupported"
            )

        maturity_state = history[
            "state"
        ]

    else:
        maturity_state = None

    return {
        "decision": decision,
        "maturity_state": (
            maturity_state
        ),
        "reported_exact_dns_present": (
            exact_dns_present
        ),
        "reported_policy_excluded": (
            policy_excluded
        ),
    }


def evaluate_exact_promotion(
    candidate: dict[str, Any],
    classification: dict[str, Any],
    dns_state: dict[str, Any],
    hostname_policy_cfg: dict[str, Any],
    *,
    settings: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """
    Evaluate Exact Promotion v1 in shadow mode.

    This function is deliberately read-only. It re-checks Hostname
    Policy and Exact DNS presence independently instead of trusting
    the classification snapshot as authority.

    "eligible" means only that a later, separately implemented write
    path may consider creating Exact DNS pending state. It is not an
    Exact DNS promotion and it never changes public Service_DNS.
    """

    normalized_settings = (
        exact_promotion_settings(
            settings
        )
    )

    if not isinstance(
        candidate,
        dict,
    ):
        raise ValueError(
            "Runtime Candidate entry "
            "must be an object"
        )

    candidate_id = (
        _validated_candidate_id(
            candidate
        )
    )

    hostname = _validated_hostname(
        candidate
    )

    feed_present = (
        _validated_feed_present(
            candidate
        )
    )

    classification_info = (
        _validated_classification(
            classification
        )
    )

    if not isinstance(
        dns_state,
        dict,
    ):
        raise ValueError(
            "DNS state must be an object"
        )

    hosts = dns_state.get(
        "hosts"
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

    if not isinstance(
        hostname_policy_cfg,
        dict,
    ):
        raise ValueError(
            "Hostname Policy config "
            "must be an object"
        )

    policy_decision = (
        evaluate_hostname(
            hostname,
            hostname_policy_cfg,
        )
    )

    exact_dns_present = (
        exact_entry is not None
    )

    exact_dns_status = (
        exact_entry.get(
            "status"
        )
        if isinstance(
            exact_entry,
            dict,
        )
        else None
    )

    if policy_decision.excluded:
        state = "hold"
        reason = (
            "exact_promotion_"
            "hostname_policy_excluded"
        )

    elif exact_dns_present:
        state = "hold"
        reason = (
            "exact_promotion_"
            "exact_dns_existing"
        )

    elif (
        classification_info[
            "decision"
        ]
        != "candidate"
    ):
        state = "hold"
        reason = (
            "exact_promotion_not_candidate"
        )

    elif (
        classification_info[
            "maturity_state"
        ]
        is None
    ):
        state = "hold"
        reason = (
            "exact_promotion_maturity_missing"
        )

    elif (
        classification_info[
            "maturity_state"
        ]
        != "ready"
    ):
        state = "hold"
        reason = (
            "exact_promotion_maturity_not_ready"
        )

    elif not feed_present:
        state = "hold"
        reason = (
            "exact_promotion_feed_absent"
        )

    elif not normalized_settings[
        "enabled"
    ]:
        state = "hold"
        reason = (
            "exact_promotion_disabled"
        )

    else:
        state = "eligible"
        reason = (
            "exact_promotion_eligible"
        )

    if (
        state
        not in EXACT_PROMOTION_STATES
    ):
        raise RuntimeError(
            "Unsupported Exact Promotion "
            f"state: {state}"
        )

    return {
        "version": (
            EXACT_PROMOTION_VERSION
        ),
        "mode": (
            EXACT_PROMOTION_MODE
        ),
        "candidate_id": (
            candidate_id
        ),
        "hostname": hostname,
        "state": state,
        "reason": reason,
        "criteria": (
            normalized_settings
        ),
        "evidence": {
            "feed_present": (
                feed_present
            ),
            "classification_decision": (
                classification_info[
                    "decision"
                ]
            ),
            "maturity_state": (
                classification_info[
                    "maturity_state"
                ]
            ),
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
            "classification_reported_exact_dns_present": (
                classification_info[
                    "reported_exact_dns_present"
                ]
            ),
            "classification_reported_policy_excluded": (
                classification_info[
                    "reported_policy_excluded"
                ]
            ),
        },
    }
