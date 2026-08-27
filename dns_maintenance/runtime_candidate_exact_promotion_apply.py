from __future__ import annotations

import copy
from datetime import datetime
from pathlib import Path
from typing import Any

from .dns_engine import (
    DNS_STATE_VERSION,
    new_host_state,
)
from .runtime_candidate_exact_promotion_state import (
    evaluate_exact_promotion_state,
)
from .utils import (
    iso,
    normalize_hostname,
    parse_iso,
    save_json,
    write_host_file,
)


EXACT_PROMOTION_APPLY_VERSION = 1
EXACT_PROMOTION_APPLY_MODE = "apply"
EXACT_PROMOTION_APPLY_SOURCE = (
    "runtime_candidate_exact_promotion:v1"
)

EXACT_PROMOTION_APPLY_ACTIONS = frozenset(
    {
        "hold",
        "created_pending",
    }
)

_ALLOWED_SETTINGS = frozenset(
    {
        "enabled",
    }
)


def exact_promotion_apply_settings(
    raw: dict[str, Any] | None,
) -> dict[str, Any]:
    """
    Validate Exact Promotion Apply v1 settings.

    Apply is disabled by default.

    Enabling Apply allows an already shadow-eligible Runtime Candidate
    to be registered as a new Exact DNS pending hostname.

    Apply never creates active Exact DNS state and never writes the
    public Service_DNS file.
    """

    if raw is None:
        raw = {}

    if not isinstance(
        raw,
        dict,
    ):
        raise ValueError(
            "exact_promotion_apply must be an object"
        )

    unknown = (
        set(raw)
        - _ALLOWED_SETTINGS
    )

    if unknown:
        raise ValueError(
            "Unknown exact_promotion_apply "
            "setting(s): "
            + ", ".join(
                sorted(unknown)
            )
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
            "exact_promotion_apply.enabled "
            "must be boolean"
        )

    return {
        "enabled": enabled,
    }


def _validate_promotion_state(
    promotion_state: dict[str, Any],
    *,
    fresh_promotion_state: dict[str, Any],
) -> tuple[
    str,
    str,
    str,
    dict[str, Any],
]:
    """
    Validate that the stored shadow Promotion snapshot belongs to the
    same Runtime Candidate / Classification generation as the fresh
    re-evaluation.

    State differences such as eligible -> hold are allowed because
    current Exact DNS or Hostname Policy may have changed since the
    stored snapshot. Identity/provenance differences fail closed.
    """

    if not isinstance(
        promotion_state,
        dict,
    ):
        raise ValueError(
            "Exact Promotion snapshot "
            "must be an object"
        )

    if (
        promotion_state.get(
            "version"
        )
        != 1
    ):
        raise ValueError(
            "Exact Promotion snapshot "
            "version is unsupported"
        )

    if (
        promotion_state.get(
            "mode"
        )
        != "shadow"
    ):
        raise ValueError(
            "Exact Promotion snapshot "
            "mode is unsupported"
        )

    service = fresh_promotion_state.get(
        "service"
    )

    source_content_hash = (
        fresh_promotion_state.get(
            "source_content_hash"
        )
    )

    source_classified_at = (
        fresh_promotion_state.get(
            "source_classified_at"
        )
    )

    if (
        promotion_state.get(
            "service"
        )
        != service
    ):
        raise ValueError(
            "Exact Promotion snapshot "
            "service mismatch"
        )

    if (
        promotion_state.get(
            "source_content_hash"
        )
        != source_content_hash
    ):
        raise ValueError(
            "Exact Promotion snapshot "
            "source_content_hash mismatch"
        )

    if (
        promotion_state.get(
            "source_classified_at"
        )
        != source_classified_at
    ):
        raise ValueError(
            "Exact Promotion snapshot "
            "source_classified_at mismatch"
        )

    evaluated_at = (
        promotion_state.get(
            "evaluated_at"
        )
    )

    if (
        not isinstance(
            evaluated_at,
            str,
        )
        or parse_iso(
            evaluated_at
        )
        is None
    ):
        raise ValueError(
            "Exact Promotion snapshot "
            "evaluated_at is invalid"
        )

    candidates = (
        promotion_state.get(
            "candidates"
        )
    )

    fresh_candidates = (
        fresh_promotion_state.get(
            "candidates"
        )
    )

    if not isinstance(
        candidates,
        dict,
    ):
        raise ValueError(
            "Exact Promotion snapshot "
            "candidates must be an object"
        )

    if not isinstance(
        fresh_candidates,
        dict,
    ):
        raise ValueError(
            "Fresh Exact Promotion snapshot "
            "candidates must be an object"
        )

    if (
        set(candidates)
        != set(fresh_candidates)
    ):
        raise ValueError(
            "Exact Promotion snapshot "
            "candidate set mismatch"
        )

    for candidate_id in sorted(
        candidates
    ):
        stored = candidates[
            candidate_id
        ]

        fresh = fresh_candidates[
            candidate_id
        ]

        if not isinstance(
            stored,
            dict,
        ):
            raise ValueError(
                "Exact Promotion snapshot "
                "candidate entry must be an object"
            )

        if not isinstance(
            fresh,
            dict,
        ):
            raise ValueError(
                "Fresh Exact Promotion "
                "candidate entry must be an object"
            )

        if (
            stored.get(
                "version"
            )
            != 1
        ):
            raise ValueError(
                "Exact Promotion candidate "
                "version is unsupported"
            )

        if (
            stored.get(
                "mode"
            )
            != "shadow"
        ):
            raise ValueError(
                "Exact Promotion candidate "
                "mode is unsupported"
            )

        if (
            stored.get(
                "candidate_id"
            )
            != candidate_id
        ):
            raise ValueError(
                "Exact Promotion candidate_id "
                "mismatch"
            )

        if (
            fresh.get(
                "candidate_id"
            )
            != candidate_id
        ):
            raise ValueError(
                "Fresh Exact Promotion "
                "candidate_id mismatch"
            )

        stored_hostname = (
            stored.get(
                "hostname"
            )
        )

        fresh_hostname = (
            fresh.get(
                "hostname"
            )
        )

        if not isinstance(
            stored_hostname,
            str,
        ):
            raise ValueError(
                "Exact Promotion candidate "
                "hostname is invalid"
            )

        normalized_hostname = (
            normalize_hostname(
                stored_hostname
            )
        )

        if (
            normalized_hostname is None
            or normalized_hostname
            != stored_hostname
        ):
            raise ValueError(
                "Exact Promotion candidate "
                "hostname must be normalized"
            )

        if (
            stored_hostname
            != fresh_hostname
        ):
            raise ValueError(
                "Exact Promotion candidate "
                "hostname mismatch"
            )

        state = stored.get(
            "state"
        )

        if state not in {
            "hold",
            "eligible",
        }:
            raise ValueError(
                "Exact Promotion candidate "
                "state is unsupported"
            )

        reason = stored.get(
            "reason"
        )

        if (
            not isinstance(
                reason,
                str,
            )
            or not reason
        ):
            raise ValueError(
                "Exact Promotion candidate "
                "reason must be non-empty"
            )

        criteria = stored.get(
            "criteria"
        )

        if not isinstance(
            criteria,
            dict,
        ):
            raise ValueError(
                "Exact Promotion candidate "
                "criteria must be an object"
            )

        enabled = criteria.get(
            "enabled"
        )

        if not isinstance(
            enabled,
            bool,
        ):
            raise ValueError(
                "Exact Promotion candidate "
                "criteria.enabled "
                "must be boolean"
            )

        if state == "eligible":
            if (
                reason
                != "exact_promotion_eligible"
            ):
                raise ValueError(
                    "Eligible Exact Promotion "
                    "candidate has invalid reason"
                )

            if not enabled:
                raise ValueError(
                    "Eligible Exact Promotion "
                    "candidate cannot have "
                    "disabled criteria"
                )

    if not isinstance(
        service,
        str,
    ):
        raise ValueError(
            "Fresh Exact Promotion service "
            "is invalid"
        )

    if not isinstance(
        source_content_hash,
        str,
    ):
        raise ValueError(
            "Fresh Exact Promotion "
            "source_content_hash is invalid"
        )

    if not isinstance(
        source_classified_at,
        str,
    ):
        raise ValueError(
            "Fresh Exact Promotion "
            "source_classified_at is invalid"
        )

    return (
        service,
        source_content_hash,
        source_classified_at,
        candidates,
    )


def evaluate_exact_promotion_apply(
    runtime_state: dict[str, Any],
    classification_state: dict[str, Any],
    promotion_state: dict[str, Any],
    dns_state: dict[str, Any],
    hostname_policy_cfg: dict[str, Any],
    now: datetime,
    *,
    settings: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """
    Evaluate Exact Promotion Apply v1.

    Apply requires BOTH:
    1. the stored shadow Promotion snapshot to say eligible;
    2. a fresh Promotion re-evaluation against current Exact DNS and
       current Hostname Policy to still say eligible.

    Eligible candidates are added only to a copied Exact DNS state as
    status=pending with ever_validated=false.

    The input DNS state is never mutated.
    """

    normalized_settings = (
        exact_promotion_apply_settings(
            settings
        )
    )

    if not isinstance(
        dns_state,
        dict,
    ):
        raise ValueError(
            "DNS state must be an object"
        )

    if (
        dns_state.get(
            "version"
        )
        != DNS_STATE_VERSION
    ):
        raise ValueError(
            "DNS state version "
            "is unsupported"
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

    if not isinstance(
        hostname_policy_cfg,
        dict,
    ):
        raise ValueError(
            "Hostname Policy config "
            "must be an object"
        )

    # Re-run the complete shadow evaluator against current DNS state
    # and current Hostname Policy. This also validates Runtime Candidate
    # and Classification snapshot identity.
    fresh_promotion_state = (
        evaluate_exact_promotion_state(
            runtime_state,
            classification_state,
            dns_state,
            hostname_policy_cfg,
            now,
            settings={
                "enabled": True,
            },
        )
    )

    (
        service,
        source_content_hash,
        source_classified_at,
        stored_candidates,
    ) = _validate_promotion_state(
        promotion_state,
        fresh_promotion_state=(
            fresh_promotion_state
        ),
    )

    fresh_candidates = (
        fresh_promotion_state[
            "candidates"
        ]
    )

    next_dns_state = (
        copy.deepcopy(
            dns_state
        )
    )

    next_hosts = (
        next_dns_state[
            "hosts"
        ]
    )

    counts = {
        "hold": 0,
        "created_pending": 0,
    }

    results: dict[
        str,
        dict[str, Any],
    ] = {}

    source_promotion_evaluated_at = (
        promotion_state[
            "evaluated_at"
        ]
    )

    for candidate_id in sorted(
        stored_candidates
    ):
        stored = (
            stored_candidates[
                candidate_id
            ]
        )

        fresh = (
            fresh_candidates[
                candidate_id
            ]
        )

        hostname = fresh[
            "hostname"
        ]

        stored_state = (
            stored[
                "state"
            ]
        )

        fresh_state = (
            fresh[
                "state"
            ]
        )

        if (
            stored_state
            != "eligible"
        ):
            action = "hold"
            reason = (
                "exact_promotion_apply_"
                "shadow_not_eligible"
            )

        elif (
            fresh_state
            != "eligible"
        ):
            action = "hold"
            reason = (
                "exact_promotion_apply_"
                "recheck_not_eligible"
            )

        elif (
            hostname
            in next_hosts
        ):
            action = "hold"
            reason = (
                "exact_promotion_apply_"
                "exact_dns_existing"
            )

        elif not normalized_settings[
            "enabled"
        ]:
            action = "hold"
            reason = (
                "exact_promotion_apply_disabled"
            )

        else:
            entry = new_host_state(
                hostname,
                now,
                EXACT_PROMOTION_APPLY_SOURCE,
                legacy_active=False,
            )

            entry[
                "runtime_promotion"
            ] = {
                "version": (
                    EXACT_PROMOTION_APPLY_VERSION
                ),
                "candidate_id": (
                    candidate_id
                ),
                "source_content_hash": (
                    source_content_hash
                ),
                "source_classified_at": (
                    source_classified_at
                ),
                "source_promotion_evaluated_at": (
                    source_promotion_evaluated_at
                ),
                "promoted_at": iso(
                    now
                ),
            }

            next_hosts[
                hostname
            ] = entry

            action = (
                "created_pending"
            )

            reason = (
                "exact_promotion_apply_"
                "created_pending"
            )

        if (
            action
            not in EXACT_PROMOTION_APPLY_ACTIONS
        ):
            raise RuntimeError(
                "Unsupported Exact Promotion "
                f"Apply action: {action}"
            )

        counts[
            action
        ] += 1

        results[
            candidate_id
        ] = {
            "version": (
                EXACT_PROMOTION_APPLY_VERSION
            ),
            "mode": (
                EXACT_PROMOTION_APPLY_MODE
            ),
            "candidate_id": (
                candidate_id
            ),
            "hostname": hostname,
            "action": action,
            "reason": reason,
            "evidence": {
                "stored_promotion_state": (
                    stored_state
                ),
                "fresh_promotion_state": (
                    fresh_state
                ),
                "fresh_promotion_reason": (
                    fresh.get(
                        "reason"
                    )
                ),
                "feed_present": (
                    fresh.get(
                        "evidence",
                        {},
                    ).get(
                        "feed_present"
                    )
                ),
                "exact_dns_present": (
                    fresh.get(
                        "evidence",
                        {},
                    ).get(
                        "exact_dns_present"
                    )
                ),
                "policy_excluded": (
                    fresh.get(
                        "evidence",
                        {},
                    ).get(
                        "policy_excluded"
                    )
                ),
            },
        }

    next_dns_state[
        "version"
    ] = DNS_STATE_VERSION

    if (
        counts[
            "created_pending"
        ]
        > 0
    ):
        next_dns_state[
            "updated_at"
        ] = iso(
            now
        )

    next_dns_state[
        "hosts"
    ] = dict(
        sorted(
            next_hosts.items()
        )
    )

    pending_hosts = sorted(
        hostname
        for hostname, entry in (
            next_dns_state[
                "hosts"
            ].items()
        )
        if (
            isinstance(
                entry,
                dict,
            )
            and entry.get(
                "status"
            )
            == "pending"
        )
    )

    return {
        "version": (
            EXACT_PROMOTION_APPLY_VERSION
        ),
        "mode": (
            EXACT_PROMOTION_APPLY_MODE
        ),
        "service": service,
        "evaluated_at": iso(
            now
        ),
        "source_content_hash": (
            source_content_hash
        ),
        "source_classified_at": (
            source_classified_at
        ),
        "source_promotion_evaluated_at": (
            source_promotion_evaluated_at
        ),
        "criteria": (
            normalized_settings
        ),
        "counts": counts,
        "candidates": results,
        "pending_hosts": (
            pending_hosts
        ),
        "dns_state": (
            next_dns_state
        ),
    }


def apply_exact_promotion_pending(
    runtime_state: dict[str, Any],
    classification_state: dict[str, Any],
    promotion_state: dict[str, Any],
    dns_state: dict[str, Any],
    hostname_policy_cfg: dict[str, Any],
    state_path: Path,
    pending_path: Path,
    dry_run: bool,
    now: datetime,
    *,
    settings: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """
    Evaluate Exact Promotion Apply and optionally persist new pending
    Exact DNS entries.

    Writes are intentionally limited to:
    - Exact DNS state.json
    - Exact DNS pending.txt

    No active/public DNS file is accepted as an argument, therefore this
    writer cannot publish a hostname directly.

    Dry-run computes the complete prospective result without writes.
    """

    try:
        result = (
            evaluate_exact_promotion_apply(
                runtime_state,
                classification_state,
                promotion_state,
                dns_state,
                hostname_policy_cfg,
                now,
                settings=settings,
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
            "pending_path": str(
                pending_path
            ),
            "result": None,
            "error": str(exc),
        }

    created_pending = (
        result[
            "counts"
        ][
            "created_pending"
        ]
    )

    if dry_run:
        return {
            "status": "ok",
            "written": False,
            "dry_run": True,
            "state_path": str(
                state_path
            ),
            "pending_path": str(
                pending_path
            ),
            "result": result,
        }

    if (
        created_pending
        == 0
    ):
        return {
            "status": "ok",
            "written": False,
            "dry_run": False,
            "state_path": str(
                state_path
            ),
            "pending_path": str(
                pending_path
            ),
            "result": result,
        }

    try:
        # state.json is authoritative. Write it first so a later
        # pending.txt failure cannot lose the promoted Exact DNS entry.
        save_json(
            state_path,
            result[
                "dns_state"
            ],
        )

        write_host_file(
            pending_path,
            result[
                "pending_hosts"
            ],
        )

    except OSError as exc:
        return {
            "status": "write_error",
            "written": False,
            "dry_run": False,
            "state_path": str(
                state_path
            ),
            "pending_path": str(
                pending_path
            ),
            "result": result,
            "error": str(exc),
        }

    return {
        "status": "ok",
        "written": True,
        "dry_run": False,
        "state_path": str(
            state_path
        ),
        "pending_path": str(
            pending_path
        ),
        "result": result,
    }
