from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Any

from .runtime_candidate_exact_promotion import (
    EXACT_PROMOTION_MODE,
    EXACT_PROMOTION_VERSION,
    evaluate_exact_promotion,
    exact_promotion_settings,
)
from .utils import iso, parse_iso, save_json


def _validate_runtime_state(
    runtime_state: dict[str, Any],
) -> tuple[str, str, dict[str, Any]]:
    if not isinstance(
        runtime_state,
        dict,
    ):
        raise ValueError(
            "Runtime Candidate state "
            "must be an object"
        )

    service = runtime_state.get(
        "service"
    )

    if (
        not isinstance(service, str)
        or not service
    ):
        raise ValueError(
            "Runtime Candidate state service "
            "must be non-empty"
        )

    source_content_hash = (
        runtime_state.get(
            "source_content_hash"
        )
    )

    if (
        not isinstance(
            source_content_hash,
            str,
        )
        or not source_content_hash
    ):
        raise ValueError(
            "Runtime Candidate state "
            "source_content_hash "
            "must be non-empty"
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

    for candidate_id, candidate in (
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
                "Runtime Candidate state entry "
                "must be an object"
            )

        if (
            candidate.get(
                "candidate_id"
            )
            != candidate_id
        ):
            raise ValueError(
                "Runtime Candidate state "
                "candidate_id mismatch"
            )

    return (
        service,
        source_content_hash,
        candidates,
    )


def _validate_classification_state(
    classification_state: dict[str, Any],
    *,
    service: str,
    source_content_hash: str,
    runtime_candidate_ids: set[str],
) -> tuple[str, dict[str, Any]]:
    if not isinstance(
        classification_state,
        dict,
    ):
        raise ValueError(
            "Runtime Candidate classification "
            "snapshot must be an object"
        )

    if (
        classification_state.get(
            "version"
        )
        != 1
    ):
        raise ValueError(
            "Runtime Candidate classification "
            "version is unsupported"
        )

    if (
        classification_state.get(
            "mode"
        )
        != "shadow"
    ):
        raise ValueError(
            "Runtime Candidate classification "
            "mode is unsupported"
        )

    if (
        classification_state.get(
            "service"
        )
        != service
    ):
        raise ValueError(
            "Runtime Candidate classification "
            "service mismatch"
        )

    if (
        classification_state.get(
            "source_content_hash"
        )
        != source_content_hash
    ):
        raise ValueError(
            "Runtime Candidate classification "
            "source_content_hash mismatch"
        )

    classified_at = (
        classification_state.get(
            "classified_at"
        )
    )

    if (
        not isinstance(
            classified_at,
            str,
        )
        or parse_iso(
            classified_at
        )
        is None
    ):
        raise ValueError(
            "Runtime Candidate classification "
            "classified_at is invalid"
        )

    candidates = (
        classification_state.get(
            "candidates"
        )
    )

    if not isinstance(
        candidates,
        dict,
    ):
        raise ValueError(
            "Runtime Candidate classification "
            "candidates must be an object"
        )

    classification_ids = set(
        candidates
    )

    if (
        classification_ids
        != runtime_candidate_ids
    ):
        raise ValueError(
            "Runtime Candidate classification "
            "candidate set mismatch"
        )

    for candidate_id, result in (
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
                "Runtime Candidate classification "
                "candidate_id must be non-empty"
            )

        if not isinstance(
            result,
            dict,
        ):
            raise ValueError(
                "Runtime Candidate classification "
                "entry must be an object"
            )

    return (
        classified_at,
        candidates,
    )


def evaluate_exact_promotion_state(
    runtime_state: dict[str, Any],
    classification_state: dict[str, Any],
    dns_state: dict[str, Any],
    hostname_policy_cfg: dict[str, Any],
    now: datetime,
    *,
    settings: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """
    Produce an Exact Promotion v1 shadow snapshot.

    The Runtime Candidate and Classification snapshots must describe
    the same service, the same feed content hash, and the same complete
    candidate set. Any mismatch fails closed.

    This function is read-only and cannot mutate Exact DNS.
    """

    normalized_settings = (
        exact_promotion_settings(
            settings
        )
    )

    (
        service,
        source_content_hash,
        runtime_candidates,
    ) = _validate_runtime_state(
        runtime_state
    )

    (
        classified_at,
        classified_candidates,
    ) = _validate_classification_state(
        classification_state,
        service=service,
        source_content_hash=(
            source_content_hash
        ),
        runtime_candidate_ids=set(
            runtime_candidates
        ),
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

    if not isinstance(
        hostname_policy_cfg,
        dict,
    ):
        raise ValueError(
            "Hostname Policy config "
            "must be an object"
        )

    evaluated: dict[
        str,
        dict[str, Any],
    ] = {}

    counts = {
        "hold": 0,
        "eligible": 0,
    }

    for candidate_id in sorted(
        runtime_candidates
    ):
        candidate = (
            runtime_candidates[
                candidate_id
            ]
        )

        classification = (
            classified_candidates[
                candidate_id
            ]
        )

        result = (
            evaluate_exact_promotion(
                candidate,
                classification,
                dns_state,
                hostname_policy_cfg,
                settings=(
                    normalized_settings
                ),
            )
        )

        if (
            result.get(
                "candidate_id"
            )
            != candidate_id
        ):
            raise ValueError(
                "Exact Promotion candidate_id "
                "mismatch"
            )

        state = result.get(
            "state"
        )

        if state not in counts:
            raise ValueError(
                "Exact Promotion state "
                "is unsupported"
            )

        counts[state] += 1

        evaluated[
            candidate_id
        ] = result

    return {
        "version": (
            EXACT_PROMOTION_VERSION
        ),
        "mode": (
            EXACT_PROMOTION_MODE
        ),
        "service": service,
        "evaluated_at": iso(
            now
        ),
        "source_content_hash": (
            source_content_hash
        ),
        "source_classified_at": (
            classified_at
        ),
        "counts": counts,
        "candidates": evaluated,
    }


def write_exact_promotion_snapshot(
    runtime_state: dict[str, Any],
    classification_state: dict[str, Any],
    dns_state: dict[str, Any],
    hostname_policy_cfg: dict[str, Any],
    state_path: Path,
    dry_run: bool,
    now: datetime,
    *,
    settings: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """
    Compute and optionally persist an Exact Promotion shadow snapshot.

    Invalid inputs never overwrite an existing snapshot.
    Dry-run computes the prospective snapshot without writing it.

    This writer only writes its own shadow snapshot. It has no path
    to Exact DNS state, pending.txt, active files, or Service_DNS.
    """

    try:
        snapshot = (
            evaluate_exact_promotion_state(
                runtime_state,
                classification_state,
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
