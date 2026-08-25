from __future__ import annotations

from pathlib import Path
from typing import Any

from .config import (
    collection_paths,
    collections_for,
    discovery_settings,
    dns_settings,
    hostname_policy_settings,
    runtime_candidate_classification_settings,
    runtime_candidate_eligibility_settings,
    runtime_candidate_maturity_settings,
    runtime_candidate_settings,
    service_settings,
)
from .discovery import discover
from .dns_engine import maintain_dns
from .policy import apply_hostname_policy
from .report import write_report
from .runtime_candidate import intake_runtime_candidate_feed
from .runtime_candidate_classification import (
    write_runtime_candidate_classification_snapshot,
)
from .service import probe_services
from .utils import utc_now


def run(
    repo_root: Path,
    cfg: dict[str, Any],
    selected: set[str] | None,
    dry_run: bool,
) -> int:
    now = utc_now()

    for collection in collections_for(cfg, selected):
        name = str(collection["name"])
        paths = collection_paths(repo_root, collection)

        runtime_candidate_cfg = runtime_candidate_settings(
            collection
        )

        runtime_classification_cfg = (
            runtime_candidate_classification_settings(
                collection
            )
        )

        runtime_eligibility_cfg = (
            runtime_candidate_eligibility_settings(
                collection
            )
        )

        runtime_maturity_cfg = (
            runtime_candidate_maturity_settings(
                collection
            )
        )

        runtime_candidate_state: (
            dict[str, Any] | None
        ) = None

        runtime_candidate_intake_status = "disabled"

        if runtime_candidate_cfg["enabled"]:
            try:
                runtime_candidate_result = (
                    intake_runtime_candidate_feed(
                        repo_root,
                        name,
                        paths.runtime_candidate_state,
                        dry_run,
                        now,
                    )
                )

                status = runtime_candidate_result[
                    "status"
                ]

                runtime_candidate_intake_status = (
                    status
                )

                if status == "ok":
                    runtime_state = (
                        runtime_candidate_result.get(
                            "state"
                        )
                    )

                    if isinstance(
                        runtime_state,
                        dict,
                    ):
                        runtime_candidate_state = (
                            runtime_state
                        )

                    candidate_count = 0

                    if isinstance(
                        runtime_state,
                        dict,
                    ):
                        runtime_candidates = (
                            runtime_state.get(
                                "candidates",
                                {},
                            )
                        )

                        if isinstance(
                            runtime_candidates,
                            dict,
                        ):
                            candidate_count = len(
                                runtime_candidates
                            )

                    print(
                        f"[{name}] runtime candidate intake: "
                        f"status=ok "
                        f"candidates={candidate_count} "
                        f"written="
                        f"{runtime_candidate_result['written']} "
                        f"dry_run={dry_run}"
                    )

                else:
                    error = (
                        runtime_candidate_result.get(
                            "error"
                        )
                    )

                    message = (
                        f"[{name}] runtime candidate intake: "
                        f"status={status}"
                    )

                    if error:
                        message += (
                            f" error={error}"
                        )

                    print(message)

            except Exception as exc:
                runtime_candidate_intake_status = (
                    "error"
                )

                print(
                    f"[{name}] runtime candidate intake: "
                    f"status=error error={exc}"
                )

        discovery_cfg = discovery_settings(
            collection
        )

        candidates, discovery_state, _ = discover(
            name,
            paths,
            discovery_cfg,
            now,
            dry_run,
        )

        dns_state, _ = maintain_dns(
            name,
            paths,
            dns_settings(
                cfg,
                collection,
            ),
            now,
            candidates,
            dry_run,
        )

        policy_cfg = hostname_policy_settings(
            collection
        )

        dns_state, _ = apply_hostname_policy(
            name,
            paths,
            dns_state,
            policy_cfg,
            now,
            dry_run,
        )

        if runtime_classification_cfg["enabled"]:
            if (
                runtime_candidate_intake_status
                != "ok"
                or runtime_candidate_state is None
            ):
                print(
                    f"[{name}] runtime candidate "
                    f"classification: "
                    f"status=skipped "
                    f"reason=intake_"
                    f"{runtime_candidate_intake_status}"
                )

            else:
                try:
                    classification_result = (
                        write_runtime_candidate_classification_snapshot(
                            runtime_candidate_state,
                            dns_state,
                            policy_cfg,
                            paths.runtime_candidate_classification,
                            dry_run,
                            now,
                            candidate_eligibility_cfg=(
                                runtime_eligibility_cfg
                            ),
                            candidate_maturity_cfg=(
                                runtime_maturity_cfg
                            ),
                        )
                    )

                    classification_status = (
                        classification_result[
                            "status"
                        ]
                    )

                    if classification_status == "ok":
                        classification_state = (
                            classification_result.get(
                                "state"
                            )
                        )

                        counts = {
                            "observed": 0,
                            "observe_only": 0,
                            "rejected": 0,
                        }

                        maturity_counts = {
                            "tracking": 0,
                            "ready": 0,
                        }

                        maturity_active = False

                        if isinstance(
                            classification_state,
                            dict,
                        ):
                            state_counts = (
                                classification_state.get(
                                    "counts",
                                    {},
                                )
                            )

                            if isinstance(
                                state_counts,
                                dict,
                            ):
                                for key in (
                                    "observed",
                                    "observe_only",
                                    "rejected",
                                ):
                                    value = (
                                        state_counts.get(
                                            key,
                                            0,
                                        )
                                    )

                                    if (
                                        type(value)
                                        is int
                                    ):
                                        counts[
                                            key
                                        ] = value

                                if (
                                    "candidate"
                                    in state_counts
                                ):
                                    candidate_value = (
                                        state_counts[
                                            "candidate"
                                        ]
                                    )

                                    if (
                                        type(
                                            candidate_value
                                        )
                                        is int
                                    ):
                                        counts[
                                            "candidate"
                                        ] = (
                                            candidate_value
                                        )

                            classified_candidates = (
                                classification_state.get(
                                    "candidates",
                                    {},
                                )
                            )

                            if isinstance(
                                classified_candidates,
                                dict,
                            ):
                                for result in (
                                    classified_candidates.values()
                                ):
                                    if not isinstance(
                                        result,
                                        dict,
                                    ):
                                        continue

                                    maturity = result.get(
                                        "maturity"
                                    )

                                    if not isinstance(
                                        maturity,
                                        dict,
                                    ):
                                        continue

                                    maturity_state = (
                                        maturity.get(
                                            "state"
                                        )
                                    )

                                    if (
                                        maturity_state
                                        in maturity_counts
                                    ):
                                        maturity_active = True
                                        maturity_counts[
                                            maturity_state
                                        ] += 1

                        candidate_message = ""

                        if "candidate" in counts:
                            candidate_message = (
                                f"candidate="
                                f"{counts['candidate']} "
                            )

                        maturity_message = ""

                        if maturity_active:
                            maturity_message = (
                                f"maturity_tracking="
                                f"{maturity_counts['tracking']} "
                                f"maturity_ready="
                                f"{maturity_counts['ready']} "
                            )

                        print(
                            f"[{name}] runtime candidate "
                            f"classification: "
                            f"status=ok mode=shadow "
                            f"observed="
                            f"{counts['observed']} "
                            f"{candidate_message}"
                            f"observe_only="
                            f"{counts['observe_only']} "
                            f"rejected="
                            f"{counts['rejected']} "
                            f"{maturity_message}"
                            f"written="
                            f"{classification_result['written']} "
                            f"dry_run={dry_run}"
                        )

                    else:
                        error = (
                            classification_result.get(
                                "error"
                            )
                        )

                        message = (
                            f"[{name}] runtime candidate "
                            f"classification: "
                            f"status="
                            f"{classification_status}"
                        )

                        if error:
                            message += (
                                f" error={error}"
                            )

                        print(message)

                except Exception as exc:
                    print(
                        f"[{name}] runtime candidate "
                        f"classification: "
                        f"status=error error={exc}"
                    )

        service_cfg = service_settings(
            cfg,
            collection,
        )

        service_state, _ = probe_services(
            name,
            paths,
            dns_state,
            service_cfg,
            now,
            dry_run,
        )

        report = write_report(
            name,
            str(collection["active_file"]),
            paths,
            dns_state,
            service_state,
            discovery_state,
            now,
            dry_run,
        )

        if dry_run:
            print(
                f"[{name}] DRY RUN report preview:\n"
                f"{report[:2000]}"
            )

    return 0
