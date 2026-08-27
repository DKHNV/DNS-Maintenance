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


@dataclass(frozen=True)
class DNSSettings:
    resolvers: tuple[str, ...]
    timeout_seconds: float
    lifetime_seconds: float
    negative_votes_required: int
    suspect_after_hours: float
    quarantine_after_hours: float
    expire_after_hours: float
    negative_streak_max_gap_hours: float
    suspect_min_negative_observations: int
    quarantine_min_negative_observations: int
    max_workers: int


@dataclass(frozen=True)
class CollectionPaths:
    active: Path
    data_dir: Path
    manual: Path
    discovered: Path
    pending: Path
    suspect: Path
    quarantine: Path
    expired: Path
    excluded: Path
    state: Path
    runtime_candidate_state: Path
    runtime_candidate_classification: Path
    runtime_candidate_exact_promotion: Path
    discovery_state: Path
    service_state: Path
    service_alive: Path
    service_suspect: Path
    service_dead: Path
    service_unknown: Path
    report: Path


def _merge(base: dict[str, Any], override: Any) -> dict[str, Any]:
    result = dict(base)
    if isinstance(override, dict):
        result.update(override)
    return result


def load_config(path: Path) -> dict[str, Any]:
    cfg = load_json(path, None)
    if not isinstance(cfg, dict):
        raise ValueError("Config must be a JSON object")
    if int(cfg.get("version", 1)) != 1:
        raise ValueError("Unsupported config version")
    collections = cfg.get("collections")
    if not isinstance(collections, list) or not collections:
        raise ValueError(
            "Config must contain a non-empty collections array"
        )

    names: set[str] = set()

    for item in collections:
        if not isinstance(item, dict):
            raise ValueError(
                "Each collection must be an object"
            )

        name = str(item.get("name", "")).strip()

        if not name or name in names:
            raise ValueError(
                f"Invalid or duplicate collection name: {name!r}"
            )

        names.add(name)

        if (
            not item.get("active_file")
            or not item.get("data_dir")
        ):
            raise ValueError(
                f"Collection {name} requires "
                "active_file and data_dir"
            )

        runtime_candidate_settings(item)
        runtime_candidate_classification_settings(item)
        runtime_candidate_eligibility_settings(item)
        runtime_candidate_maturity_settings(item)
        runtime_candidate_exact_promotion_settings(item)
        runtime_candidate_exact_promotion_apply_settings(item)
        hostname_policy_settings(item)

    return cfg


def collections_for(
    cfg: dict[str, Any],
    selected: set[str] | None = None,
) -> list[dict[str, Any]]:
    items = list(cfg["collections"])

    if not selected:
        return items

    available = {
        str(x["name"])
        for x in items
    }
    unknown = selected - available

    if unknown:
        raise ValueError(
            f"Unknown collection(s): "
            f"{', '.join(sorted(unknown))}"
        )

    return [
        x
        for x in items
        if str(x["name"]) in selected
    ]


def runtime_candidate_classification_settings(
    collection: dict[str, Any],
) -> dict[str, Any]:
    runtime_cfg = collection.get(
        "runtime_candidate"
    )

    if runtime_cfg is None:
        return {
            "enabled": False,
        }

    if not isinstance(runtime_cfg, dict):
        raise ValueError(
            "runtime_candidate must be an object"
        )

    raw = runtime_cfg.get(
        "classification"
    )

    if raw is None:
        return {
            "enabled": False,
        }

    if not isinstance(raw, dict):
        raise ValueError(
            "runtime_candidate.classification "
            "must be an object"
        )

    result = dict(raw)
    result.setdefault(
        "enabled",
        False,
    )

    if not isinstance(
        result["enabled"],
        bool,
    ):
        raise ValueError(
            "runtime_candidate.classification.enabled "
            "must be boolean"
        )

    runtime_enabled = runtime_candidate_settings(
        collection
    )["enabled"]

    if (
        result["enabled"]
        and not runtime_enabled
    ):
        raise ValueError(
            "runtime_candidate.classification.enabled "
            "requires runtime_candidate.enabled"
        )

    return result


def runtime_candidate_eligibility_settings(
    collection: dict[str, Any],
) -> dict[str, Any]:
    runtime_cfg = collection.get(
        "runtime_candidate"
    )

    if runtime_cfg is None:
        return normalize_candidate_eligibility_settings(
            None
        )

    if not isinstance(runtime_cfg, dict):
        raise ValueError(
            "runtime_candidate must be an object"
        )

    classification_cfg = runtime_cfg.get(
        "classification"
    )

    if classification_cfg is None:
        raw = None

    else:
        if not isinstance(
            classification_cfg,
            dict,
        ):
            raise ValueError(
                "runtime_candidate.classification "
                "must be an object"
            )

        raw = classification_cfg.get(
            "candidate_eligibility"
        )

    result = normalize_candidate_eligibility_settings(
        raw
    )

    classification_enabled = (
        runtime_candidate_classification_settings(
            collection
        )["enabled"]
    )

    if (
        result["enabled"]
        and not classification_enabled
    ):
        raise ValueError(
            "runtime_candidate.classification."
            "candidate_eligibility.enabled requires "
            "runtime_candidate.classification.enabled"
        )

    return result


def runtime_candidate_maturity_settings(
    collection: dict[str, Any],
) -> dict[str, Any]:
    runtime_cfg = collection.get(
        "runtime_candidate"
    )

    if runtime_cfg is None:
        return normalize_candidate_maturity_settings(
            None
        )

    if not isinstance(runtime_cfg, dict):
        raise ValueError(
            "runtime_candidate must be an object"
        )

    classification_cfg = runtime_cfg.get(
        "classification"
    )

    if classification_cfg is None:
        raw = None

    else:
        if not isinstance(
            classification_cfg,
            dict,
        ):
            raise ValueError(
                "runtime_candidate.classification "
                "must be an object"
            )

        raw = classification_cfg.get(
            "candidate_maturity"
        )

    result = normalize_candidate_maturity_settings(
        raw
    )

    classification_enabled = (
        runtime_candidate_classification_settings(
            collection
        )["enabled"]
    )

    if (
        result["enabled"]
        and not classification_enabled
    ):
        raise ValueError(
            "runtime_candidate.classification."
            "candidate_maturity.enabled requires "
            "runtime_candidate.classification.enabled"
        )

    eligibility_enabled = (
        runtime_candidate_eligibility_settings(
            collection
        )["enabled"]
    )

    if (
        result["enabled"]
        and not eligibility_enabled
    ):
        raise ValueError(
            "runtime_candidate.classification."
            "candidate_maturity.enabled requires "
            "runtime_candidate.classification."
            "candidate_eligibility.enabled"
        )

    return result


def runtime_candidate_exact_promotion_settings(
    collection: dict[str, Any],
) -> dict[str, Any]:
    """
    Validate Exact Promotion v1 configuration.

    The import is intentionally local because
    runtime_candidate_exact_promotion imports Hostname Policy,
    while policy imports CollectionPaths from this module.
    Keeping this import lazy avoids a config -> promotion ->
    policy -> config import cycle.
    """

    from .runtime_candidate_exact_promotion import (
        exact_promotion_settings as normalize_exact_promotion_settings,
    )

    runtime_cfg = collection.get(
        "runtime_candidate"
    )

    if runtime_cfg is None:
        return normalize_exact_promotion_settings(
            None
        )

    if not isinstance(runtime_cfg, dict):
        raise ValueError(
            "runtime_candidate must be an object"
        )

    raw = runtime_cfg.get(
        "exact_promotion"
    )

    result = normalize_exact_promotion_settings(
        raw
    )

    runtime_enabled = runtime_candidate_settings(
        collection
    )["enabled"]

    if (
        result["enabled"]
        and not runtime_enabled
    ):
        raise ValueError(
            "runtime_candidate."
            "exact_promotion.enabled requires "
            "runtime_candidate.enabled"
        )

    classification_enabled = (
        runtime_candidate_classification_settings(
            collection
        )["enabled"]
    )

    if (
        result["enabled"]
        and not classification_enabled
    ):
        raise ValueError(
            "runtime_candidate."
            "exact_promotion.enabled requires "
            "runtime_candidate.classification.enabled"
        )

    eligibility_enabled = (
        runtime_candidate_eligibility_settings(
            collection
        )["enabled"]
    )

    if (
        result["enabled"]
        and not eligibility_enabled
    ):
        raise ValueError(
            "runtime_candidate."
            "exact_promotion.enabled requires "
            "runtime_candidate.classification."
            "candidate_eligibility.enabled"
        )

    maturity_enabled = (
        runtime_candidate_maturity_settings(
            collection
        )["enabled"]
    )

    if (
        result["enabled"]
        and not maturity_enabled
    ):
        raise ValueError(
            "runtime_candidate."
            "exact_promotion.enabled requires "
            "runtime_candidate.classification."
            "candidate_maturity.enabled"
        )

    return result


def runtime_candidate_exact_promotion_apply_settings(
    collection: dict[str, Any],
) -> dict[str, Any]:
    """
    Validate Exact Promotion Apply v1 configuration.

    The import is intentionally local because the Apply module imports
    dns_engine, while dns_engine imports configuration types from this
    module. Keeping the import lazy avoids a config -> apply ->
    dns_engine -> config import cycle.

    Apply is disabled by default and may only be enabled when the
    shadow Exact Promotion stage is enabled.
    """

    from .runtime_candidate_exact_promotion_apply import (
        exact_promotion_apply_settings as normalize_exact_promotion_apply_settings,
    )

    runtime_cfg = collection.get(
        "runtime_candidate"
    )

    if runtime_cfg is None:
        return normalize_exact_promotion_apply_settings(
            None
        )

    if not isinstance(
        runtime_cfg,
        dict,
    ):
        raise ValueError(
            "runtime_candidate must be an object"
        )

    raw = runtime_cfg.get(
        "exact_promotion_apply"
    )

    result = (
        normalize_exact_promotion_apply_settings(
            raw
        )
    )

    promotion_enabled = (
        runtime_candidate_exact_promotion_settings(
            collection
        )["enabled"]
    )

    if (
        result["enabled"]
        and not promotion_enabled
    ):
        raise ValueError(
            "runtime_candidate."
            "exact_promotion_apply.enabled requires "
            "runtime_candidate."
            "exact_promotion.enabled"
        )

    return result


def dns_settings(
    cfg: dict[str, Any],
    collection: dict[str, Any],
) -> DNSSettings:
    defaults = (
        cfg.get("defaults", {})
        if isinstance(
            cfg.get("defaults"),
            dict,
        )
        else {}
    )

    raw = _merge(
        (
            defaults.get("dns", {})
            if isinstance(
                defaults.get("dns"),
                dict,
            )
            else {}
        ),
        collection.get("dns"),
    )

    resolvers = tuple(
        str(x)
        for x in raw.get(
            "resolvers",
            [
                "1.1.1.1",
                "8.8.8.8",
                "9.9.9.9",
            ],
        )
    )

    if not resolvers:
        raise ValueError(
            "At least one DNS resolver is required"
        )

    for resolver in resolvers:
        try:
            ipaddress.ip_address(
                resolver
            )
        except ValueError as exc:
            raise ValueError(
                "Resolver must be an IP address: "
                f"{resolver}"
            ) from exc

    settings = DNSSettings(
        resolvers=resolvers,
        timeout_seconds=float(
            raw.get(
                "timeout_seconds",
                2.0,
            )
        ),
        lifetime_seconds=float(
            raw.get(
                "lifetime_seconds",
                4.0,
            )
        ),
        negative_votes_required=int(
            raw.get(
                "negative_votes_required",
                2,
            )
        ),
        suspect_after_hours=float(
            raw.get(
                "suspect_after_hours",
                72.0,
            )
        ),
        quarantine_after_hours=float(
            raw.get(
                "quarantine_after_hours",
                168.0,
            )
        ),
        expire_after_hours=float(
            raw.get(
                "expire_after_hours",
                720.0,
            )
        ),
        negative_streak_max_gap_hours=float(
            raw.get(
                "negative_streak_max_gap_hours",
                48.0,
            )
        ),
        suspect_min_negative_observations=int(
            raw.get(
                "suspect_min_negative_observations",
                3,
            )
        ),
        quarantine_min_negative_observations=int(
            raw.get(
                "quarantine_min_negative_observations",
                7,
            )
        ),
        max_workers=int(
            raw.get(
                "max_workers",
                20,
            )
        ),
    )

    if not (
        1
        <= settings.negative_votes_required
        <= len(settings.resolvers)
    ):
        raise ValueError(
            "negative_votes_required "
            "must fit resolver count"
        )

    if (
        settings.suspect_after_hours <= 0
        or settings.quarantine_after_hours
        < settings.suspect_after_hours
    ):
        raise ValueError(
            "DNS time thresholds are invalid"
        )

    if (
        settings.expire_after_hours <= 0
        or settings.negative_streak_max_gap_hours
        <= 0
    ):
        raise ValueError(
            "DNS expiry/gap thresholds "
            "must be positive"
        )

    if (
        settings.suspect_min_negative_observations
        < 1
    ):
        raise ValueError(
            "suspect_min_negative_observations "
            "must be >= 1"
        )

    if (
        settings.quarantine_min_negative_observations
        < settings.suspect_min_negative_observations
    ):
        raise ValueError(
            "quarantine_min_negative_observations "
            "must be >= suspect minimum"
        )

    if settings.max_workers < 1:
        raise ValueError(
            "max_workers must be >= 1"
        )

    return settings


def service_settings(
    cfg: dict[str, Any],
    collection: dict[str, Any],
) -> dict[str, Any]:
    defaults = (
        cfg.get("defaults", {})
        if isinstance(
            cfg.get("defaults"),
            dict,
        )
        else {}
    )

    base = (
        defaults.get(
            "service_check",
            {},
        )
        if isinstance(
            defaults.get(
                "service_check"
            ),
            dict,
        )
        else {}
    )

    raw = _merge(
        base,
        collection.get(
            "service_check"
        ),
    )

    raw.setdefault(
        "enabled",
        False,
    )
    raw.setdefault(
        "port",
        443,
    )
    raw.setdefault(
        "path",
        "/",
    )
    raw.setdefault(
        "timeout_seconds",
        4.0,
    )
    raw.setdefault(
        "max_workers",
        10,
    )
    raw.setdefault(
        "max_ipv4_per_host",
        3,
    )
    raw.setdefault(
        "suspect_after_hours",
        72.0,
    )
    raw.setdefault(
        "dead_after_hours",
        168.0,
    )
    raw.setdefault(
        "failure_streak_max_gap_hours",
        48.0,
    )
    raw.setdefault(
        "suspect_min_failure_observations",
        3,
    )
    raw.setdefault(
        "dead_min_failure_observations",
        7,
    )
    raw.setdefault(
        "history_days",
        14.0,
    )
    raw.setdefault(
        "history_max_entries",
        256,
    )
    raw.setdefault(
        "failure_log_limit",
        50,
    )
    raw.setdefault(
        "user_agent",
        "DKHNV-DNS-Maintenance/1.0",
    )

    if (
        int(raw["port"]) < 1
        or int(raw["port"]) > 65535
    ):
        raise ValueError(
            "service_check.port "
            "must be 1..65535"
        )

    if (
        float(
            raw["suspect_after_hours"]
        )
        <= 0
        or float(
            raw["dead_after_hours"]
        )
        < float(
            raw["suspect_after_hours"]
        )
    ):
        raise ValueError(
            "Service time thresholds are invalid"
        )

    if (
        int(
            raw[
                "dead_min_failure_observations"
            ]
        )
        < int(
            raw[
                "suspect_min_failure_observations"
            ]
        )
    ):
        raise ValueError(
            "Service observation thresholds "
            "are invalid"
        )

    if (
        float(
            raw["history_days"]
        )
        <= 0
        or int(
            raw["history_max_entries"]
        )
        < 1
    ):
        raise ValueError(
            "Service history settings are invalid"
        )

    return raw


def discovery_settings(
    collection: dict[str, Any],
) -> dict[str, Any]:
    raw = (
        collection.get(
            "discovery",
            {},
        )
        if isinstance(
            collection.get(
                "discovery"
            ),
            dict,
        )
        else {}
    )

    raw = dict(raw)

    raw.setdefault(
        "enabled",
        False,
    )
    raw.setdefault(
        "sources",
        [],
    )

    if (
        raw["enabled"]
        and not isinstance(
            raw["sources"],
            list,
        )
    ):
        raise ValueError(
            "discovery.sources must be an array"
        )

    for source in raw["sources"]:
        if (
            not isinstance(
                source,
                dict,
            )
            or source.get("type")
            != "certspotter"
        ):
            raise ValueError(
                "v1 supports discovery source "
                "type 'certspotter' only"
            )

        roots = source.get(
            "roots",
            [],
        )

        if (
            not isinstance(
                roots,
                list,
            )
            or not roots
        ):
            raise ValueError(
                "certspotter source requires "
                "non-empty roots"
            )

        for root in roots:
            if not normalize_hostname(
                str(root)
            ):
                raise ValueError(
                    "Invalid discovery root: "
                    f"{root!r}"
                )

    return raw


def runtime_candidate_settings(
    collection: dict[str, Any],
) -> dict[str, Any]:
    raw = collection.get(
        "runtime_candidate"
    )

    if raw is None:
        return {
            "enabled": False,
        }

    if not isinstance(
        raw,
        dict,
    ):
        raise ValueError(
            "runtime_candidate "
            "must be an object"
        )

    result = dict(raw)
    result.setdefault(
        "enabled",
        False,
    )

    if not isinstance(
        result["enabled"],
        bool,
    ):
        raise ValueError(
            "runtime_candidate.enabled "
            "must be boolean"
        )

    return result


def hostname_policy_settings(
    collection: dict[str, Any],
) -> dict[str, Any]:
    raw = (
        collection.get(
            "hostname_policy",
            {},
        )
        if isinstance(
            collection.get(
                "hostname_policy"
            ),
            dict,
        )
        else {}
    )

    result = dict(raw)

    result.setdefault(
        "enabled",
        False,
    )
    result.setdefault(
        "allow",
        [],
    )
    result.setdefault(
        "exclude",
        [],
    )

    if not isinstance(
        result["enabled"],
        bool,
    ):
        raise ValueError(
            "hostname_policy.enabled "
            "must be boolean"
        )

    seen_ids: set[str] = set()

    for group in (
        "allow",
        "exclude",
    ):
        rules = result[group]

        if not isinstance(
            rules,
            list,
        ):
            raise ValueError(
                f"hostname_policy.{group} "
                "must be an array"
            )

        normalized_rules: list[
            dict[str, Any]
        ] = []

        for index, raw_rule in enumerate(
            rules
        ):
            if not isinstance(
                raw_rule,
                dict,
            ):
                raise ValueError(
                    f"hostname_policy."
                    f"{group}[{index}] "
                    "must be an object"
                )

            match = str(
                raw_rule.get(
                    "match",
                    "",
                )
            ).strip().lower()

            if match not in {
                "exact",
                "suffix",
            }:
                raise ValueError(
                    f"hostname_policy."
                    f"{group}[{index}].match "
                    "must be 'exact' or 'suffix'"
                )

            value = normalize_hostname(
                str(
                    raw_rule.get(
                        "value",
                        "",
                    )
                )
            )

            if not value:
                raise ValueError(
                    f"hostname_policy."
                    f"{group}[{index}] "
                    "has invalid hostname value"
                )

            rule_id = str(
                raw_rule.get("id")
                or (
                    f"{group}:"
                    f"{match}:"
                    f"{value}"
                )
            ).strip()

            if (
                not rule_id
                or rule_id in seen_ids
            ):
                raise ValueError(
                    "Duplicate or empty hostname "
                    "policy rule id: "
                    f"{rule_id!r}"
                )

            seen_ids.add(
                rule_id
            )

            reason = str(
                raw_rule.get("reason")
                or ""
            ).strip()

            if (
                group == "exclude"
                and not reason
            ):
                raise ValueError(
                    f"hostname_policy."
                    f"exclude[{index}] "
                    "requires a reason"
                )

            normalized_rules.append(
                {
                    "id": rule_id,
                    "match": match,
                    "value": value,
                    "reason": reason,
                }
            )

        result[group] = (
            normalized_rules
        )

    return result


def collection_paths(
    repo_root: Path,
    collection: dict[str, Any],
) -> CollectionPaths:
    data_rel = str(
        collection["data_dir"]
    ).rstrip("/")

    data_dir = safe_path(
        repo_root,
        data_rel,
    )

    def p(name: str) -> Path:
        return safe_path(
            repo_root,
            f"{data_rel}/{name}",
        )

    return CollectionPaths(
        active=safe_path(
            repo_root,
            str(
                collection["active_file"]
            ),
        ),
        data_dir=data_dir,
        manual=p(
            "manual.txt"
        ),
        discovered=p(
            "discovered.txt"
        ),
        pending=p(
            "pending.txt"
        ),
        suspect=p(
            "suspect.txt"
        ),
        quarantine=p(
            "quarantine.txt"
        ),
        expired=p(
            "expired.txt"
        ),
        excluded=p(
            "excluded.txt"
        ),
        state=p(
            "state.json"
        ),
        runtime_candidate_state=p(
            "runtime_candidate_state.json"
        ),
        runtime_candidate_classification=p(
            "runtime_candidate_classification.json"
        ),
        runtime_candidate_exact_promotion=p(
            "runtime_candidate_exact_promotion.json"
        ),
        discovery_state=p(
            "discovery_state.json"
        ),
        service_state=p(
            "service_state.json"
        ),
        service_alive=p(
            "service_alive.txt"
        ),
        service_suspect=p(
            "service_suspect.txt"
        ),
        service_dead=p(
            "service_dead.txt"
        ),
        service_unknown=p(
            "service_unknown.txt"
        ),
        report=p(
            "report.md"
        ),
    )
