from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from pathlib import Path
from typing import Any

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
    state: Path
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
        raise ValueError("Config must contain a non-empty collections array")
    names: set[str] = set()
    for item in collections:
        if not isinstance(item, dict):
            raise ValueError("Each collection must be an object")
        name = str(item.get("name", "")).strip()
        if not name or name in names:
            raise ValueError(f"Invalid or duplicate collection name: {name!r}")
        names.add(name)
        if not item.get("active_file") or not item.get("data_dir"):
            raise ValueError(f"Collection {name} requires active_file and data_dir")
    return cfg


def collections_for(cfg: dict[str, Any], selected: set[str] | None = None) -> list[dict[str, Any]]:
    items = list(cfg["collections"])
    if not selected:
        return items
    available = {str(x["name"]) for x in items}
    unknown = selected - available
    if unknown:
        raise ValueError(f"Unknown collection(s): {', '.join(sorted(unknown))}")
    return [x for x in items if str(x["name"]) in selected]


def dns_settings(cfg: dict[str, Any], collection: dict[str, Any]) -> DNSSettings:
    defaults = cfg.get("defaults", {}) if isinstance(cfg.get("defaults"), dict) else {}
    raw = _merge(defaults.get("dns", {}) if isinstance(defaults.get("dns"), dict) else {}, collection.get("dns"))
    resolvers = tuple(str(x) for x in raw.get("resolvers", ["1.1.1.1", "8.8.8.8", "9.9.9.9"]))
    if not resolvers:
        raise ValueError("At least one DNS resolver is required")
    for resolver in resolvers:
        try:
            ipaddress.ip_address(resolver)
        except ValueError as exc:
            raise ValueError(f"Resolver must be an IP address: {resolver}") from exc
    settings = DNSSettings(
        resolvers=resolvers,
        timeout_seconds=float(raw.get("timeout_seconds", 2.0)),
        lifetime_seconds=float(raw.get("lifetime_seconds", 4.0)),
        negative_votes_required=int(raw.get("negative_votes_required", 2)),
        suspect_after_hours=float(raw.get("suspect_after_hours", 72.0)),
        quarantine_after_hours=float(raw.get("quarantine_after_hours", 168.0)),
        expire_after_hours=float(raw.get("expire_after_hours", 720.0)),
        negative_streak_max_gap_hours=float(raw.get("negative_streak_max_gap_hours", 48.0)),
        suspect_min_negative_observations=int(raw.get("suspect_min_negative_observations", 3)),
        quarantine_min_negative_observations=int(raw.get("quarantine_min_negative_observations", 7)),
        max_workers=int(raw.get("max_workers", 20)),
    )
    if not 1 <= settings.negative_votes_required <= len(settings.resolvers):
        raise ValueError("negative_votes_required must fit resolver count")
    if settings.suspect_after_hours <= 0 or settings.quarantine_after_hours < settings.suspect_after_hours:
        raise ValueError("DNS time thresholds are invalid")
    if settings.expire_after_hours <= 0 or settings.negative_streak_max_gap_hours <= 0:
        raise ValueError("DNS expiry/gap thresholds must be positive")
    if settings.suspect_min_negative_observations < 1:
        raise ValueError("suspect_min_negative_observations must be >= 1")
    if settings.quarantine_min_negative_observations < settings.suspect_min_negative_observations:
        raise ValueError("quarantine_min_negative_observations must be >= suspect minimum")
    if settings.max_workers < 1:
        raise ValueError("max_workers must be >= 1")
    return settings


def service_settings(cfg: dict[str, Any], collection: dict[str, Any]) -> dict[str, Any]:
    defaults = cfg.get("defaults", {}) if isinstance(cfg.get("defaults"), dict) else {}
    base = defaults.get("service_check", {}) if isinstance(defaults.get("service_check"), dict) else {}
    raw = _merge(base, collection.get("service_check"))
    raw.setdefault("enabled", False)
    raw.setdefault("port", 443)
    raw.setdefault("path", "/")
    raw.setdefault("timeout_seconds", 4.0)
    raw.setdefault("max_workers", 10)
    raw.setdefault("max_ipv4_per_host", 3)
    raw.setdefault("suspect_after_hours", 72.0)
    raw.setdefault("dead_after_hours", 168.0)
    raw.setdefault("failure_streak_max_gap_hours", 48.0)
    raw.setdefault("suspect_min_failure_observations", 3)
    raw.setdefault("dead_min_failure_observations", 7)
    raw.setdefault("history_days", 14.0)
    raw.setdefault("history_max_entries", 256)
    raw.setdefault("failure_log_limit", 50)
    raw.setdefault("user_agent", "DKHNV-DNS-Maintenance/1.0")
    if int(raw["port"]) < 1 or int(raw["port"]) > 65535:
        raise ValueError("service_check.port must be 1..65535")
    if float(raw["suspect_after_hours"]) <= 0 or float(raw["dead_after_hours"]) < float(raw["suspect_after_hours"]):
        raise ValueError("Service time thresholds are invalid")
    if int(raw["dead_min_failure_observations"]) < int(raw["suspect_min_failure_observations"]):
        raise ValueError("Service observation thresholds are invalid")
    if float(raw["history_days"]) <= 0 or int(raw["history_max_entries"]) < 1:
        raise ValueError("Service history settings are invalid")
    return raw


def discovery_settings(collection: dict[str, Any]) -> dict[str, Any]:
    raw = collection.get("discovery", {}) if isinstance(collection.get("discovery"), dict) else {}
    raw = dict(raw)
    raw.setdefault("enabled", False)
    raw.setdefault("sources", [])
    if raw["enabled"] and not isinstance(raw["sources"], list):
        raise ValueError("discovery.sources must be an array")
    for source in raw["sources"]:
        if not isinstance(source, dict) or source.get("type") != "certspotter":
            raise ValueError("v1 supports discovery source type 'certspotter' only")
        roots = source.get("roots", [])
        if not isinstance(roots, list) or not roots:
            raise ValueError("certspotter source requires non-empty roots")
        for root in roots:
            if not normalize_hostname(str(root)):
                raise ValueError(f"Invalid discovery root: {root!r}")
    return raw


def collection_paths(repo_root: Path, collection: dict[str, Any]) -> CollectionPaths:
    data_rel = str(collection["data_dir"]).rstrip("/")
    data_dir = safe_path(repo_root, data_rel)
    def p(name: str) -> Path:
        return safe_path(repo_root, f"{data_rel}/{name}")
    return CollectionPaths(
        active=safe_path(repo_root, str(collection["active_file"])),
        data_dir=data_dir,
        manual=p("manual.txt"),
        discovered=p("discovered.txt"),
        pending=p("pending.txt"),
        suspect=p("suspect.txt"),
        quarantine=p("quarantine.txt"),
        expired=p("expired.txt"),
        state=p("state.json"),
        discovery_state=p("discovery_state.json"),
        service_state=p("service_state.json"),
        service_alive=p("service_alive.txt"),
        service_suspect=p("service_suspect.txt"),
        service_dead=p("service_dead.txt"),
        service_unknown=p("service_unknown.txt"),
        report=p("report.md"),
    )
