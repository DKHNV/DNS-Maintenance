from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any

from .config import CollectionPaths
from .utils import iso, save_json, write_host_file


@dataclass(frozen=True)
class PolicyDecision:
    excluded: bool
    rule: str | None = None
    reason: str | None = None
    manual_override: bool = False


def _matches(host: str, rule: dict[str, Any]) -> bool:
    value = str(rule["value"])
    match = str(rule["match"])
    if match == "exact":
        return host == value
    if match == "suffix":
        return host == value or host.endswith("." + value)
    raise ValueError(f"Unsupported hostname policy match type: {match}")


def evaluate_hostname(host: str, cfg: dict[str, Any], *, manual_override: bool = False) -> PolicyDecision:
    if manual_override:
        return PolicyDecision(False, manual_override=True)
    if not cfg.get("enabled", False):
        return PolicyDecision(False)

    # Explicit allow rules are exceptions to broader excludes.
    for rule in cfg.get("allow", []):
        if _matches(host, rule):
            return PolicyDecision(False, rule=str(rule["id"]), reason=str(rule.get("reason") or "explicit allow"))

    for rule in cfg.get("exclude", []):
        if _matches(host, rule):
            return PolicyDecision(True, rule=str(rule["id"]), reason=str(rule["reason"]))

    return PolicyDecision(False)


def _normalize_policy_entry(entry: dict[str, Any]) -> None:
    entry.setdefault("policy_excluded_at", None)
    entry.setdefault("policy_rule", None)
    entry.setdefault("policy_reason", None)


def _clear_policy(entry: dict[str, Any]) -> None:
    entry["policy_excluded_at"] = None
    entry["policy_rule"] = None
    entry["policy_reason"] = None


def _sync_dns_files(paths: CollectionPaths, state: dict[str, Any]) -> None:
    hosts = state.get("hosts", {})
    active = {h for h, e in hosts.items() if e.get("status") in {"active", "suspect"} and e.get("ever_validated")}
    pending = {h for h, e in hosts.items() if e.get("status") == "pending"}
    suspect = {h for h, e in hosts.items() if e.get("status") == "suspect"}
    quarantine = {h for h, e in hosts.items() if e.get("status") == "quarantine"}
    expired = {h for h, e in hosts.items() if e.get("status") == "expired"}
    excluded = {h for h, e in hosts.items() if e.get("status") == "excluded"}

    write_host_file(paths.active, active)
    write_host_file(paths.pending, pending)
    write_host_file(paths.suspect, suspect)
    write_host_file(paths.quarantine, quarantine)
    write_host_file(paths.expired, expired)
    write_host_file(paths.excluded, excluded)
    save_json(paths.state, state)


def apply_hostname_policy(
    name: str,
    paths: CollectionPaths,
    dns_state: dict[str, Any],
    cfg: dict[str, Any],
    now: datetime,
    dry_run: bool,
) -> tuple[dict[str, Any], dict[str, int]]:
    hosts = dns_state.get("hosts", {})
    if not isinstance(hosts, dict):
        raise ValueError(f"[{name}] invalid DNS state for hostname policy")

    previously_managed = any(
        isinstance(entry, dict)
        and (entry.get("status") == "excluded" or entry.get("policy_excluded_at"))
        for entry in hosts.values()
    )
    if not cfg.get("enabled", False) and not previously_managed:
        return dns_state, {"excluded": 0, "transitions": 0, "manual_overrides": 0}

    stamp = iso(now)
    transitions = 0
    manual_overrides = 0

    for host, entry in sorted(hosts.items()):
        if not isinstance(entry, dict):
            continue
        _normalize_policy_entry(entry)
        was_policy_excluded = entry.get("status") == "excluded" or bool(entry.get("policy_excluded_at"))

        sources = {str(x) for x in entry.get("sources", [])}
        manual_override = "manual" in sources
        if manual_override:
            manual_overrides += 1

        # DNS safety/lifecycle states are stronger than semantic policy.
        # A manual override must never resurrect quarantine/expired entries.
        if entry.get("status") in {"quarantine", "expired"}:
            if was_policy_excluded:
                _clear_policy(entry)
            continue

        decision = evaluate_hostname(host, cfg, manual_override=manual_override)
        if decision.excluded:
            if entry.get("status") != "excluded":
                transitions += 1
                print(f"[{name}] hostname policy: {host}: {entry.get('status')} -> excluded ({decision.rule})")
            entry["status"] = "excluded"
            entry["policy_excluded_at"] = entry.get("policy_excluded_at") or stamp
            entry["policy_rule"] = decision.rule
            entry["policy_reason"] = decision.reason
            continue

        if was_policy_excluded:
            # maintain_dns has already performed this cycle's DNS check. Only a
            # fresh OK may republish a hostname after policy release/override.
            fresh_ok = entry.get("last_check") == stamp and entry.get("last_result") == "OK"
            old = str(entry.get("status", "excluded"))
            _clear_policy(entry)
            if fresh_ok:
                entry["status"] = "active"
                entry["ever_validated"] = True
                if old != "active":
                    transitions += 1
                    print(f"[{name}] hostname policy: {host}: excluded -> active (fresh DNS OK)")
            else:
                entry["status"] = "pending"
                entry["ever_validated"] = False
                if old != "pending":
                    transitions += 1
                    print(f"[{name}] hostname policy: {host}: excluded -> pending (revalidation required)")

    excluded = sum(1 for e in hosts.values() if isinstance(e, dict) and e.get("status") == "excluded")
    dns_state["hosts"] = dict(sorted(hosts.items()))
    if not dry_run:
        _sync_dns_files(paths, dns_state)

    print(f"[{name}] hostname policy: excluded={excluded} transitions={transitions} manual_overrides={manual_overrides}")
    return dns_state, {"excluded": excluded, "transitions": transitions, "manual_overrides": manual_overrides}
