from __future__ import annotations

import concurrent.futures
import ipaddress
import sys
from dataclasses import dataclass
from datetime import datetime
from typing import Any

import dns.exception
import dns.resolver

from .config import DNSSettings, CollectionPaths
from .utils import hours_between, iso, load_json, parse_iso, read_host_file, save_json, write_host_file

DNS_STATE_VERSION = 2


@dataclass(frozen=True)
class DNSResult:
    aggregate: str
    ipv4: tuple[str, ...]
    canonical_name: str | None
    resolver_results: dict[str, dict[str, Any]]


def aggregate_resolver_results(results: dict[str, dict[str, Any]], negative_votes_required: int) -> DNSResult:
    ipv4: set[str] = set()
    canonical: list[str] = []
    negatives = 0
    for result in results.values():
        status = result.get("status")
        if status == "OK":
            ipv4.update(str(x) for x in result.get("ipv4", []))
            if result.get("canonical_name"):
                canonical.append(str(result["canonical_name"]))
        elif status in {"NXDOMAIN", "NO_A"}:
            negatives += 1
    aggregate = "OK" if ipv4 else "NEGATIVE" if negatives >= negative_votes_required else "TRANSIENT"
    return DNSResult(
        aggregate,
        tuple(sorted(ipv4, key=ipaddress.ip_address)),
        sorted(canonical)[0] if canonical else None,
        results,
    )


def query_one_resolver(host: str, nameserver: str, settings: DNSSettings) -> dict[str, Any]:
    resolver = dns.resolver.Resolver(configure=False)
    resolver.nameservers = [nameserver]
    resolver.timeout = settings.timeout_seconds
    resolver.lifetime = settings.lifetime_seconds
    resolver.retry_servfail = True
    try:
        answer = resolver.resolve(host, "A", search=False)
        return {
            "status": "OK",
            "ipv4": sorted({r.address for r in answer}),
            "canonical_name": str(answer.canonical_name).rstrip(".").lower(),
        }
    except dns.resolver.NXDOMAIN:
        return {"status": "NXDOMAIN", "ipv4": []}
    except dns.resolver.NoAnswer:
        return {"status": "NO_A", "ipv4": []}
    except dns.resolver.NoNameservers as exc:
        return {"status": "NO_NAMESERVERS", "ipv4": [], "detail": str(exc)[:300]}
    except (dns.resolver.LifetimeTimeout, dns.exception.Timeout) as exc:
        return {"status": "TIMEOUT", "ipv4": [], "detail": str(exc)[:300]}
    except dns.exception.DNSException as exc:
        return {"status": "DNS_ERROR", "ipv4": [], "detail": f"{type(exc).__name__}: {exc}"[:300]}
    except Exception as exc:
        return {"status": "ERROR", "ipv4": [], "detail": f"{type(exc).__name__}: {exc}"[:300]}


def check_host(host: str, settings: DNSSettings) -> DNSResult:
    results = {resolver: query_one_resolver(host, resolver, settings) for resolver in settings.resolvers}
    return aggregate_resolver_results(results, settings.negative_votes_required)


def new_host_state(host: str, now: datetime, source: str, legacy_active: bool = False) -> dict[str, Any]:
    return {
        "hostname": host,
        "status": "active" if legacy_active else "pending",
        "sources": [source],
        "first_seen": iso(now),
        "last_check": None,
        "last_success": None,
        "last_negative": None,
        "last_result": "UNTESTED",
        "negative_since": None,
        "negative_observations": 0,
        "consecutive_negative_checks": 0,
        "ever_validated": bool(legacy_active),
        "ipv4": [],
        "canonical_name": None,
        "quarantined_at": None,
        "expired_at": None,
        "resolver_results": {},
    }


def add_source(state: dict[str, Any], source: str) -> None:
    state["sources"] = sorted(set(str(x) for x in state.get("sources", [])) | {source})


def normalize_dns_entry(state: dict[str, Any]) -> None:
    # Safe migration from the Telegram count-based v1 state. We deliberately do
    # not infer negative_since from old counters: time-based escalation starts
    # only after v2 observes a fresh negative result.
    state.setdefault("negative_since", None)
    state.setdefault("negative_observations", 0)
    state.setdefault("consecutive_negative_checks", int(state.get("consecutive_negative_checks", 0)))
    state.setdefault("last_negative", state.get("last_failure"))


def _negative_window(state: dict[str, Any], now: datetime, settings: DNSSettings) -> tuple[datetime, int]:
    last_negative = parse_iso(state.get("last_negative"))
    start = parse_iso(state.get("negative_since"))
    observations = int(state.get("negative_observations", 0))
    if start is None or last_negative is None or hours_between(last_negative, now) > settings.negative_streak_max_gap_hours:
        return now, 1
    return start, observations + 1


def apply_dns_result(state: dict[str, Any], result: DNSResult, now: datetime, settings: DNSSettings) -> tuple[str, str]:
    normalize_dns_entry(state)
    old = str(state.get("status", "pending"))
    stamp = iso(now)
    state["last_check"] = stamp
    state["resolver_results"] = result.resolver_results

    if result.aggregate == "OK":
        state.update({
            "status": "active", "last_success": stamp, "last_result": "OK",
            "negative_since": None, "negative_observations": 0, "consecutive_negative_checks": 0,
            "ever_validated": True, "ipv4": list(result.ipv4), "canonical_name": result.canonical_name,
            "quarantined_at": None, "expired_at": None,
        })
        return old, "active"

    if result.aggregate == "TRANSIENT":
        state["last_result"] = "TRANSIENT"
        return old, str(state.get("status", "pending"))

    start, observations = _negative_window(state, now, settings)
    state["negative_since"] = iso(start)
    state["last_negative"] = stamp
    state["last_failure"] = stamp  # compatibility/readability
    state["last_result"] = "NEGATIVE"
    state["negative_observations"] = observations
    state["consecutive_negative_checks"] = observations
    state["ipv4"] = []
    state["canonical_name"] = None

    if old == "quarantine":
        quarantined_at = parse_iso(state.get("quarantined_at")) or now
        state["quarantined_at"] = iso(quarantined_at)
        if hours_between(quarantined_at, now) >= settings.expire_after_hours:
            state["status"] = "expired"
            state["expired_at"] = stamp
            return old, "expired"
        return old, "quarantine"

    elapsed = hours_between(start, now)
    if elapsed >= settings.quarantine_after_hours and observations >= settings.quarantine_min_negative_observations:
        state["status"] = "quarantine"
        state["quarantined_at"] = stamp
        return old, "quarantine"
    if elapsed >= settings.suspect_after_hours and observations >= settings.suspect_min_negative_observations:
        state["status"] = "suspect"
        return old, "suspect"

    # Preserve an already-suspect state during a fresh v2 observation window;
    # it can only recover on OK, and can only escalate on sufficient time+evidence.
    if old == "suspect":
        state["status"] = "suspect"
    else:
        state["status"] = "active" if state.get("ever_validated") else "pending"
    return old, str(state["status"])


def load_dns_state(path: Any) -> dict[str, Any]:
    state = load_json(path, {"version": DNS_STATE_VERSION, "updated_at": None, "hosts": {}})
    if not isinstance(state, dict) or not isinstance(state.get("hosts"), dict):
        raise ValueError(f"Invalid DNS state: {path}")
    version = int(state.get("version", 1))
    if version not in {1, DNS_STATE_VERSION}:
        raise ValueError(f"Unsupported DNS state version: {version}")
    for entry in state["hosts"].values():
        if isinstance(entry, dict):
            normalize_dns_entry(entry)
    state["version"] = DNS_STATE_VERSION
    return state


def maintain_dns(
    name: str,
    paths: CollectionPaths,
    settings: DNSSettings,
    now: datetime,
    candidate_sources: dict[str, set[str]],
    dry_run: bool,
) -> tuple[dict[str, Any], dict[str, int]]:
    state = load_dns_state(paths.state)
    hosts: dict[str, dict[str, Any]] = state["hosts"]

    imported = 0
    for host in sorted(read_host_file(paths.active)):
        if host not in hosts:
            hosts[host] = new_host_state(host, now, "legacy_active", legacy_active=True)
            imported += 1

    queues = {
        "manual": read_host_file(paths.manual),
        "external_discovery": read_host_file(paths.discovered),
    }
    for source, queue in queues.items():
        for host in queue:
            candidate_sources.setdefault(host, set()).add(source)

    for host, sources in sorted(candidate_sources.items()):
        if host not in hosts:
            hosts[host] = new_host_state(host, now, sorted(sources)[0], legacy_active=False)
            imported += 1
        elif hosts[host].get("status") == "expired":
            hosts[host]["status"] = "pending"
            hosts[host]["expired_at"] = None
            hosts[host]["quarantined_at"] = None
            hosts[host]["negative_since"] = None
            hosts[host]["negative_observations"] = 0
            hosts[host]["ever_validated"] = False
        for source in sources:
            add_source(hosts[host], source)

    targets = sorted(host for host, entry in hosts.items() if entry.get("status") != "expired")
    print(f"[{name}] DNS: checking {len(targets)} host(s) with {len(settings.resolvers)} resolver(s)")
    results: dict[str, DNSResult] = {}
    if targets:
        with concurrent.futures.ThreadPoolExecutor(max_workers=min(settings.max_workers, len(targets))) as pool:
            future_map = {pool.submit(check_host, host, settings): host for host in targets}
            for future in concurrent.futures.as_completed(future_map):
                host = future_map[future]
                try:
                    results[host] = future.result()
                except Exception as exc:
                    print(f"WARN [{name}] DNS worker {host}: {exc}", file=sys.stderr)
                    results[host] = DNSResult("TRANSIENT", tuple(), None, {"internal": {"status": "ERROR"}})

    counts = {"OK": 0, "NEGATIVE": 0, "TRANSIENT": 0}
    transitions = 0
    for host in targets:
        result = results[host]
        counts[result.aggregate] += 1
        old, new = apply_dns_result(hosts[host], result, now, settings)
        if old != new:
            transitions += 1
            print(f"[{name}] DNS transition: {host}: {old} -> {new}")

    active = {h for h, e in hosts.items() if e.get("status") in {"active", "suspect"} and e.get("ever_validated")}
    pending = {h for h, e in hosts.items() if e.get("status") == "pending"}
    suspect = {h for h, e in hosts.items() if e.get("status") == "suspect"}
    quarantine = {h for h, e in hosts.items() if e.get("status") == "quarantine"}
    expired = {h for h, e in hosts.items() if e.get("status") == "expired"}
    state["version"] = DNS_STATE_VERSION
    state["updated_at"] = iso(now)
    state["hosts"] = dict(sorted(hosts.items()))

    if not dry_run:
        write_host_file(paths.active, active)
        write_host_file(paths.pending, pending)
        write_host_file(paths.suspect, suspect)
        write_host_file(paths.quarantine, quarantine)
        write_host_file(paths.expired, expired)
        write_host_file(paths.manual, [])
        write_host_file(paths.discovered, [])
        save_json(paths.state, state)

    print(f"[{name}] DNS: OK={counts['OK']} NEGATIVE={counts['NEGATIVE']} TRANSIENT={counts['TRANSIENT']} | active={len(active)} pending={len(pending)} suspect={len(suspect)} quarantine={len(quarantine)} expired={len(expired)}")
    return state, {
        "checked": len(targets), "imported": imported, "ok": counts["OK"], "negative": counts["NEGATIVE"],
        "transient": counts["TRANSIENT"], "active": len(active), "pending": len(pending), "suspect": len(suspect),
        "quarantine": len(quarantine), "expired": len(expired), "transitions": transitions,
    }
