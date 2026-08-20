from __future__ import annotations

import concurrent.futures
import socket
import ssl
from datetime import datetime, timedelta
from typing import Any

from .config import CollectionPaths
from .utils import hours_between, iso, load_json, parse_iso, save_json, write_host_file

SERVICE_STATE_VERSION = 3


def probe_ip(host: str, ip: str, cfg: dict[str, Any]) -> dict[str, Any]:
    port = int(cfg["port"])
    timeout = float(cfg["timeout_seconds"])
    path = str(cfg["path"])
    user_agent = str(cfg["user_agent"])
    base = {"ip": ip, "port": port}
    try:
        raw = socket.create_connection((ip, port), timeout=timeout)
        raw.settimeout(timeout)
        context = ssl.create_default_context()
        with raw, context.wrap_socket(raw, server_hostname=host) as tls:
            tls_version = tls.version()
            cipher = tls.cipher()[0] if tls.cipher() else None
            request = f"HEAD {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: {user_agent}\r\nConnection: close\r\n\r\n".encode()
            try:
                tls.sendall(request)
                data = tls.recv(512)
                first = data.split(b"\r\n", 1)[0].decode("latin1", errors="replace")
                parts = first.split()
                code = int(parts[1]) if len(parts) >= 2 and parts[1].isdigit() else None
                return {**base, "status": "HTTPS_OK" if code is not None else "TLS_OK", "http_status": code, "tls_version": tls_version, "cipher": cipher}
            except (socket.timeout, OSError):
                return {**base, "status": "TLS_OK", "tls_version": tls_version, "cipher": cipher}
    except socket.timeout as exc:
        return {**base, "status": "TIMEOUT", "detail": str(exc)[:300]}
    except ConnectionRefusedError as exc:
        return {**base, "status": "REFUSED", "detail": str(exc)[:300]}
    except ssl.SSLCertVerificationError as exc:
        return {**base, "status": "TLS_CERT_ERROR", "detail": str(exc)[:300]}
    except ssl.SSLError as exc:
        return {**base, "status": "TLS_ERROR", "detail": str(exc)[:300]}
    except OSError as exc:
        return {**base, "status": "NETWORK_ERROR", "detail": str(exc)[:300]}


def aggregate_attempts(attempts: list[dict[str, Any]]) -> str:
    if any(x.get("status") in {"HTTPS_OK", "TLS_OK"} for x in attempts):
        return "ALIVE"
    return "FAILURE" if attempts else "SKIPPED"


def probe_host(host: str, ipv4: list[str], cfg: dict[str, Any]) -> tuple[str, list[dict[str, Any]], list[str]]:
    selected = sorted(set(ipv4))[: int(cfg["max_ipv4_per_host"])]
    attempts: list[dict[str, Any]] = []
    for ip in selected:
        attempt = probe_ip(host, ip, cfg)
        attempts.append(attempt)
        if attempt.get("status") in {"HTTPS_OK", "TLS_OK"}:
            break
    return aggregate_attempts(attempts), attempts, selected


def new_service_state(host: str, now: datetime) -> dict[str, Any]:
    return {
        "hostname": host, "status": "unknown", "first_seen": iso(now), "last_check": None,
        "last_success": None, "last_failure": None, "last_result": "UNTESTED", "ever_alive": False,
        "last_ipv4": [], "attempts": [], "failure_since": None, "failure_observations": 0,
        "consecutive_failures": 0, "history": [], "history_samples": 0, "history_successes": 0,
        "history_failures": 0, "stability_score": None,
    }


def normalize_service_entry(state: dict[str, Any]) -> None:
    previous = state.get("last_failure")
    if isinstance(previous, str) and previous:
        state["last_failure"] = {"at": previous, "type": "LEGACY", "statuses": [], "attempts": []}
    state.setdefault("failure_since", None)
    state.setdefault("failure_observations", 0)
    state.setdefault("consecutive_failures", int(state.get("consecutive_failures", 0)))
    state.setdefault("history", [])
    state.setdefault("history_samples", 0)
    state.setdefault("history_successes", 0)
    state.setdefault("history_failures", 0)
    state.setdefault("stability_score", None)


def failure_record(attempts: list[dict[str, Any]], now: datetime) -> dict[str, Any]:
    compact = []
    for a in attempts:
        if a.get("status") in {"HTTPS_OK", "TLS_OK"}:
            continue
        item = {"ip": a.get("ip"), "port": a.get("port"), "status": str(a.get("status", "ERROR"))}
        if a.get("detail"):
            item["detail"] = " ".join(str(a["detail"]).split())[:300]
        compact.append(item)
    statuses = sorted({x["status"] for x in compact})
    return {"at": iso(now), "type": statuses[0] if len(statuses) == 1 else "MULTIPLE" if statuses else "UNKNOWN", "statuses": statuses, "attempts": compact}


def history_event(aggregate: str, attempts: list[dict[str, Any]], now: datetime) -> dict[str, Any]:
    event: dict[str, Any] = {"at": iso(now), "result": aggregate}
    if aggregate == "ALIVE":
        ok = next((x for x in attempts if x.get("status") in {"HTTPS_OK", "TLS_OK"}), None)
        if ok:
            event.update({"type": ok.get("status"), "ip": ok.get("ip")})
            if ok.get("http_status") is not None:
                event["http_status"] = ok.get("http_status")
            if ok.get("tls_version"):
                event["tls_version"] = ok.get("tls_version")
    elif aggregate == "FAILURE":
        record = failure_record(attempts, now)
        event.update({"type": record["type"], "statuses": record["statuses"]})
    else:
        event["type"] = "DNS_SKIPPED"
    return event


def update_history(state: dict[str, Any], event: dict[str, Any], now: datetime, cfg: dict[str, Any]) -> None:
    history = state.setdefault("history", [])
    if not isinstance(history, list):
        history = []
        state["history"] = history
    history.append(event)
    cutoff = now - timedelta(days=float(cfg["history_days"]))
    filtered = [x for x in history if isinstance(x, dict) and (parse_iso(x.get("at")) or now) >= cutoff]
    max_entries = int(cfg["history_max_entries"])
    state["history"] = filtered[-max_entries:]
    measured = [x for x in state["history"] if x.get("result") in {"ALIVE", "FAILURE"}]
    successes = sum(1 for x in measured if x.get("result") == "ALIVE")
    failures = sum(1 for x in measured if x.get("result") == "FAILURE")
    state["history_samples"] = len(measured)
    state["history_successes"] = successes
    state["history_failures"] = failures
    state["stability_score"] = round(successes * 100 / len(measured), 1) if measured else None


def _failure_window(state: dict[str, Any], now: datetime, cfg: dict[str, Any]) -> tuple[datetime, int]:
    last_failure = state.get("last_failure")
    last_at = parse_iso(last_failure.get("at")) if isinstance(last_failure, dict) else None
    start = parse_iso(state.get("failure_since"))
    observations = int(state.get("failure_observations", 0))
    if start is None or last_at is None or hours_between(last_at, now) > float(cfg["failure_streak_max_gap_hours"]):
        return now, 1
    return start, observations + 1


def apply_service_result(state: dict[str, Any], aggregate: str, attempts: list[dict[str, Any]], ipv4: list[str], now: datetime, cfg: dict[str, Any]) -> tuple[str, str]:
    normalize_service_entry(state)
    old = str(state.get("status", "unknown"))
    state["last_check"] = iso(now)
    state["last_result"] = aggregate
    state["attempts"] = attempts
    state["last_ipv4"] = list(ipv4)
    update_history(state, history_event(aggregate, attempts, now), now, cfg)

    if aggregate == "ALIVE":
        state.update({"status": "alive", "last_success": iso(now), "ever_alive": True, "failure_since": None, "failure_observations": 0, "consecutive_failures": 0})
        return old, "alive"
    if aggregate == "SKIPPED":
        return old, str(state.get("status", "unknown"))

    start, observations = _failure_window(state, now, cfg)
    state["failure_since"] = iso(start)
    state["failure_observations"] = observations
    state["consecutive_failures"] = observations
    state["last_failure"] = failure_record(attempts, now)
    elapsed = hours_between(start, now)
    if elapsed >= float(cfg["dead_after_hours"]) and observations >= int(cfg["dead_min_failure_observations"]):
        state["status"] = "dead"
    elif elapsed >= float(cfg["suspect_after_hours"]) and observations >= int(cfg["suspect_min_failure_observations"]):
        state["status"] = "suspect"
    elif old not in {"suspect", "dead"}:
        state["status"] = "alive" if state.get("ever_alive") else "unknown"
    return old, str(state["status"])


def load_service_state(path: Any) -> dict[str, Any]:
    state = load_json(path, {"version": SERVICE_STATE_VERSION, "updated_at": None, "hosts": {}})
    if not isinstance(state, dict) or not isinstance(state.get("hosts"), dict):
        raise ValueError(f"Invalid service state: {path}")
    version = int(state.get("version", 1))
    if version not in {1, 2, 3}:
        raise ValueError(f"Unsupported service state version: {version}")
    for entry in state["hosts"].values():
        if isinstance(entry, dict):
            normalize_service_entry(entry)
    state["version"] = SERVICE_STATE_VERSION
    return state


def probe_services(name: str, paths: CollectionPaths, dns_state: dict[str, Any], cfg: dict[str, Any], now: datetime, dry_run: bool) -> tuple[dict[str, Any], dict[str, int]]:
    state = load_service_state(paths.service_state)
    if not cfg.get("enabled", False):
        return state, {"checked": 0, "alive": 0, "suspect": 0, "dead": 0, "unknown": 0}
    dns_hosts = dns_state.get("hosts", {})
    active_hosts = sorted(h for h, e in dns_hosts.items() if e.get("status") in {"active", "suspect"} and e.get("ever_validated"))
    service_hosts: dict[str, dict[str, Any]] = state["hosts"]
    for host in active_hosts:
        service_hosts.setdefault(host, new_service_state(host, now))

    print(f"[{name}] HTTPS/TLS: probing {len(active_hosts)} active DNS host(s)")
    results: dict[str, tuple[str, list[dict[str, Any]], list[str]]] = {}
    def work(host: str):
        ipv4 = dns_hosts.get(host, {}).get("ipv4", [])
        return host, probe_host(host, [str(x) for x in ipv4] if isinstance(ipv4, list) else [], cfg)
    with concurrent.futures.ThreadPoolExecutor(max_workers=int(cfg["max_workers"])) as pool:
        futures = [pool.submit(work, host) for host in active_hosts]
        for future in concurrent.futures.as_completed(futures):
            host, result = future.result()
            results[host] = result

    transitions = []
    failure_types: dict[str, int] = {}
    for host in active_hosts:
        aggregate, attempts, ips = results[host]
        old, new = apply_service_result(service_hosts[host], aggregate, attempts, ips, now, cfg)
        if old != new:
            transitions.append((host, old, new))
        if aggregate == "FAILURE":
            for attempt in attempts:
                status = str(attempt.get("status", "ERROR"))
                failure_types[status] = failure_types.get(status, 0) + 1

    active_set = set(active_hosts)
    alive = {h for h in active_set if service_hosts[h].get("status") == "alive"}
    suspect = {h for h in active_set if service_hosts[h].get("status") == "suspect"}
    dead = {h for h in active_set if service_hosts[h].get("status") == "dead"}
    unknown = active_set - alive - suspect - dead
    if failure_types:
        print(f"[{name}] HTTPS/TLS failures: " + " ".join(f"{k}={v}" for k, v in sorted(failure_types.items())))
    for host, old, new in transitions[:30]:
        print(f"[{name}] HTTPS/TLS transition: {host}: {old} -> {new}")

    limit = int(cfg["failure_log_limit"])
    failed = [h for h in active_hosts if results[h][0] == "FAILURE"]
    for host in failed[:limit]:
        entry = service_hosts[host]
        print(f"[{name}] HTTPS/TLS failure: {host} status={entry.get('status')} observations={entry.get('failure_observations')} since={entry.get('failure_since')}")
        for attempt in results[host][1]:
            line = f"[{name}]   {attempt.get('ip')}:{attempt.get('port')} {attempt.get('status')}"
            if attempt.get("detail"):
                line += " " + " ".join(str(attempt["detail"]).split())[:300]
            print(line)

    state["version"] = SERVICE_STATE_VERSION
    state["updated_at"] = iso(now)
    state["hosts"] = dict(sorted(service_hosts.items()))
    if not dry_run:
        save_json(paths.service_state, state)
        write_host_file(paths.service_alive, alive)
        write_host_file(paths.service_suspect, suspect)
        write_host_file(paths.service_dead, dead)
        write_host_file(paths.service_unknown, unknown)
    print(f"[{name}] HTTPS/TLS: alive={len(alive)} suspect={len(suspect)} dead={len(dead)} unknown={len(unknown)}")
    return state, {"checked": len(active_hosts), "alive": len(alive), "suspect": len(suspect), "dead": len(dead), "unknown": len(unknown)}
