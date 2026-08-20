from __future__ import annotations

from collections import Counter
from datetime import datetime
from typing import Any

from .config import CollectionPaths
from .utils import atomic_write_text, iso


def _esc(value: Any) -> str:
    return str(value).replace("|", "\\|").replace("\n", " ")


def render_report(name: str, active_file: str, dns_state: dict[str, Any], service_state: dict[str, Any], discovery_state: dict[str, Any], now: datetime) -> str:
    dns_hosts = dns_state.get("hosts", {}) if isinstance(dns_state.get("hosts"), dict) else {}
    service_hosts = service_state.get("hosts", {}) if isinstance(service_state.get("hosts"), dict) else {}
    dns_counts = Counter(str(e.get("status", "unknown")) for e in dns_hosts.values() if isinstance(e, dict))
    service_counts = Counter(str(e.get("status", "unknown")) for e in service_hosts.values() if isinstance(e, dict))
    current_failures = Counter()
    rows = []
    for host, entry in service_hosts.items():
        if not isinstance(entry, dict) or entry.get("last_result") != "FAILURE":
            continue
        last_failure = entry.get("last_failure") if isinstance(entry.get("last_failure"), dict) else {}
        ftype = str(last_failure.get("type", "UNKNOWN"))
        current_failures[ftype] += 1
        rows.append((host, entry, ftype))
    scores = [float(e["stability_score"]) for e in service_hosts.values() if isinstance(e, dict) and e.get("stability_score") is not None]
    lines = [
        f"# {name.title()} DNS Maintenance Report",
        "",
        f"Generated: `{iso(now)}`",
        "",
        "## DNS lifecycle",
        "",
        "| State | Hosts |",
        "|---|---:|",
        f"| Active | {dns_counts.get('active', 0)} |",
        f"| Pending | {dns_counts.get('pending', 0)} |",
        f"| Suspect | {dns_counts.get('suspect', 0)} |",
        f"| Quarantine | {dns_counts.get('quarantine', 0)} |",
        f"| Expired | {dns_counts.get('expired', 0)} |",
        "",
        "## HTTPS/TLS observation",
        "",
        "| State | Hosts |",
        "|---|---:|",
        f"| Alive | {service_counts.get('alive', 0)} |",
        f"| Unknown | {service_counts.get('unknown', 0)} |",
        f"| Suspect | {service_counts.get('suspect', 0)} |",
        f"| Dead | {service_counts.get('dead', 0)} |",
        "",
        "## Stability window",
        "",
        "The score is based on measured HTTPS/TLS checks within the configured calendar-day window. SKIPPED observations are excluded.",
        "",
        f"Measured hosts: **{len(scores)}**",
        f"Average stability: **{round(sum(scores) / len(scores), 1) if scores else 'n/a'}%**" if scores else "Average stability: **n/a**",
        "",
        "## Current HTTPS/TLS failures",
        "",
    ]
    if current_failures:
        lines += ["| Type | Hosts |", "|---|---:|"]
        for kind, count in sorted(current_failures.items()):
            lines.append(f"| {_esc(kind)} | {count} |")
    else:
        lines.append("No current HTTPS/TLS failures.")
    if rows:
        lines += [
            "", "### Failure details", "",
            "| Hostname | State | Since | Observations | Last error | IPv4 | Stability | Samples |",
            "|---|---|---|---:|---|---|---:|---:|",
        ]
        for host, entry, kind in sorted(rows):
            ips = ", ".join(str(x) for x in entry.get("last_ipv4", [])) or "-"
            score = entry.get("stability_score")
            lines.append(
                f"| `{_esc(host)}` | {_esc(entry.get('status', 'unknown'))} | `{_esc(entry.get('failure_since') or '-')}` | "
                f"{int(entry.get('failure_observations', 0))} | {_esc(kind)} | {_esc(ips)} | "
                f"{score if score is not None else 'n/a'} | {int(entry.get('history_samples', 0))} |"
            )
    discovery_updated = discovery_state.get("updated_at") or "-"
    lines += [
        "", "## Discovery", "",
        f"Discovery state updated: `{_esc(discovery_updated)}`",
        "",
        "## Notes", "",
        f"- Public active DNS file: `{_esc(active_file)}`.",
        "- DNS lifecycle is time-based and does not depend on how many times per day the workflow runs.",
        "- HTTPS/TLS health is observational and never removes a hostname from the public DNS file.",
        "",
    ]
    return "\n".join(lines)


def write_report(name: str, active_file: str, paths: CollectionPaths, dns_state: dict[str, Any], service_state: dict[str, Any], discovery_state: dict[str, Any], now: datetime, dry_run: bool) -> str:
    report = render_report(name, active_file, dns_state, service_state, discovery_state, now)
    if not dry_run:
        atomic_write_text(paths.report, report)
        print(f"[{name}] report: {paths.report}")
    return report
