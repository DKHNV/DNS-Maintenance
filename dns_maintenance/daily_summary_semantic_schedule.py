from __future__ import annotations

import re
from typing import Any

from dns_maintenance import daily_summary as core

DNS_FIELDS_WITH_EXCLUDED = (
    "active",
    "pending",
    "suspect",
    "quarantine",
    "excluded",
    "expired",
)

_ORIGINAL_RENDER_SUMMARY = core.render_summary


def _table_counts_compat(section: str, expected: tuple[str, ...]) -> dict[str, int]:
    """Parse report counters while treating Excluded as an additive optional field.

    Reports produced before hostname-policy support do not contain an Excluded row.
    They must continue to parse as excluded=0. Every other expected counter remains
    mandatory so malformed reports do not silently become healthy zeroes.
    """
    found: dict[str, int] = {}
    for raw_line in section.splitlines():
        line = raw_line.strip()
        match = re.fullmatch(r"\|\s*([^|]+?)\s*\|\s*(\d+)\s*\|", line)
        if not match:
            continue
        label = match.group(1).strip().lower()
        if label in {"state", "---"}:
            continue
        found[label] = int(match.group(2))

    missing = [name for name in expected if name not in found and name != "excluded"]
    if missing:
        raise ValueError("Missing report counters: " + ", ".join(missing))

    return {name: found.get(name, 0) for name in expected}


def _snapshot_services(snapshot: dict[str, Any] | None) -> dict[str, dict[str, Any]]:
    if not isinstance(snapshot, dict):
        return {}
    services = snapshot.get("services", {})
    return services if isinstance(services, dict) else {}


def _augment_summary_body_with_excluded(
    body: str,
    records: list[Any],
    previous_snapshot: dict[str, Any] | None,
    current_snapshot: dict[str, Any],
) -> str:
    """Add Excluded per-service and total deltas to the existing summary layout."""
    lines = body.splitlines()

    header = "| Service | Active | Pending | Suspect | Quarantine | HTTPS | Health |"
    separator = "|---|---:|---:|---:|---:|---|---|"
    try:
        header_index = lines.index(header)
    except ValueError as exc:
        raise ValueError("Daily summary service table layout changed") from exc

    if header_index + 1 >= len(lines) or lines[header_index + 1] != separator:
        raise ValueError("Daily summary service table separator changed")

    lines[header_index] = "| Service | Active | Pending | Suspect | Quarantine | Excluded | HTTPS | Health |"
    lines[header_index + 1] = "|---|---:|---:|---:|---:|---:|---|---|"

    previous_services = _snapshot_services(previous_snapshot)
    current_services = _snapshot_services(current_snapshot)

    row_index = header_index + 2
    for record in records:
        if row_index >= len(lines) or not lines[row_index].startswith("| "):
            raise ValueError("Daily summary service rows do not match collected records")

        line = lines[row_index]
        if not line.endswith(" |"):
            raise ValueError("Daily summary service row layout changed")
        cells = line[2:-2].split(" | ")
        if len(cells) != 7:
            raise ValueError("Daily summary service row column count changed")

        current = current_services.get(record.key, {})
        previous = previous_services.get(record.key)
        excluded_current = int(current.get("excluded", 0) or 0)
        excluded_previous = None if previous is None else int(previous.get("excluded", 0) or 0)
        cells.insert(5, core.format_delta(excluded_previous, excluded_current))
        lines[row_index] = "| " + " | ".join(cells) + " |"
        row_index += 1

    current_totals = core.totals_from_services(current_services)
    previous_totals = core.totals_from_services(previous_services) if previous_services else {}
    excluded_total = core.format_delta(
        previous_totals.get("excluded") if previous_services else None,
        int(current_totals.get("excluded", 0)),
    )

    try:
        stats_index = lines.index("### Общая статистика")
    except ValueError as exc:
        raise ValueError("Daily summary totals section is missing") from exc

    quarantine_index = next(
        (i for i in range(stats_index, len(lines)) if lines[i].startswith("| Quarantine |")),
        None,
    )
    if quarantine_index is None:
        raise ValueError("Daily summary Quarantine total row is missing")
    lines.insert(quarantine_index + 1, f"| Excluded | {excluded_total} |")

    return "\n".join(lines) + ("\n" if body.endswith("\n") else "")


def _render_summary_with_excluded(
    records: list[Any],
    previous_snapshot: dict[str, Any] | None,
    **kwargs: Any,
) -> tuple[str, dict[str, Any]]:
    body, snapshot = _ORIGINAL_RENDER_SUMMARY(records, previous_snapshot, **kwargs)
    return (
        _augment_summary_body_with_excluded(body, records, previous_snapshot, snapshot),
        snapshot,
    )


def _install() -> None:
    # Additive schema extension. Older reports/snapshots remain valid.
    core.DNS_FIELDS = DNS_FIELDS_WITH_EXCLUDED
    core._table_counts = _table_counts_compat
    core.render_summary = _render_summary_with_excluded


_install()

# Import only after patching the shared daily_summary module. The existing
# schedule wrapper then receives the extended core while retaining its proven
# same-local-date deduplication behavior.
from dns_maintenance import daily_summary_schedule as schedule  # noqa: E402


def main(argv: list[str] | None = None) -> int:
    return schedule.main(argv)


if __name__ == "__main__":
    raise SystemExit(main())
