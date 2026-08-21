from __future__ import annotations

import argparse
import concurrent.futures
import json
import os
import re
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlencode
from urllib.request import Request, urlopen
from zoneinfo import ZoneInfo

API_ROOT = "https://api.github.com"
RAW_ROOT = "https://raw.githubusercontent.com"
ISSUE_MARKER = "<!-- dns-maintenance-daily-summary-root -->"
SNAPSHOT_PREFIX = "<!-- dns-maintenance-snapshot:"
SNAPSHOT_SUFFIX = "-->"
SNAPSHOT_VERSION = 1

DNS_FIELDS = ("active", "pending", "suspect", "quarantine", "expired")
HTTPS_FIELDS = ("alive", "unknown", "suspect", "dead")


@dataclass(frozen=True)
class RepoInfo:
    full_name: str
    default_branch: str


@dataclass
class ServiceRecord:
    key: str
    repo: str
    collection: str
    report_url: str
    report_generated_at: str | None
    dns: dict[str, int]
    https: dict[str, int]
    error: str | None = None

    def snapshot(self) -> dict[str, Any]:
        return {
            "repo": self.repo,
            "collection": self.collection,
            "report_url": self.report_url,
            "report_generated_at": self.report_generated_at,
            **{field: int(self.dns.get(field, 0)) for field in DNS_FIELDS},
            **{f"https_{field}": int(self.https.get(field, 0)) for field in HTTPS_FIELDS},
            "error": self.error,
        }


class GitHubClient:
    def __init__(self, token: str | None, *, timeout: float = 30.0) -> None:
        self.token = (token or "").strip()
        self.timeout = timeout

    def _headers(self, *, github_api: bool = True) -> dict[str, str]:
        headers = {
            "User-Agent": "DKHNV-DNS-Maintenance-Daily-Summary/1.0",
            "Accept": "application/vnd.github+json" if github_api else "text/plain",
        }
        if github_api:
            headers["X-GitHub-Api-Version"] = "2022-11-28"
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        return headers

    def api_json(
        self,
        path: str,
        *,
        method: str = "GET",
        payload: dict[str, Any] | None = None,
    ) -> Any:
        url = path if path.startswith("https://") else API_ROOT + path
        data = None
        if payload is not None:
            data = json.dumps(payload).encode("utf-8")
        request = Request(url, data=data, method=method, headers=self._headers())
        if data is not None:
            request.add_header("Content-Type", "application/json")
        with urlopen(request, timeout=self.timeout) as response:
            return json.loads(response.read().decode("utf-8"))

    def raw_text(self, repo: RepoInfo, path: str) -> str | None:
        branch = quote(repo.default_branch, safe="")
        encoded_path = "/".join(quote(part, safe="") for part in path.split("/"))
        url = f"{RAW_ROOT}/{repo.full_name}/{branch}/{encoded_path}"
        request = Request(url, headers=self._headers(github_api=False))
        try:
            with urlopen(request, timeout=self.timeout) as response:
                return response.read().decode("utf-8")
        except HTTPError as exc:
            if exc.code == 404:
                return None
            raise

    def list_owner_repositories(self, owner: str) -> list[RepoInfo]:
        profile = self.api_json(f"/users/{quote(owner, safe='')}")
        owner_type = str(profile.get("type", "User"))
        if owner_type == "Organization":
            base = f"/orgs/{quote(owner, safe='')}/repos"
            params_base = {"type": "all", "sort": "full_name", "direction": "asc"}
        else:
            base = f"/users/{quote(owner, safe='')}/repos"
            params_base = {"type": "owner", "sort": "full_name", "direction": "asc"}

        repos: list[RepoInfo] = []
        page = 1
        while True:
            params = {**params_base, "per_page": 100, "page": page}
            payload = self.api_json(base + "?" + urlencode(params))
            if not isinstance(payload, list):
                raise ValueError("GitHub repositories response is not a list")
            for item in payload:
                if not isinstance(item, dict):
                    continue
                if item.get("archived") or item.get("disabled") or item.get("fork"):
                    continue
                full_name = str(item.get("full_name", "")).strip()
                default_branch = str(item.get("default_branch", "main")).strip() or "main"
                if full_name:
                    repos.append(RepoInfo(full_name=full_name, default_branch=default_branch))
            if len(payload) < 100:
                break
            page += 1
        return repos


def _section(markdown: str, heading: str) -> str:
    marker = f"## {heading}"
    start = markdown.find(marker)
    if start < 0:
        raise ValueError(f"Missing report section: {heading}")
    start += len(marker)
    next_heading = markdown.find("\n## ", start)
    return markdown[start:] if next_heading < 0 else markdown[start:next_heading]


def _table_counts(section: str, expected: tuple[str, ...]) -> dict[str, int]:
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
    missing = [name for name in expected if name not in found]
    if missing:
        raise ValueError("Missing report counters: " + ", ".join(missing))
    return {name: found[name] for name in expected}


def parse_report(markdown: str) -> tuple[str, dict[str, int], dict[str, int]]:
    match = re.search(r"Generated:\s*`([^`]+)`", markdown)
    if not match:
        raise ValueError("Missing report generation timestamp")
    generated_at = match.group(1).strip()

    dns = _table_counts(_section(markdown, "DNS lifecycle"), DNS_FIELDS)
    https = _table_counts(_section(markdown, "HTTPS/TLS observation"), HTTPS_FIELDS)
    return generated_at, dns, https


def _config_collections(config: dict[str, Any]) -> list[dict[str, str]]:
    if config.get("daily_summary", {}).get("enabled") is False:
        return []

    result: list[dict[str, str]] = []
    collections = config.get("collections", [])
    if not isinstance(collections, list):
        return result

    for collection in collections:
        if not isinstance(collection, dict):
            continue
        if collection.get("daily_summary", {}).get("enabled") is False:
            continue
        name = str(collection.get("name", "")).strip()
        data_dir = str(collection.get("data_dir", "")).strip().strip("/")
        if not name or not data_dir:
            continue
        result.append({"name": name, "data_dir": data_dir})
    return result


def discover_managed_collections(
    client: GitHubClient,
    owner: str,
    *,
    max_workers: int = 12,
) -> tuple[list[tuple[RepoInfo, dict[str, str]]], list[str]]:
    repos = client.list_owner_repositories(owner)
    managed: list[tuple[RepoInfo, dict[str, str]]] = []
    errors: list[str] = []

    def read_config(repo: RepoInfo) -> tuple[RepoInfo, list[dict[str, str]], str | None]:
        try:
            raw = client.raw_text(repo, "dns-maintenance-v1.json")
            if raw is None:
                return repo, [], None
            config = json.loads(raw)
            if not isinstance(config, dict):
                return repo, [], "config root is not an object"
            return repo, _config_collections(config), None
        except (HTTPError, URLError, TimeoutError, OSError, ValueError, json.JSONDecodeError) as exc:
            return repo, [], f"{type(exc).__name__}: {exc}"

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = [pool.submit(read_config, repo) for repo in repos]
        for future in concurrent.futures.as_completed(futures):
            repo, collections, error = future.result()
            if error:
                errors.append(f"{repo.full_name}: {error}")
                continue
            for collection in collections:
                managed.append((repo, collection))

    managed.sort(key=lambda item: (item[0].full_name.lower(), item[1]["name"].lower()))
    errors.sort()
    return managed, errors


def collect_records(
    client: GitHubClient,
    managed: list[tuple[RepoInfo, dict[str, str]]],
    *,
    max_workers: int = 12,
) -> tuple[list[ServiceRecord], list[str]]:
    records: list[ServiceRecord] = []
    errors: list[str] = []

    def read_report(repo: RepoInfo, collection: dict[str, str]) -> ServiceRecord:
        name = collection["name"]
        data_dir = collection["data_dir"]
        report_path = f"{data_dir}/report.md"
        report_url = f"https://github.com/{repo.full_name}/blob/{repo.default_branch}/{report_path}"
        key = f"{repo.full_name}#{name}"
        try:
            raw = client.raw_text(repo, report_path)
            if raw is None:
                return ServiceRecord(
                    key=key,
                    repo=repo.full_name,
                    collection=name,
                    report_url=report_url,
                    report_generated_at=None,
                    dns={field: 0 for field in DNS_FIELDS},
                    https={field: 0 for field in HTTPS_FIELDS},
                    error="report.md not found",
                )
            generated_at, dns, https = parse_report(raw)
            return ServiceRecord(
                key=key,
                repo=repo.full_name,
                collection=name,
                report_url=report_url,
                report_generated_at=generated_at,
                dns=dns,
                https=https,
            )
        except (HTTPError, URLError, TimeoutError, OSError, ValueError) as exc:
            return ServiceRecord(
                key=key,
                repo=repo.full_name,
                collection=name,
                report_url=report_url,
                report_generated_at=None,
                dns={field: 0 for field in DNS_FIELDS},
                https={field: 0 for field in HTTPS_FIELDS},
                error=f"{type(exc).__name__}: {exc}",
            )

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = [pool.submit(read_report, repo, collection) for repo, collection in managed]
        for future in concurrent.futures.as_completed(futures):
            record = future.result()
            records.append(record)
            if record.error:
                errors.append(f"{record.key}: {record.error}")

    records.sort(key=lambda x: (x.repo.lower(), x.collection.lower()))
    errors.sort()
    return records, errors


def parse_iso(value: str | None) -> datetime | None:
    if not value:
        return None
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def format_delta(previous: int | None, current: int) -> str:
    if previous is None:
        return f"— → **{current}**"
    delta = current - previous
    sign = "+" if delta > 0 else ""
    return f"{previous} → **{current}** ({sign}{delta})"


def _snapshot_services(snapshot: dict[str, Any] | None) -> dict[str, dict[str, Any]]:
    if not isinstance(snapshot, dict):
        return {}
    services = snapshot.get("services", {})
    return services if isinstance(services, dict) else {}


def classify_health(
    record: ServiceRecord,
    *,
    now_utc: datetime,
    stale_after_hours: float,
) -> tuple[str, str]:
    if record.error:
        return "❌", "report unavailable"

    generated = parse_iso(record.report_generated_at)
    if generated is None:
        return "❌", "invalid report time"

    age_hours = max((now_utc - generated).total_seconds() / 3600.0, 0.0)
    if age_hours > stale_after_hours:
        return "❌", f"stale {age_hours:.1f}h"
    if record.https.get("dead", 0) > 0:
        return "❌", f"HTTPS dead {record.https['dead']}"
    if (
        record.dns.get("suspect", 0) > 0
        or record.dns.get("quarantine", 0) > 0
        or record.https.get("suspect", 0) > 0
    ):
        details = []
        if record.dns.get("suspect", 0):
            details.append(f"DNS suspect {record.dns['suspect']}")
        if record.dns.get("quarantine", 0):
            details.append(f"quarantine {record.dns['quarantine']}")
        if record.https.get("suspect", 0):
            details.append(f"HTTPS suspect {record.https['suspect']}")
        return "⚠️", ", ".join(details)
    return "✅", f"current {age_hours:.1f}h"


def build_snapshot(records: list[ServiceRecord], *, created_at: str) -> dict[str, Any]:
    return {
        "version": SNAPSHOT_VERSION,
        "created_at": created_at,
        "services": {record.key: record.snapshot() for record in records},
    }


def totals_from_services(services: dict[str, dict[str, Any]]) -> dict[str, int]:
    fields = list(DNS_FIELDS) + [f"https_{field}" for field in HTTPS_FIELDS]
    return {
        field: sum(int(service.get(field, 0) or 0) for service in services.values())
        for field in fields
    }


def _escape_cell(value: str) -> str:
    return value.replace("|", r"\|").replace("\n", " ")


def render_summary(
    records: list[ServiceRecord],
    previous_snapshot: dict[str, Any] | None,
    *,
    now_utc: datetime,
    local_timezone: str,
    stale_after_hours: float,
    mention: str | None,
    discovery_errors: list[str] | None = None,
) -> tuple[str, dict[str, Any]]:
    tz = ZoneInfo(local_timezone)
    now_local = now_utc.astimezone(tz)
    current_snapshot = build_snapshot(records, created_at=now_utc.isoformat().replace("+00:00", "Z"))
    current_services = _snapshot_services(current_snapshot)
    previous_services = _snapshot_services(previous_snapshot)

    lines: list[str] = []
    if mention:
        lines.append(f"@{mention}")
        lines.append("")

    lines.append(f"## DNS Maintenance · {now_local:%Y-%m-%d %H:%M %Z}")
    lines.append("")
    lines.append("Период сравнения: с предыдущей суточной сводки.")
    lines.append("")
    lines.append("| Service | Active | Pending | Suspect | Quarantine | HTTPS | Health |")
    lines.append("|---|---:|---:|---:|---:|---|---|")

    health_notes: list[str] = []
    for record in records:
        current = current_services[record.key]
        previous = previous_services.get(record.key)
        status_icon, status_text = classify_health(
            record,
            now_utc=now_utc,
            stale_after_hours=stale_after_hours,
        )
        label = record.repo.split("/", 1)[-1]
        if sum(1 for item in records if item.repo == record.repo) > 1:
            label += f":{record.collection}"
        service_link = f"[{_escape_cell(label)}]({record.report_url})"

        https_text = (
            f"{record.https.get('alive', 0)} alive · "
            f"{record.https.get('unknown', 0)} unknown · "
            f"{record.https.get('suspect', 0)} suspect · "
            f"{record.https.get('dead', 0)} dead"
        )
        lines.append(
            "| "
            + " | ".join(
                [
                    service_link,
                    format_delta(None if previous is None else int(previous.get("active", 0)), int(current["active"])),
                    format_delta(None if previous is None else int(previous.get("pending", 0)), int(current["pending"])),
                    format_delta(None if previous is None else int(previous.get("suspect", 0)), int(current["suspect"])),
                    format_delta(None if previous is None else int(previous.get("quarantine", 0)), int(current["quarantine"])),
                    _escape_cell(https_text),
                    f"{status_icon} {_escape_cell(status_text)}",
                ]
            )
            + " |"
        )
        if status_icon != "✅":
            health_notes.append(f"{status_icon} `{record.repo}#{record.collection}`: {status_text}")

    current_totals = totals_from_services(current_services)
    previous_totals = totals_from_services(previous_services) if previous_services else {}

    lines.append("")
    lines.append("### Общая статистика")
    lines.append("")
    lines.append("| Metric | Previous → Current |")
    lines.append("|---|---:|")
    for label, field in [
        ("Active", "active"),
        ("Pending", "pending"),
        ("Suspect", "suspect"),
        ("Quarantine", "quarantine"),
        ("Expired", "expired"),
    ]:
        lines.append(
            f"| {label} | {format_delta(previous_totals.get(field) if previous_services else None, current_totals[field])} |"
        )

    current_keys = set(current_services)
    previous_keys = set(previous_services)
    new_keys = sorted(current_keys - previous_keys)
    removed_keys = sorted(previous_keys - current_keys)

    notes: list[str] = []
    if previous_services:
        if new_keys:
            notes.append("🆕 Новые коллекции: " + ", ".join(f"`{key}`" for key in new_keys))
        if removed_keys:
            notes.append("⚠️ Исчезли из discovery: " + ", ".join(f"`{key}`" for key in removed_keys))
    else:
        notes.append("ℹ️ Это первый snapshot. Дельты появятся в следующей сводке.")

    notes.extend(health_notes)
    for error in discovery_errors or []:
        notes.append(f"⚠️ discovery: `{_escape_cell(error)}`")

    lines.append("")
    lines.append("### Состояние")
    lines.append("")
    if notes:
        lines.extend(f"- {note}" for note in notes)
    else:
        lines.append("- ✅ Все обнаруженные коллекции выглядят штатно.")

    lines.append("")
    lines.append(
        f"Обнаружено коллекций: **{len(records)}**. "
        f"Порог stale: **{stale_after_hours:g} ч**. "
        "HTTPS `unknown` сам по себе не считается аварией."
    )
    lines.append("")
    compact_snapshot = json.dumps(current_snapshot, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
    lines.append(f"{SNAPSHOT_PREFIX}{compact_snapshot}{SNAPSHOT_SUFFIX}")

    return "\n".join(lines) + "\n", current_snapshot


def extract_snapshot(text: str) -> dict[str, Any] | None:
    start = text.rfind(SNAPSHOT_PREFIX)
    if start < 0:
        return None
    start += len(SNAPSHOT_PREFIX)
    end = text.find(SNAPSHOT_SUFFIX, start)
    if end < 0:
        return None
    try:
        value = json.loads(text[start:end])
    except json.JSONDecodeError:
        return None
    if not isinstance(value, dict):
        return None
    return value


def find_summary_issue(client: GitHubClient, repository: str) -> dict[str, Any] | None:
    page = 1
    while True:
        issues = client.api_json(
            f"/repos/{repository}/issues?" + urlencode({"state": "open", "per_page": 100, "page": page})
        )
        if not isinstance(issues, list):
            return None
        for issue in issues:
            if not isinstance(issue, dict) or "pull_request" in issue:
                continue
            body = str(issue.get("body") or "")
            if ISSUE_MARKER in body:
                return issue
        if len(issues) < 100:
            return None
        page += 1


def ensure_summary_issue(client: GitHubClient, repository: str, title: str) -> dict[str, Any]:
    issue = find_summary_issue(client, repository)
    if issue is not None:
        return issue
    body = (
        f"{ISSUE_MARKER}\n\n"
        "Ежедневная автоматическая сводка DNS-Maintenance. "
        "Каждый комментарий содержит текущее состояние всех автоматически обнаруженных коллекций "
        "и сравнение с предыдущей сводкой.\n"
    )
    created = client.api_json(
        f"/repos/{repository}/issues",
        method="POST",
        payload={"title": title, "body": body},
    )
    if not isinstance(created, dict):
        raise ValueError("GitHub did not return the created issue")
    return created


def latest_snapshot_from_issue(
    client: GitHubClient,
    repository: str,
    issue_number: int,
) -> dict[str, Any] | None:
    latest: dict[str, Any] | None = None
    page = 1
    while True:
        comments = client.api_json(
            f"/repos/{repository}/issues/{issue_number}/comments?"
            + urlencode({"per_page": 100, "page": page})
        )
        if not isinstance(comments, list):
            break
        for comment in comments:
            if not isinstance(comment, dict):
                continue
            snapshot = extract_snapshot(str(comment.get("body") or ""))
            if snapshot is not None:
                latest = snapshot
        if len(comments) < 100:
            break
        page += 1
    return latest


def publish_comment(
    client: GitHubClient,
    repository: str,
    issue_number: int,
    body: str,
) -> None:
    client.api_json(
        f"/repos/{repository}/issues/{issue_number}/comments",
        method="POST",
        payload={"body": body},
    )


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Build and publish a daily DNS-Maintenance summary")
    parser.add_argument("--owner", required=True, help="GitHub user or organization whose repositories are scanned")
    parser.add_argument("--repository", required=True, help="Repository where the summary issue is stored, owner/name")
    parser.add_argument("--timezone", default="Europe/Helsinki")
    parser.add_argument("--stale-after-hours", type=float, default=12.0)
    parser.add_argument("--mention", default="")
    parser.add_argument("--issue-title", default="DNS Maintenance — Daily Summary")
    parser.add_argument("--max-workers", type=int, default=12)
    parser.add_argument("--dry-run", action="store_true", help="Print the report but do not create an issue/comment")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    if args.stale_after_hours <= 0:
        raise SystemExit("--stale-after-hours must be > 0")
    if not 1 <= args.max_workers <= 64:
        raise SystemExit("--max-workers must be 1..64")

    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    client = GitHubClient(token)

    try:
        managed, discovery_errors = discover_managed_collections(
            client,
            args.owner,
            max_workers=args.max_workers,
        )
        records, report_errors = collect_records(
            client,
            managed,
            max_workers=args.max_workers,
        )
        discovery_errors.extend(report_errors)

        previous_snapshot = None
        issue = find_summary_issue(client, args.repository)
        if issue is not None:
            previous_snapshot = latest_snapshot_from_issue(
                client,
                args.repository,
                int(issue["number"]),
            )

        now_utc = datetime.now(timezone.utc)
        body, _ = render_summary(
            records,
            previous_snapshot,
            now_utc=now_utc,
            local_timezone=args.timezone,
            stale_after_hours=args.stale_after_hours,
            mention=args.mention.strip() or None,
            discovery_errors=discovery_errors,
        )

        if args.dry_run:
            print(body)
            return 0

        if not token:
            raise RuntimeError("GITHUB_TOKEN or GH_TOKEN is required for publishing")

        issue = issue or ensure_summary_issue(client, args.repository, args.issue_title)
        publish_comment(client, args.repository, int(issue["number"]), body)
        print(f"Published daily summary to issue #{issue['number']}: {issue.get('html_url', '')}")
        print(f"Collections: {len(records)}")
        return 0

    except (HTTPError, URLError, TimeoutError, OSError, ValueError, RuntimeError) as exc:
        print(f"ERROR: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
