from __future__ import annotations

import argparse
import os
import re
import sys
from datetime import datetime, timezone
from urllib.parse import urlencode
from zoneinfo import ZoneInfo

from dns_maintenance import daily_summary as core

SUMMARY_HEADING_RE = re.compile(
    r"^## DNS Maintenance · (\d{4}-\d{2}-\d{2})\b",
    re.MULTILINE,
)


def body_has_summary_for_local_date(
    body: str,
    target_date: str,
    local_timezone: str,
) -> bool:
    """Return True when a comment represents a summary for target_date.

    Prefer the hidden snapshot timestamp. Fall back to the visible local-date
    heading so a damaged or missing snapshot cannot cause a scheduled duplicate.
    """
    tz = ZoneInfo(local_timezone)

    snapshot = core.extract_snapshot(body)
    if isinstance(snapshot, dict):
        created_at = core.parse_iso(str(snapshot.get("created_at") or ""))
        if created_at is not None:
            if created_at.astimezone(tz).date().isoformat() == target_date:
                return True

    return any(
        match.group(1) == target_date
        for match in SUMMARY_HEADING_RE.finditer(body)
    )


def issue_has_summary_for_local_date(
    client: core.GitHubClient,
    repository: str,
    issue_number: int,
    *,
    target_date: str,
    local_timezone: str,
) -> bool:
    page = 1
    while True:
        comments = client.api_json(
            f"/repos/{repository}/issues/{issue_number}/comments?"
            + urlencode({"per_page": 100, "page": page})
        )
        if not isinstance(comments, list):
            raise ValueError("GitHub issue comments response is not a list")

        for comment in comments:
            if not isinstance(comment, dict):
                continue
            if body_has_summary_for_local_date(
                str(comment.get("body") or ""),
                target_date,
                local_timezone,
            ):
                return True

        if len(comments) < 100:
            return False
        page += 1


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Scheduled wrapper for DNS-Maintenance daily summary"
    )
    parser.add_argument("--owner", required=True)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--timezone", default="Europe/Helsinki")
    parser.add_argument("--stale-after-hours", type=float, default=12.0)
    parser.add_argument("--mention", default="")
    parser.add_argument("--issue-title", default="DNS Maintenance — Daily Summary")
    parser.add_argument("--max-workers", type=int, default=12)
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument(
        "--skip-if-published-today",
        action="store_true",
        help="For scheduled runs, exit 0 if today's local-date summary already exists",
    )
    return parser.parse_args(argv)


def _forward_args(args: argparse.Namespace) -> list[str]:
    result = [
        "--owner",
        args.owner,
        "--repository",
        args.repository,
        "--timezone",
        args.timezone,
        "--stale-after-hours",
        str(args.stale_after_hours),
        "--issue-title",
        args.issue_title,
        "--max-workers",
        str(args.max_workers),
    ]
    if args.mention:
        result.extend(["--mention", args.mention])
    if args.dry_run:
        result.append("--dry-run")
    return result


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)

    if args.skip_if_published_today and not args.dry_run:
        token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
        client = core.GitHubClient(token)

        try:
            tz = ZoneInfo(args.timezone)
            now_utc = datetime.now(timezone.utc)
            target_date = now_utc.astimezone(tz).date().isoformat()

            issue = core.find_summary_issue(client, args.repository)
            if issue is not None:
                issue_number = int(issue["number"])
                if issue_has_summary_for_local_date(
                    client,
                    args.repository,
                    issue_number,
                    target_date=target_date,
                    local_timezone=args.timezone,
                ):
                    print(
                        f"Daily summary for {target_date} ({args.timezone}) already exists; "
                        "scheduled backup run skipped."
                    )
                    return 0
        except Exception as exc:
            # Fail closed: if deduplication cannot be verified, do not risk
            # publishing a duplicate. A later backup schedule can try again.
            print(
                "ERROR: could not verify daily-summary deduplication: "
                f"{type(exc).__name__}: {exc}",
                file=sys.stderr,
            )
            return 1

    return core.main(_forward_args(args))


if __name__ == "__main__":
    raise SystemExit(main())
