from __future__ import annotations

import json
import os
import sys
from datetime import datetime
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

from .config import CollectionPaths
from .utils import is_within_root, iso, load_json, normalize_hostname, save_json

DISCOVERY_STATE_VERSION = 2
CERTSPOTTER_URL = "https://api.certspotter.com/v1/issuances"


def fetch_certspotter_page(root: str, after: int | None, timeout: float, user_agent: str) -> tuple[list[dict[str, Any]], int | None]:
    params = [("domain", root), ("include_subdomains", "true"), ("expand", "dns_names")]
    if after is not None:
        params.append(("after", str(after)))
    request = Request(CERTSPOTTER_URL + "?" + urlencode(params), headers={"Accept": "application/json", "User-Agent": user_agent})
    api_key = os.environ.get("CERTSPOTTER_API_KEY", "").strip()
    if api_key:
        request.add_header("Authorization", f"Bearer {api_key}")
    with urlopen(request, timeout=timeout) as response:
        payload = json.loads(response.read().decode("utf-8"))
    if not isinstance(payload, list):
        raise ValueError("Cert Spotter returned non-array JSON")
    page = [x for x in payload if isinstance(x, dict)]
    next_after = after
    if page and page[-1].get("id") is not None:
        next_after = int(page[-1]["id"])
    return page, next_after


def extract_candidates(page: list[dict[str, Any]], root: str) -> set[str]:
    result: set[str] = set()
    for issuance in page:
        names = issuance.get("dns_names", [])
        if not isinstance(names, list):
            continue
        for raw in names:
            if not isinstance(raw, str) or raw.strip().startswith("*."):
                continue
            host = normalize_hostname(raw)
            if host and is_within_root(host, root):
                result.add(host)
    return result


def normalize_discovery_state(state: dict[str, Any]) -> dict[str, Any]:
    version = int(state.get("version", 1))
    if version not in {1, 2}:
        raise ValueError(f"Unsupported discovery state version: {version}")
    # Current Telegram v1 used sources.certspotter.<root>. Keep it directly
    # compatible while upgrading only the top-level state version.
    state.setdefault("sources", {}).setdefault("certspotter", {})
    state["version"] = DISCOVERY_STATE_VERSION
    return state


def discover(name: str, paths: CollectionPaths, cfg: dict[str, Any], now: datetime, dry_run: bool) -> tuple[dict[str, set[str]], dict[str, Any], dict[str, int]]:
    if not cfg.get("enabled", False):
        print(f"[{name}] discovery disabled")
        return {}, load_json(paths.discovery_state, {"version": 2, "sources": {"certspotter": {}}}), {"candidates": 0, "new": 0, "requests": 0, "errors": 0}

    state = load_json(paths.discovery_state, {"version": 2, "updated_at": None, "sources": {"certspotter": {}}})
    if not isinstance(state, dict):
        raise ValueError(f"[{name}] invalid discovery state")
    state = normalize_discovery_state(state)
    result: dict[str, set[str]] = {}
    requests = errors = 0

    for source in cfg.get("sources", []):
        source_id = str(source.get("id", "certspotter"))
        timeout = float(source.get("request_timeout_seconds", 30.0))
        max_pages = int(source.get("max_pages_per_root", 5))
        user_agent = str(source.get("user_agent", "DKHNV-DNS-Maintenance/1.0"))
        if not 1 <= max_pages <= 100:
            raise ValueError("max_pages_per_root must be 1..100")
        for raw_root in sorted(set(source.get("roots", []))):
            root = normalize_hostname(str(raw_root))
            assert root is not None
            root_state = state["sources"]["certspotter"].setdefault(root, {"after": None, "caught_up": False, "last_poll": None})
            after = int(root_state["after"]) if root_state.get("after") is not None else None
            found: set[str] = set()
            caught_up = False
            for _ in range(max_pages):
                try:
                    page, next_after = fetch_certspotter_page(root, after, timeout, user_agent)
                    requests += 1
                except HTTPError as exc:
                    errors += 1
                    print(f"WARN [{name}] Cert Spotter {root}: HTTP {exc.code}", file=sys.stderr)
                    break
                except (URLError, TimeoutError, OSError, ValueError, json.JSONDecodeError) as exc:
                    errors += 1
                    print(f"WARN [{name}] Cert Spotter {root}: {type(exc).__name__}: {exc}", file=sys.stderr)
                    break
                if not page:
                    caught_up = True
                    break
                found.update(extract_candidates(page, root))
                if next_after == after:
                    break
                after = next_after
            for host in found:
                result.setdefault(host, set()).add(f"{source_id}:{root}")
            root_state.update({"after": after, "caught_up": caught_up, "last_poll": iso(now)})
            print(f"[{name}] discovery {source_id}:{root}: {len(found)} candidate(s), {'caught up' if caught_up else 'batch limited'}")

    state["updated_at"] = iso(now)
    if not dry_run:
        save_json(paths.discovery_state, state)
    print(f"[{name}] discovery: candidates={len(result)} requests={requests} errors={errors}")
    return result, state, {"candidates": len(result), "new": len(result), "requests": requests, "errors": errors}
