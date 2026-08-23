from __future__ import annotations

from pathlib import Path
from typing import Any

from .config import collection_paths, collections_for, discovery_settings, dns_settings, hostname_policy_settings, service_settings
from .discovery import discover
from .dns_engine import maintain_dns
from .policy import apply_hostname_policy
from .report import write_report
from .service import probe_services
from .utils import utc_now


def run(repo_root: Path, cfg: dict[str, Any], selected: set[str] | None, dry_run: bool) -> int:
    now = utc_now()
    for collection in collections_for(cfg, selected):
        name = str(collection["name"])
        paths = collection_paths(repo_root, collection)
        discovery_cfg = discovery_settings(collection)
        candidates, discovery_state, _ = discover(name, paths, discovery_cfg, now, dry_run)
        dns_state, _ = maintain_dns(name, paths, dns_settings(cfg, collection), now, candidates, dry_run)
        policy_cfg = hostname_policy_settings(collection)
        dns_state, _ = apply_hostname_policy(name, paths, dns_state, policy_cfg, now, dry_run)
        service_cfg = service_settings(cfg, collection)
        service_state, _ = probe_services(name, paths, dns_state, service_cfg, now, dry_run)
        report = write_report(name, str(collection["active_file"]), paths, dns_state, service_state, discovery_state, now, dry_run)
        if dry_run:
            print(f"[{name}] DRY RUN report preview:\n{report[:2000]}")
    return 0
