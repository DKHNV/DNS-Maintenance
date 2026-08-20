from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .config import collection_paths, collections_for, load_config
from .runner import run


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Universal DNS maintenance engine")
    p.add_argument("--repo-root", default=".")
    p.add_argument("--config", default="dns-maintenance.json")
    p.add_argument("--collection", action="append")
    p.add_argument("--dry-run", action="store_true")
    p.add_argument("--managed-paths", action="store_true", help="Print managed git paths separated by NUL and exit")
    return p


def main() -> int:
    args = parser().parse_args()
    repo_root = Path(args.repo_root).resolve()
    config_path = (repo_root / args.config).resolve()
    try:
        config_path.relative_to(repo_root)
        cfg = load_config(config_path)
        selected = set(args.collection or []) or None
        if args.managed_paths:
            paths: list[str] = []
            for collection in collections_for(cfg, selected):
                cp = collection_paths(repo_root, collection)
                paths.extend([str(cp.active.relative_to(repo_root)), str(cp.data_dir.relative_to(repo_root))])
            sys.stdout.buffer.write(b"\0".join(x.encode() for x in sorted(set(paths))) + b"\0")
            return 0
        return run(repo_root, cfg, selected, args.dry_run)
    except (ValueError, KeyError, json.JSONDecodeError, OSError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
