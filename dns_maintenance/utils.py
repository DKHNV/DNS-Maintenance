from __future__ import annotations

import copy
import ipaddress
import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import urlparse

HOST_LABEL_RE = re.compile(r"(?!-)[a-z0-9-]{1,63}(?<!-)$")


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def parse_iso(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)
    except (ValueError, TypeError):
        return None


def hours_between(start: datetime, end: datetime) -> float:
    return max(0.0, (end - start).total_seconds() / 3600.0)


def atomic_write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(text, encoding="utf-8", newline="\n")
    os.replace(tmp, path)


def load_json(path: Path, default: Any) -> Any:
    if not path.exists():
        return copy.deepcopy(default)
    return json.loads(path.read_text(encoding="utf-8"))


def save_json(path: Path, data: Any) -> None:
    atomic_write_text(path, json.dumps(data, ensure_ascii=False, indent=2, sort_keys=True) + "\n")


def normalize_hostname(raw: str) -> str | None:
    value = raw.strip()
    if not value or value.startswith("#"):
        return None
    value = re.split(r"\s+#", value, maxsplit=1)[0].strip()
    if not value:
        return None
    if "://" in value:
        value = urlparse(value).hostname or ""
    elif value.count(":") == 1:
        host_part, port_part = value.rsplit(":", 1)
        if port_part.isdigit():
            value = host_part
    value = value.rstrip(".").strip().lower()
    if value.startswith("*."):
        value = value[2:]
    if not value:
        return None
    try:
        ipaddress.ip_address(value)
        return None
    except ValueError:
        pass
    try:
        value = value.encode("idna").decode("ascii")
    except UnicodeError:
        return None
    if len(value) > 253:
        return None
    labels = value.split(".")
    if len(labels) < 2 or any(not HOST_LABEL_RE.fullmatch(label) for label in labels):
        return None
    return value


def read_host_file(path: Path) -> set[str]:
    if not path.exists():
        return set()
    result: set[str] = set()
    for line in path.read_text(encoding="utf-8").splitlines():
        host = normalize_hostname(line)
        if host:
            result.add(host)
    return result


def write_host_file(path: Path, hosts: Iterable[str]) -> None:
    atomic_write_text(path, "".join(f"{host}\n" for host in sorted(set(hosts))))


def safe_path(repo_root: Path, relative: str) -> Path:
    root = repo_root.resolve()
    path = (root / relative).resolve()
    try:
        path.relative_to(root)
    except ValueError as exc:
        raise ValueError(f"Path escapes repository root: {relative}") from exc
    return path


def is_within_root(host: str, root: str) -> bool:
    host = host.lower().rstrip(".")
    root = root.lower().rstrip(".")
    return host == root or host.endswith("." + root)
