from __future__ import annotations

import hashlib
import ipaddress
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable


ROOT = Path(__file__).resolve().parents[1]
CONFIG_DIR = ROOT / "config"
LOG_DIR = ROOT / "logs"
DASHBOARD_DIR = ROOT / "dashboards"
UPLOAD_DIR = LOG_DIR / "uploads"


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def ensure_dirs() -> None:
    for path in (CONFIG_DIR, LOG_DIR, DASHBOARD_DIR, UPLOAD_DIR):
        path.mkdir(parents=True, exist_ok=True)


def load_json(path: Path, default: Any) -> Any:
    if not path.exists():
        return default
    return json.loads(path.read_text(encoding="utf-8"))


def write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, sort_keys=True), encoding="utf-8")


def append_jsonl(path: Path, event: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(event, sort_keys=True) + "\n")


def iter_jsonl(path: Path) -> Iterable[dict[str, Any]]:
    if not path.exists():
        return
    with path.open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError:
                yield {
                    "timestamp": utc_now(),
                    "event_type": "parse_error",
                    "source": str(path),
                    "line_number": line_number,
                }


def sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def is_internal_ip(ip: str, cidrs: list[str]) -> bool:
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(address in ipaddress.ip_network(cidr) for cidr in cidrs)
