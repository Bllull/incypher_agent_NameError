"""Pull unseen log-portal records and print them as JSON lines."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
from typing import Any
from urllib.parse import urljoin

import requests

import tools.config  # Load .env without overriding Docker-injected settings.


def _cursor_path() -> Path:
    configured = os.getenv("LOG_PORTAL_CURSOR_PATH")
    if configured:
        return Path(configured)
    work_root = Path(os.getenv("IN_CYPHER_WORK_DIR", "/work"))
    if work_root.is_dir() and os.access(work_root, os.W_OK):
        return work_root / "log_portal_cursor.json"
    return Path(__file__).resolve().parent.parent / ".agent_data" / "log_portal_cursor.json"


def _read_cursor(path: Path) -> int:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
        return max(0, int(value.get("after", 0))) if isinstance(value, dict) else 0
    except (OSError, ValueError, json.JSONDecodeError):
        return 0


def _write_cursor(path: Path, after: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"after": after}), encoding="utf-8")


def get_new_logs(*, after: int, limit: int = 100, timeout: float = 10.0) -> dict[str, Any]:
    """GET log records after one cursor from the configured authenticated portal."""
    base_url = os.getenv("LOG_PORTAL_URL", "").strip()
    token = os.getenv("LOG_PORTAL_TOKEN", "").strip()
    if not base_url or not token:
        raise RuntimeError("LOG_PORTAL_URL and LOG_PORTAL_TOKEN must be set")
    response = requests.get(
        urljoin(f"{base_url.rstrip('/')}/", "api/logs"),
        headers={"Authorization": f"Bearer {token}"},
        params={"after": after, "limit": limit},
        timeout=timeout,
    )
    response.raise_for_status()
    payload = response.json()
    if not isinstance(payload, dict) or not isinstance(payload.get("entries"), list):
        raise RuntimeError("log portal returned an invalid response")
    return payload


def main() -> int:
    parser = argparse.ArgumentParser(description="Print unseen remote-agent log records.")
    parser.add_argument("--after", type=int, help="Override the stored cursor")
    parser.add_argument("--limit", type=int, default=100)
    parser.add_argument("--no-advance", action="store_true", help="Do not save the returned cursor")
    arguments = parser.parse_args()
    cursor_path = _cursor_path()
    after = arguments.after if arguments.after is not None else _read_cursor(cursor_path)
    payload = get_new_logs(after=after, limit=arguments.limit)
    for entry in payload["entries"]:
        print(json.dumps(entry, sort_keys=True))
    next_after = payload.get("next_after")
    if not arguments.no_advance and isinstance(next_after, int):
        _write_cursor(cursor_path, next_after)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
