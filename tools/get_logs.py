"""Continuously display unseen log-portal records in a terminal-friendly table."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import time
from typing import Any
from urllib.parse import urljoin

import requests

import tools.config  # Load .env without overriding Docker-injected settings.


_TABLE_HEADER = "TIME                             | ID       | SOURCE                   | MESSAGE"
_TABLE_RULE = "---------------------------------+----------+--------------------------+--------"
_TIME_WIDTH = 32
_ID_WIDTH = 8
_SOURCE_WIDTH = 24


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


def format_log_entry(record: Any) -> str:
    """Render one portal record as a readable row with stable metadata columns."""
    if not isinstance(record, dict):
        return f"{'?':<{_TIME_WIDTH}} | {'?':>{_ID_WIDTH}} | {'unknown':<{_SOURCE_WIDTH}} | {record!r}"

    received_at = str(record.get("received_at", "unknown"))
    record_id = str(record.get("id", "?"))
    source = str(record.get("source", "unknown"))
    payload = record.get("entry")
    if isinstance(payload, dict) and isinstance(payload.get("message"), str):
        message = payload["message"]
        remaining = {key: value for key, value in payload.items() if key != "message"}
        if remaining:
            # Keep the human-oriented message first, without discarding the
            # structured fields that often carry solver evidence and context.
            message = f"{message} | {json.dumps(remaining, sort_keys=True, default=str)}"
    elif isinstance(payload, str):
        message = payload
    else:
        message = json.dumps(payload, sort_keys=True, default=str)

    prefix = (
        f"{received_at:<{_TIME_WIDTH}} | {record_id:>{_ID_WIDTH}} | "
        f"{source:<{_SOURCE_WIDTH}} | "
    )
    continuation = " " * len(prefix)
    return prefix + message.replace("\n", f"\n{continuation}")


def listen_for_logs(
    *,
    after: int,
    cursor_path: Path,
    limit: int = 100,
    interval: float = 2.0,
    advance_cursor: bool = True,
    once: bool = False,
) -> int:
    """Poll forever for new records, retaining the cursor after each response.

    Transient network and server errors are reported locally and retried after
    ``interval`` seconds. A malformed configuration remains a startup error in
    ``main`` rather than an endless retry loop.
    """
    current_after = after
    while True:
        try:
            payload = get_new_logs(after=current_after, limit=limit)
            entries = payload["entries"]
            if entries:
                print(_TABLE_HEADER, flush=True)
                print(_TABLE_RULE, flush=True)
                for entry in entries:
                    print(format_log_entry(entry), flush=True)
            next_after = payload.get("next_after")
            if isinstance(next_after, int):
                current_after = max(current_after, next_after)
                if advance_cursor:
                    _write_cursor(cursor_path, current_after)
        except requests.RequestException as exc:
            print(f"[log-listener] request failed; retrying: {exc}", flush=True)
        except (RuntimeError, ValueError, OSError) as exc:
            print(f"[log-listener] invalid portal response; retrying: {exc}", flush=True)

        if once:
            return 0
        time.sleep(interval)


def main() -> int:
    parser = argparse.ArgumentParser(description="Continuously print unseen remote-agent log records.")
    parser.add_argument("--after", type=int, help="Override the stored cursor")
    parser.add_argument("--limit", type=int, default=100)
    parser.add_argument("--no-advance", action="store_true", help="Do not save the returned cursor")
    parser.add_argument(
        "--interval",
        type=float,
        default=float(os.getenv("LOG_PORTAL_POLL_INTERVAL", "2")),
        help="Seconds between polls (default: LOG_PORTAL_POLL_INTERVAL or 2)",
    )
    parser.add_argument("--once", action="store_true", help="Fetch once instead of listening continuously")
    arguments = parser.parse_args()
    if arguments.limit < 1 or arguments.limit > 100:
        parser.error("--limit must be between 1 and 100")
    if arguments.interval <= 0:
        parser.error("--interval must be positive")

    cursor_path = _cursor_path()
    after = arguments.after if arguments.after is not None else _read_cursor(cursor_path)
    # Validate credentials before entering the retry loop, so a typo does not
    # look like a transient portal outage.
    if not os.getenv("LOG_PORTAL_URL", "").strip() or not os.getenv("LOG_PORTAL_TOKEN", "").strip():
        parser.error("LOG_PORTAL_URL and LOG_PORTAL_TOKEN must be set")
    try:
        return listen_for_logs(
            after=after,
            cursor_path=cursor_path,
            limit=arguments.limit,
            interval=arguments.interval,
            advance_cursor=not arguments.no_advance,
            once=arguments.once,
        )
    except KeyboardInterrupt:
        print("\n[log-listener] stopped.")
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
