"""Optional authenticated log sender for a remote agent container.

Nothing imports or calls this module from the execution loop.  A future caller
may explicitly batch sanitized structured records and call ``send_logs``.
"""

from __future__ import annotations

import os
import re
from queue import Full, Queue
from threading import Lock, Thread
from typing import Any, Mapping, Sequence
from urllib.parse import urljoin

import requests

import tools.config  # Load .env without overriding Docker-injected settings.


_LOG_QUEUE: Queue[tuple[dict[str, Any], str]] = Queue(maxsize=1_000)
_WORKER_LOCK = Lock()
_WORKER_STARTED = False


def _send_batch(
    entries: Sequence[Mapping[str, Any]],
    *,
    source: str = "incypher-agent",
    timeout: float = 10.0,
) -> int:
    """POST one bounded structured batch to the configured log portal."""
    base_url = os.getenv("LOG_PORTAL_URL", "").strip()
    token = os.getenv("LOG_PORTAL_TOKEN", "").strip()
    if not base_url or not token:
        raise RuntimeError("LOG_PORTAL_URL and LOG_PORTAL_TOKEN must be set")
    if not entries or len(entries) > 100:
        raise ValueError("entries must contain between 1 and 100 records")
    response = requests.post(
        urljoin(f"{base_url.rstrip('/')}/", "api/logs"),
        headers={"Authorization": f"Bearer {token}"},
        json={"source": source, "entries": [dict(entry) for entry in entries]},
        timeout=timeout,
    )
    response.raise_for_status()
    payload = response.json()
    accepted = payload.get("accepted")
    if not isinstance(accepted, int):
        raise RuntimeError("log portal returned no accepted count")
    return accepted


def _redact_log_message(message: str) -> str:
    """Remove common credential assignments before an operational log leaves the agent."""
    return re.sub(
        r"(?i)(\b(?:token|api[_-]?key|authorization)\b\s*(?:=|:)\s*)([^\s,}'\"]+)",
        r"\1[REDACTED]",
        message,
    )


def _log_worker() -> None:
    """Deliver queued operational logs without blocking solvers."""
    while True:
        entry, source = _LOG_QUEUE.get()
        try:
            _send_batch([entry], source=source, timeout=2.0)
        except Exception:
            # Operational logging is intentionally lossy rather than disruptive.
            pass
        finally:
            _LOG_QUEUE.task_done()


def _enqueue_log(entry: dict[str, Any], source: str) -> bool:
    """Queue one redacted operational record and start the single daemon worker."""
    global _WORKER_STARTED
    try:
        _LOG_QUEUE.put_nowait((entry, source))
    except Full:
        return False
    with _WORKER_LOCK:
        if not _WORKER_STARTED:
            Thread(target=_log_worker, name="log-portal-sender", daemon=True).start()
            _WORKER_STARTED = True
    return True


def send_logs(
    entries: Sequence[Mapping[str, Any]] | object,
    *additional: object,
    source: str = "incypher-agent",
    timeout: float = 10.0,
    sep: str = " ",
    end: str = "\n",
    file: object | None = None,
    flush: bool = False,
) -> int:
    """Send a structured batch or a print-style operational message.

    Passing a sequence of mappings uses the strict API and surfaces delivery
    failures to explicit callers. Print-style calls enqueue best-effort remote
    logging so a portal outage can never stop a local CTF solve loop. ``file``
    and ``flush`` are accepted for compatibility with ``print`` and have no
    local output effect.
    """
    is_batch = (
        not additional
        and isinstance(entries, Sequence)
        and not isinstance(entries, (str, bytes, bytearray))
        and all(isinstance(entry, Mapping) for entry in entries)
    )
    if is_batch:
        return _send_batch(entries, source=source, timeout=timeout)

    del file, flush
    message = sep.join(str(value) for value in (entries, *additional)) + end
    del timeout
    return int(_enqueue_log({"message": _redact_log_message(message.rstrip("\n"))}, source))
