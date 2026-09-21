"""Optional authenticated log sender for a remote agent container.

Nothing imports or calls this module from the execution loop.  A future caller
may explicitly batch sanitized structured records and call ``send_logs``.
"""

from __future__ import annotations

import os
from typing import Any, Mapping, Sequence
from urllib.parse import urljoin

import requests

import tools.config  # Load .env without overriding Docker-injected settings.


def send_logs(
    entries: Sequence[Mapping[str, Any]],
    *,
    source: str = "incypher-agent",
    timeout: float = 10.0,
) -> int:
    """POST one bounded batch to the configured log portal and return its count."""
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
