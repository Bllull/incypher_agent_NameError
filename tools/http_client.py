"""Small, same-origin HTTP helper for web CTF challenges."""

from __future__ import annotations

from typing import Any
from urllib.parse import urljoin, urlparse

import requests


def create_session() -> requests.Session:
    """Return a session that preserves cookies between challenge requests.

    ``trust_env`` is disabled so a stale local HTTP(S)_PROXY setting cannot
    redirect traffic away from an isolated challenge instance.
    """
    session = requests.Session()
    session.trust_env = False
    session.headers["User-Agent"] = "incypher-ctf-agent/1.0"
    return session


def same_origin_url(base_url: str, path: str) -> str:
    """Resolve a relative challenge path and reject requests to another host."""
    resolved = urljoin(base_url, path)
    base = urlparse(base_url)
    candidate = urlparse(resolved)
    if (candidate.scheme, candidate.netloc) != (base.scheme, base.netloc):
        raise ValueError("HTTP workflow only permits requests to the challenge origin")
    return resolved


def interact_http(
    session: requests.Session,
    base_url: str,
    method: str = "GET",
    path: str = "/",
    params: dict[str, Any] | None = None,
    data: dict[str, Any] | None = None,
    timeout: int = 15,
) -> requests.Response:
    """Send one bounded GET or form-encoded POST request to the target."""
    method = method.upper()
    if method not in {"GET", "POST"}:
        raise ValueError("Only GET and POST are supported by the HTTP workflow")

    return session.request(
        method,
        same_origin_url(base_url, path),
        params=params or None,
        data=data or None,
        timeout=timeout,
        allow_redirects=True,
    )
