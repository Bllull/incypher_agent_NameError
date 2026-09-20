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


def request_json(
    session: requests.Session,
    base_url: str,
    method: str = "GET",
    path: str = "/",
    params: dict[str, Any] | None = None,
    json_body: dict[str, Any] | list[Any] | None = None,
    timeout: int = 15,
) -> dict[str, Any] | list[Any]:
    """Send a same-origin GET or POST and return its decoded JSON response."""
    method = method.upper()
    if method not in {"GET", "POST"}:
        raise ValueError("Only GET and POST are supported by the JSON workflow")
    if method == "GET" and json_body is not None:
        raise ValueError("GET JSON requests must use params instead of json_body")

    response = session.request(
        method,
        same_origin_url(base_url, path),
        params=params or None,
        json=json_body if method == "POST" else None,
        headers={"Accept": "application/json"},
        timeout=timeout,
        allow_redirects=True,
    )
    response.raise_for_status()
    try:
        payload = response.json()
    except requests.exceptions.JSONDecodeError as exc:
        raise ValueError("HTTP response did not contain valid JSON") from exc
    if not isinstance(payload, (dict, list)):
        raise ValueError("JSON response must be an object or array")
    return payload


def graphql_query(
    session: requests.Session,
    base_url: str,
    query: str,
    variables: dict[str, Any] | None = None,
    *,
    path: str = "/graphql",
    operation_name: str | None = None,
    timeout: int = 15,
) -> dict[str, Any]:
    """POST a GraphQL operation and return its complete JSON response."""
    if not isinstance(query, str) or not query.strip():
        raise ValueError("query must be a non-empty string")
    if variables is not None and not isinstance(variables, dict):
        raise TypeError("variables must be a dictionary or None")
    if operation_name is not None and (
        not isinstance(operation_name, str) or not operation_name.strip()
    ):
        raise ValueError("operation_name must be a non-empty string or None")

    body: dict[str, Any] = {
        "query": query,
        "variables": variables or {},
    }
    if operation_name is not None:
        body["operationName"] = operation_name

    payload = request_json(
        session,
        base_url,
        method="POST",
        path=path,
        json_body=body,
        timeout=timeout,
    )
    if not isinstance(payload, dict):
        raise ValueError("GraphQL response must be a JSON object")
    return payload
