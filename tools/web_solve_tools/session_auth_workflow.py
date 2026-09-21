"""Evidence-gated HTTP helpers for session-bound authorization CTF challenges."""

from __future__ import annotations

from html.parser import HTMLParser
from typing import Any
from urllib.parse import urlsplit

import requests

from tools.http_client import interact_http, same_origin_url


MAX_RANGE_PROBE_SIZE = 100
MAX_RESPONSE_TEXT_CHARS = 4000
MAX_INITIAL_DISCOVERY_REQUESTS = 3
INITIAL_DISCOVERY_TIMEOUT = 5
_INITIAL_ROUTE_HINTS = ("login", "dashboard", "account", "profile")


class _RouteParser(HTMLParser):
    """Collect same-origin links and form actions exposed by an HTML page."""

    def __init__(self, base_url: str) -> None:
        super().__init__(convert_charrefs=True)
        self._base_url = base_url
        self.routes: set[str] = set()

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attribute_map = dict(attrs)
        attribute_name = "action" if tag.lower() == "form" else "href"
        value = attribute_map.get(attribute_name)
        if not value:
            return
        try:
            resolved = same_origin_url(self._base_url, value)
        except ValueError:
            return
        parsed = urlsplit(resolved)
        self.routes.add(parsed.path or "/")


def discover_session_surface(
    session: requests.Session,
    challenge_url: str,
) -> tuple[dict[str, Any], list[requests.Response]]:
    """Collect a bounded passive auth surface without exposing cookie values.

    The discovery budget is one landing-page request and at most two static,
    linked authentication-related routes. It deliberately does not invent
    paths, follow logout links, or probe identifier-bearing routes.
    """
    landing_response = interact_http(
        session,
        challenge_url,
        method="GET",
        path="",
        timeout=INITIAL_DISCOVERY_TIMEOUT,
    )
    landing_response.raise_for_status()
    parser = _RouteParser(landing_response.url)
    parser.feed(landing_response.text)
    candidate_routes = [
        route
        for route in parser.routes
        if route != "/"
        and "{" not in route
        and "<" not in route
        and any(hint in route.lower() for hint in _INITIAL_ROUTE_HINTS)
    ]
    candidate_routes.sort(
        key=lambda route: next(
            index
            for index, hint in enumerate(_INITIAL_ROUTE_HINTS)
            if hint in route.lower()
        )
    )
    candidate_routes = candidate_routes[: MAX_INITIAL_DISCOVERY_REQUESTS - 1]
    responses = [landing_response]
    route_probes: list[dict[str, Any]] = []
    for route in candidate_routes:
        response = interact_http(
            session,
            challenge_url,
            method="GET",
            path=route,
            timeout=INITIAL_DISCOVERY_TIMEOUT,
        )
        responses.append(response)
        route_probes.append(
            {
                "path": route,
                "status_code": response.status_code,
                "url": response.url,
                "body_excerpt": response.text[:MAX_RESPONSE_TEXT_CHARS],
            }
        )
    cookies = [
        {
            "name": cookie.name,
            "domain": cookie.domain,
            "path": cookie.path,
            "secure": cookie.secure,
            "expires": cookie.expires,
            "has_http_only": "HttpOnly" in cookie._rest,
            "same_site": cookie._rest.get("SameSite"),
        }
        for cookie in session.cookies
    ]
    return (
        {
            "landing_url": landing_response.url,
            "status_code": landing_response.status_code,
            "routes": sorted(parser.routes),
            "route_probes": route_probes,
            "cookies": cookies,
            "body_excerpt": landing_response.text[:MAX_RESPONSE_TEXT_CHARS],
        },
        responses,
    )


def validate_session_action(action: dict[str, Any]) -> dict[str, Any]:
    """Validate one LLM-proposed same-origin request or bounded range probe."""
    kind = action.get("kind", "request")
    purpose = action.get("purpose")
    if kind not in {"request", "range_probe"}:
        raise ValueError("session action kind must be request or range_probe")
    if not isinstance(purpose, str) or not purpose.strip():
        raise ValueError("session action purpose must be a non-empty string")

    if kind == "request":
        method = action.get("method", "GET")
        path = action.get("path")
        params = action.get("params", {})
        data = action.get("data", {})
        if method not in {"GET", "POST"}:
            raise ValueError("session request method must be GET or POST")
        if not isinstance(path, str) or not path.startswith("/"):
            raise ValueError("session request path must be an absolute same-origin path")
        parsed = urlsplit(path)
        if parsed.scheme or parsed.netloc:
            raise ValueError("session request path must not contain an origin")
        if not isinstance(params, dict) or not isinstance(data, dict):
            raise ValueError("session request params and data must be objects")
        return {
            "kind": kind,
            "method": method,
            "path": path,
            "params": params,
            "data": data,
            "purpose": purpose,
        }

    path_template = action.get("path_template")
    start = action.get("start")
    end = action.get("end")
    stop_status = action.get("stop_status", 200)
    if not isinstance(path_template, str) or not path_template.startswith("/"):
        raise ValueError("range probe path_template must be an absolute same-origin path")
    if "{value}" not in path_template or urlsplit(path_template).scheme or urlsplit(path_template).netloc:
        raise ValueError("range probe path_template must contain {value} and no origin")
    if isinstance(start, bool) or isinstance(end, bool) or not isinstance(start, int) or not isinstance(end, int):
        raise ValueError("range probe start and end must be integers")
    if end < start or end - start + 1 > MAX_RANGE_PROBE_SIZE:
        raise ValueError(f"range probe must contain 1 to {MAX_RANGE_PROBE_SIZE} values")
    if isinstance(stop_status, bool) or not isinstance(stop_status, int) or not 100 <= stop_status <= 599:
        raise ValueError("range probe stop_status must be an HTTP status code")
    return {
        "kind": kind,
        "path_template": path_template,
        "start": start,
        "end": end,
        "stop_status": stop_status,
        "purpose": purpose,
    }


def run_session_actions(
    session: requests.Session,
    challenge_url: str,
    actions: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], list[requests.Response]]:
    """Run validated actions and return compact records plus raw responses."""
    records: list[dict[str, Any]] = []
    responses: list[requests.Response] = []
    for raw_action in actions:
        action = validate_session_action(raw_action)
        if action["kind"] == "request":
            method = str(action["method"])
            response = interact_http(
                session,
                challenge_url,
                method=method,
                path=str(action["path"]),
                params=action["params"] if method == "GET" else None,
                data=action["data"] if method == "POST" else None,
            )
            responses.append(response)
            records.append(
                {
                    "action": action,
                    "status_code": response.status_code,
                    "url": response.url,
                    "text": response.text[:MAX_RESPONSE_TEXT_CHARS],
                }
            )
            continue

        matched: requests.Response | None = None
        attempts = 0
        for value in range(int(action["start"]), int(action["end"]) + 1):
            response = interact_http(
                session,
                challenge_url,
                method="GET",
                path=str(action["path_template"]).replace("{value}", str(value)),
            )
            attempts += 1
            if response.status_code == action["stop_status"]:
                matched = response
                responses.append(response)
                break
        records.append(
            {
                "action": action,
                "attempts": attempts,
                "matched": matched is not None,
                "status_code": matched.status_code if matched else None,
                "url": matched.url if matched else None,
                "text": matched.text[:MAX_RESPONSE_TEXT_CHARS] if matched else "",
            }
        )
    return records, responses
