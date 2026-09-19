"""HTML form discovery, submission, validation, and context helpers."""

from __future__ import annotations

import re
from html.parser import HTMLParser
from typing import Any
from urllib.parse import urljoin

import requests

from tools.http_client import create_session, interact_http
from tools.web_solve_tools.web_context import store_form_schema

_FLAG_PATTERN = re.compile(r"INCYPHER\{[^\r\n}]+\}")


class _FormParser(HTMLParser):
    """Extract the first usable HTML form without extra dependencies."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.forms: list[dict[str, Any]] = []
        self._form: dict[str, Any] | None = None
        self._select: dict[str, Any] | None = None
        self._textarea: dict[str, Any] | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attributes = {key.lower(): value or "" for key, value in attrs}
        tag = tag.lower()
        if tag == "form":
            self._form = {
                "action": attributes.get("action", ""),
                "method": attributes.get("method", "get").upper(),
                "fields": {},
            }
            self.forms.append(self._form)
            return
        if self._form is None:
            return
        if tag == "select":
            self._select = {"name": attributes.get("name", ""), "value": None, "first": None}
        elif tag == "option" and self._select is not None:
            value = attributes.get("value", "")
            self._select["first"] = self._select["first"] or value
            if "selected" in attributes:
                self._select["value"] = value
        elif tag == "textarea":
            self._textarea = {"name": attributes.get("name", ""), "text": []}
        elif tag == "input":
            name = attributes.get("name", "")
            input_type = attributes.get("type", "text").lower()
            if not name or input_type in {"submit", "button", "reset", "image", "file"}:
                return
            if input_type in {"checkbox", "radio"} and "checked" not in attributes:
                return
            self._form["fields"][name] = attributes.get("value", "")

    def handle_data(self, data: str) -> None:
        if self._textarea is not None:
            self._textarea["text"].append(data)

    def handle_endtag(self, tag: str) -> None:
        tag = tag.lower()
        if tag == "textarea" and self._textarea is not None and self._form is not None:
            if self._textarea["name"]:
                self._form["fields"][self._textarea["name"]] = "".join(self._textarea["text"])
            self._textarea = None
        elif tag == "select" and self._select is not None and self._form is not None:
            if self._select["name"]:
                self._form["fields"][self._select["name"]] = self._select["value"] or self._select["first"] or ""
            self._select = None
        elif tag == "form":
            self._form = None


def _validated_schema_from_context(context: dict[str, Any] | None) -> dict[str, Any] | None:
    """Return the most recently stored validated schema from context."""
    value = context.get("form_schema") if context else None
    return value if isinstance(value, dict) and isinstance(value.get("fields"), dict) else None


def get_form_json(
    challenge_url: str,
    context: dict[str, Any] | None = None,
    session: requests.Session | None = None,
    chal_ID: int | None = None,
) -> dict[str, Any]:
    """Discover and validate a form, prioritising validated context schemas."""
    cached = _validated_schema_from_context(context)
    if cached is not None:
        print(f"[web] Using cached validated form schema for {challenge_url}")
        return cached
    http = session or create_session()
    response = interact_http(http, challenge_url, method="GET")
    response.raise_for_status()
    parser = _FormParser()
    parser.feed(response.text)
    if not parser.forms:
        raise ValueError(f"No HTML form found at {challenge_url}")
    form = parser.forms[0]
    method = form["method"] if form["method"] in {"GET", "POST"} else "GET"
    action = urljoin(response.url, form["action"] or response.url)
    schema = {"url": action, "method": method, "fields": dict(form["fields"])}
    if not validate_form_json(schema, session=http):
        raise ValueError(f"Discovered form at {challenge_url} failed validation")
    if chal_ID is not None:
        print(f"[web] Caching validated form schema for {challenge_url}")
        store_form_schema(chal_ID, schema)
    return schema


def submit_form(
    form_schema: dict[str, Any],
    values: dict[str, Any] | list[dict[str, Any]] | None = None,
    session: requests.Session | None = None,
) -> requests.Response | list[requests.Response]:
    """Submit once or repeatedly, optionally overriding selected field values.

    A dictionary preserves the original single-submit behavior. A list sends
    one request per dictionary and returns the responses in the same order.
    The same session is reused so cookies and challenge state are preserved.
    """
    url = str(form_schema.get("url", ""))
    method = str(form_schema.get("method", "GET")).upper()
    schema_fields = form_schema.get("fields", {})
    if not url or not isinstance(schema_fields, dict):
        raise ValueError("form_schema must contain a URL and a fields object")
    if values is not None and not isinstance(values, (dict, list)):
        raise TypeError("values must be a dictionary or list of dictionaries")
    if isinstance(values, list) and not all(isinstance(item, dict) for item in values):
        raise TypeError("every repeated form value must be a dictionary")

    http = session or create_session()
    submissions = values if isinstance(values, list) else [values or {}]
    responses: list[requests.Response] = []
    for overrides in submissions:
        fields = {**schema_fields, **overrides}
        response = interact_http(
            http,
            url,
            method=method,
            params=fields if method == "GET" else None,
            data=fields if method == "POST" else None,
        )
        print(f"[web] form response: status={response.status_code} url={response.url}")
        responses.append(response)
    return responses if isinstance(values, list) else responses[0]


def _test_value(field_name: str, current: Any) -> str:
    """Choose a harmless deterministic value for an empty form field."""
    if current not in (None, ""):
        return str(current)
    name = field_name.lower()
    if "email" in name:
        return "ctf-test@example.com"
    if any(word in name for word in ("url", "uri", "link")):
        return "https://example.com"
    if any(word in name for word in ("num", "count", "age", "id")):
        return "1"
    return "test"


def validate_form_json(
    form_schema: dict[str, Any],
    session: requests.Session | None = None,
    test_variables: dict[str, Any] | None = None,
) -> bool:
    """Submit test variables and validate the response status."""
    fields = form_schema.get("fields")
    if not isinstance(fields, dict) or not fields:
        return False
    tested = {name: _test_value(name, value) for name, value in fields.items()}
    if test_variables:
        tested.update(test_variables)
    try:
        response = submit_form(form_schema, values=tested, session=session)
    except (requests.RequestException, ValueError) as exc:
        print(f"[web] form validation failed: {exc}")
        return False
    valid = 200 <= response.status_code < 400
    print(f"[web] form validation: {'passed' if valid else 'failed'}")
    return valid


def extract_flag(text: str) -> str | None:
    """Return an INCYPHER flag from a response body, if present."""
    match = _FLAG_PATTERN.search(text)
    return match.group(0) if match else None
