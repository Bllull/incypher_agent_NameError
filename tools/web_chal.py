"""HTTP form discovery and validation for URL-based CTF challenges."""

from __future__ import annotations

import json
import re
from html.parser import HTMLParser
from typing import Any
from urllib.parse import urljoin

import requests

from tools.context import append_context, get_chal_file_path, get_context
from tools.ctfd_api import get_challenge_url
from tools.http_client import create_session, interact_http


VALIDATED_FORM_HEADER = "[VALIDATED_WEB_FORM_SCHEMA]"
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


def _validated_schema_from_context(context: str | None) -> dict[str, Any] | None:
    """Return the most recently stored validated schema from context."""
    if not context or VALIDATED_FORM_HEADER not in context:
        return None
    tail = context.rsplit(VALIDATED_FORM_HEADER, 1)[1].lstrip(" :\r\n")
    try:
        value, _ = json.JSONDecoder().raw_decode(tail)
    except json.JSONDecodeError:
        return None
    return value if isinstance(value, dict) and isinstance(value.get("fields"), dict) else None


def get_form_json(
    challenge_url: str,
    context: str | None = None,
    session: requests.Session | None = None,
) -> dict[str, Any]:
    """Discover a form, prioritising a previously validated context schema."""
    cached = _validated_schema_from_context(context)
    if cached is not None:
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
    return {"url": action, "method": method, "fields": dict(form["fields"])}


def submit_form(form_schema: dict[str, Any], session: requests.Session | None = None) -> requests.Response:
    """Submit a form schema and return the complete HTTP response."""
    url = str(form_schema.get("url", ""))
    method = str(form_schema.get("method", "GET")).upper()
    fields = form_schema.get("fields", {})
    if not url or not isinstance(fields, dict):
        raise ValueError("form_schema must contain a URL and a fields object")
    response = interact_http(
        session or create_session(),
        url,
        method=method,
        params=fields if method == "GET" else None,
        data=fields if method == "POST" else None,
    )
    print(f"[web] form response: status={response.status_code} url={response.url}")
    print(response.text)
    return response


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
        response = submit_form({**form_schema, "fields": tested}, session=session)
    except (requests.RequestException, ValueError) as exc:
        print(f"[web] form validation failed: {exc}")
        return False
    valid = 200 <= response.status_code < 400
    print(f"[web] form validation: {'passed' if valid else 'failed'}")
    return valid


def append_validated_form_context(chal_ID: int, form_schema: dict[str, Any]) -> None:
    """Append a labelled validated schema for reuse on the next pass."""
    append_context(
        f"{VALIDATED_FORM_HEADER}\n{json.dumps(form_schema, sort_keys=True)}",
        chal_ID,
    )


def web_chal_solver(chal_ID: int) -> str | None:
    """Discover, test, and persist the first form for a web challenge."""
    context = get_context(chal_ID)
    print(f"[web] Challenge {chal_ID} context: {context!r}")
    print(f"[web] Challenge {chal_ID} file path: {get_chal_file_path(chal_ID)!r}")
    try:
        challenge_url = get_challenge_url(chal_ID)
        session = create_session()
        form_schema = get_form_json(challenge_url, context=context, session=session)
        print(f"[web] Form schema: {json.dumps(form_schema, sort_keys=True)}")
        if validate_form_json(form_schema, session=session):
            append_validated_form_context(chal_ID, form_schema)
            response = submit_form(form_schema, session=session)
            match = _FLAG_PATTERN.search(response.text)
            return match.group(0) if match else None
    except (requests.RequestException, ValueError, TypeError) as exc:
        print(f"[web] Challenge {chal_ID} form workflow failed: {exc}")
    return None   

# def main():
#     web_chal_solver(24)

# if __name__ == "__main__":
#     main()
