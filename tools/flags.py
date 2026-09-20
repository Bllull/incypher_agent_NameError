"""Shared helpers for recognizing InCypher challenge flags."""

from __future__ import annotations

import re
from typing import Any


_FLAG_PATTERN = re.compile(r"INCYPHER\{[^\r\n}]+\}")


def extract_flag(text: str) -> str | None:
    """Return the first exact-format ``INCYPHER{...}`` flag in text."""
    if not isinstance(text, str):
        raise TypeError("text must be a string")
    match = _FLAG_PATTERN.search(text)
    return match.group(0) if match else None


def extract_flag_from_json(payload: dict[str, Any] | list[Any]) -> str | None:
    """Return the first flag found recursively in a JSON object or array.

    Both object keys and string values are inspected. Other JSON scalar values
    cannot contain a textual flag and are ignored.
    """
    if not isinstance(payload, (dict, list)):
        raise TypeError("payload must be a JSON object or array")

    def visit(value: Any) -> str | None:
        if isinstance(value, str):
            return extract_flag(value)
        if isinstance(value, dict):
            for key, child in value.items():
                flag = extract_flag(key) if isinstance(key, str) else None
                if flag:
                    return flag
                flag = visit(child)
                if flag:
                    return flag
        elif isinstance(value, list):
            for child in value:
                flag = visit(child)
                if flag:
                    return flag
        return None

    return visit(payload)
