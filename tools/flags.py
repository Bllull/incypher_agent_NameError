"""Shared helpers for recognizing InCypher challenge flags."""

from __future__ import annotations

import re


_FLAG_PATTERN = re.compile(r"INCYPHER\{[^\r\n}]+\}")


def extract_flag(text: str) -> str | None:
    """Return the first exact-format ``INCYPHER{...}`` flag in text."""
    if not isinstance(text, str):
        raise TypeError("text must be a string")
    match = _FLAG_PATTERN.search(text)
    return match.group(0) if match else None
