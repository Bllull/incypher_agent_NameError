"""Deterministic evidence extraction for iterative SSTI form experiments."""

from __future__ import annotations

import hashlib
import re
from typing import Any

from tools.flags import extract_flag

_REJECTION_PATTERN = re.compile(
    r"(?:blocked|forbidden|disallowed|not allowed|blacklist(?:ed)?)"
    r"(?:\s+(?:token|term|word|character))?\s*[:=]?\s*['\"]?([\w./-]{1,64})?",
    re.IGNORECASE,
)
_QUOTED_REJECTION_PATTERN = re.compile(
    r"['\"]([^'\"]{1,64})['\"]\s+(?:is\s+)?(?:blocked|forbidden|disallowed)",
    re.IGNORECASE,
)
_ERROR_MARKERS = ("traceback", "syntaxerror", "template error", "exception", "undefined", "error")


def response_fingerprint(status_code: int, text: str) -> str:
    """Return a compact stable identity for a server response."""
    value = f"{status_code}:{text}"
    return hashlib.sha256(value.encode("utf-8", errors="replace")).hexdigest()[:16]


def analyze_ssti_response(
    payload: dict[str, object],
    status_code: int,
    text: str,
    *,
    expected_output: str | None = None,
) -> dict[str, Any]:
    """Classify observable response signals without assuming a template engine."""
    lowered = text.lower()
    rejection_terms = {
        match.group(1).strip().lower()
        for match in _REJECTION_PATTERN.finditer(text)
        if match.group(1)
    }
    rejection_terms.update(
        match.group(1).strip().lower() for match in _QUOTED_REJECTION_PATTERN.finditer(text)
    )
    rejected = bool(rejection_terms) or bool(_REJECTION_PATTERN.search(text))
    errors = [marker for marker in _ERROR_MARKERS if marker in lowered]
    flag = extract_flag(text)
    payload_values = [str(value) for value in payload.values()]
    reflected = any(value and value in text for value in payload_values)
    expected_observed = bool(expected_output and expected_output in text)

    if flag:
        classification = "flag_found"
    elif rejected:
        classification = "filter_rejection"
    elif errors or status_code >= 400:
        classification = "runtime_or_http_error"
    elif expected_observed:
        classification = "expected_output_observed"
    else:
        classification = "response_observed"

    evidence = [f"response_status:{status_code}"]
    evidence.extend(f"filter_rejection:{term}" for term in sorted(rejection_terms))
    evidence.extend(f"error_marker:{marker}" for marker in errors)
    if reflected:
        evidence.append("payload_reflected")
    if expected_observed:
        evidence.append("expected_output_observed")
    if flag:
        evidence.append("flag_found")

    return {
        "classification": classification,
        "evidence": evidence,
        "fingerprint": response_fingerprint(status_code, text),
        "filter_terms": sorted(rejection_terms),
        "error_markers": errors,
        "payload_reflected": reflected,
        "expected_output_observed": expected_observed,
    }
