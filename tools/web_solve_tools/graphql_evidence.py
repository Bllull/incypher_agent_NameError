"""Deterministic evidence extraction from GraphQL JSON responses."""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any

from tools.flags import extract_flag_from_json


_QUOTED_IDENTIFIER_PATTERN = re.compile(
    r"[\"'`]([_A-Za-z][_0-9A-Za-z]*)[\"'`]"
)
_SUGGESTION_PATTERN = re.compile(r"did you mean\s+(.+?)(?:\?|$)", re.IGNORECASE)
_UNKNOWN_FIELD_PATTERN = re.compile(
    r"cannot query field\s+[\"'`]([_A-Za-z][_0-9A-Za-z]*)[\"'`]",
    re.IGNORECASE,
)
_UNKNOWN_ARGUMENT_PATTERN = re.compile(
    r"unknown argument\s+[\"'`]([_A-Za-z][_0-9A-Za-z]*)[\"'`]",
    re.IGNORECASE,
)
_REQUIRED_ARGUMENT_PATTERN = re.compile(
    r"field\s+[\"'`]([_A-Za-z][_0-9A-Za-z]*)[\"'`]\s+argument\s+"
    r"[\"'`]([_A-Za-z][_0-9A-Za-z]*)[\"'`]\s+of type\s+"
    r"[\"'`]([^\"'`]+)[\"'`]\s+is required",
    re.IGNORECASE,
)
_SELECTION_REQUIRED_PATTERN = re.compile(
    r"field\s+[\"'`]([_A-Za-z][_0-9A-Za-z]*)[\"'`]\s+of type\s+"
    r"[\"'`]([^\"'`]+)[\"'`]\s+must have a selection",
    re.IGNORECASE,
)


def graphql_response_fingerprint(payload: dict[str, Any]) -> str:
    """Return a stable compact identity for one GraphQL response."""
    normalized = json.dumps(payload, ensure_ascii=False, sort_keys=True)
    return hashlib.sha256(normalized.encode("utf-8", errors="replace")).hexdigest()[:16]


def _error_messages(payload: dict[str, Any]) -> list[str]:
    """Return well-formed messages from the GraphQL ``errors`` array."""
    errors = payload.get("errors", [])
    if not isinstance(errors, list):
        return []
    return [
        message
        for error in errors
        if isinstance(error, dict)
        and isinstance((message := error.get("message")), str)
        and message.strip()
    ]


def _suggested_identifiers(messages: list[str]) -> list[str]:
    """Extract GraphQL validator suggestions without executing their text."""
    suggestions: list[str] = []
    for message in messages:
        match = _SUGGESTION_PATTERN.search(message)
        if not match:
            continue
        for identifier in _QUOTED_IDENTIFIER_PATTERN.findall(match.group(1)):
            if identifier not in suggestions:
                suggestions.append(identifier)
    return suggestions


def _introspection_fields(payload: dict[str, Any]) -> dict[str, list[str]]:
    """Extract root field names from a successful minimal introspection query."""
    result = {"query_fields": [], "mutation_fields": []}
    data = payload.get("data")
    schema = data.get("__schema") if isinstance(data, dict) else None
    if not isinstance(schema, dict):
        return result

    for type_key, result_key in (
        ("queryType", "query_fields"),
        ("mutationType", "mutation_fields"),
    ):
        root_type = schema.get(type_key)
        fields = root_type.get("fields", []) if isinstance(root_type, dict) else []
        if not isinstance(fields, list):
            continue
        result[result_key] = [
            field["name"]
            for field in fields
            if isinstance(field, dict)
            and isinstance(field.get("name"), str)
            and field["name"]
        ]
    return result


def _returned_facts(payload: dict[str, Any], limit: int = 64) -> list[dict[str, Any]]:
    """Flatten bounded scalar values from GraphQL ``data`` into reusable facts."""
    facts: list[dict[str, Any]] = []

    def visit(value: Any, path: list[str]) -> None:
        if len(facts) >= limit:
            return
        if isinstance(value, dict):
            for key, child in value.items():
                if isinstance(key, str):
                    visit(child, [*path, key])
            return
        if isinstance(value, list):
            for index, child in enumerate(value):
                visit(child, [*path, str(index)])
            return
        if value is None or isinstance(value, (str, int, float, bool)):
            normalized = value[:1000] if isinstance(value, str) else value
            facts.append({"path": ".".join(path), "value": normalized})

    visit(payload.get("data"), ["data"])
    return facts


def analyze_graphql_response(payload: dict[str, Any]) -> dict[str, Any]:
    """Classify a GraphQL response and extract bounded solver evidence."""
    if not isinstance(payload, dict):
        raise TypeError("GraphQL payload must be a dictionary")

    messages = _error_messages(payload)
    suggestions = _suggested_identifiers(messages)
    unknown_fields = list(
        dict.fromkeys(
            match.group(1)
            for message in messages
            for match in _UNKNOWN_FIELD_PATTERN.finditer(message)
        )
    )
    unknown_arguments = list(
        dict.fromkeys(
            match.group(1)
            for message in messages
            for match in _UNKNOWN_ARGUMENT_PATTERN.finditer(message)
        )
    )
    required_arguments = [
        {"field": match.group(1), "argument": match.group(2), "type": match.group(3)}
        for message in messages
        for match in _REQUIRED_ARGUMENT_PATTERN.finditer(message)
    ]
    selection_required = [
        {"field": match.group(1), "type": match.group(2)}
        for message in messages
        for match in _SELECTION_REQUIRED_PATTERN.finditer(message)
    ]
    introspection = _introspection_fields(payload)
    facts = _returned_facts(payload)
    flag = extract_flag_from_json(payload)
    data_present = payload.get("data") is not None

    if flag:
        classification = "flag_found"
    elif data_present and messages:
        classification = "partial_data"
    elif data_present:
        classification = "data_returned"
    elif messages:
        classification = "graphql_error"
    else:
        classification = "empty_response"

    evidence = [f"graphql_response:{graphql_response_fingerprint(payload)}"]
    evidence.extend(f"graphql_suggestion:{name}" for name in suggestions)
    evidence.extend(
        f"graphql_required_argument:{item['field']}.{item['argument']}:{item['type']}"
        for item in required_arguments
    )
    evidence.extend(
        f"graphql_query_field:{name}" for name in introspection["query_fields"]
    )
    evidence.extend(
        f"graphql_mutation_field:{name}" for name in introspection["mutation_fields"]
    )
    if flag:
        evidence.append("flag_found")

    return {
        "classification": classification,
        "evidence": evidence,
        "fingerprint": graphql_response_fingerprint(payload),
        "error_messages": messages,
        "suggestions": suggestions,
        "unknown_fields": unknown_fields,
        "unknown_arguments": unknown_arguments,
        "required_arguments": required_arguments,
        "selection_required": selection_required,
        "introspection": introspection,
        "returned_facts": facts,
        "flag": flag,
    }
