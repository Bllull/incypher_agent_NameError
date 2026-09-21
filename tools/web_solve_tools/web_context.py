"""Web-workflow state stored in the reserved shared context record."""

from __future__ import annotations

from typing import Any, Iterable
import json

from tools.context import delete_context, get_context, store_context


WEB_CONTEXT_ID = -1000
WEB_CONTEXT_VERSION = 3


def _initial_context(chal_ID: int) -> dict[str, Any]:
    """Return an empty reasoning tree for one web challenge."""
    return {
        "version": WEB_CONTEXT_VERSION,
        "challenge_id": chal_ID,
        "form_schema": None,
        "root_id": "root",
        "active_node_id": "root",
        "nodes": {
            "root": {
                "id": "root",
                "parent_id": None,
                "inference": "Initial web challenge investigation",
                "field_vars_to_test": [],
                "responses": [],
                "phase": "discovery",
                "input_surface": "unknown",
                "evidence": [],
                "new_evidence": [],
                "subsequent_steps": [],
                "status": "active",
            }
        },
    }


def reset_web_context(chal_ID: int) -> dict[str, Any]:
    """Clear and initialize the shared web context for a new challenge run."""
    delete_context(WEB_CONTEXT_ID)
    context = _initial_context(chal_ID)
    store_context(context, WEB_CONTEXT_ID)
    return context


def get_web_context(chal_ID: int) -> dict[str, Any]:
    """Return web state, resetting it when it belongs to another challenge."""
    context = get_context(WEB_CONTEXT_ID)
    if (
        not context
        or context.get("version") != WEB_CONTEXT_VERSION
        or context.get("challenge_id") != chal_ID
        or not isinstance(context.get("nodes"), dict)
    ):
        return reset_web_context(chal_ID)
    return context


def store_form_schema(chal_ID: int, form_schema: dict[str, Any]) -> None:
    """Store the current challenge's validated form schema in web state."""
    context = get_web_context(chal_ID)
    context["form_schema"] = form_schema
    store_context(context, WEB_CONTEXT_ID)


def upsert_web_node(chal_ID: int, node: dict[str, Any]) -> None:
    """Insert or replace one reasoning node and make it active."""
    node_id = node.get("id")
    parent_id = node.get("parent_id")
    if not isinstance(node_id, str) or not node_id:
        raise ValueError("web node id must be a non-empty string")
    if parent_id is not None and not isinstance(parent_id, str):
        raise ValueError("web node parent_id must be a string or None")

    context = get_web_context(chal_ID)
    nodes = context["nodes"]
    if parent_id is not None and parent_id not in nodes:
        raise ValueError(f"web node parent does not exist: {parent_id}")
    nodes[node_id] = node
    context["active_node_id"] = node_id
    store_context(context, WEB_CONTEXT_ID)


def append_web_node(
    chal_ID: int,
    *,
    parent_id: str,
    inference: str,
    field_vars_to_test: list[dict[str, Any]],
    responses: list[dict[str, Any]],
    subsequent_steps: list[str],
    phase: str = "discovery",
    input_surface: str = "unknown",
    evidence: Iterable[str] = (),
    status: str = "active",
) -> str:
    """Append a child reasoning node and return its generated ID."""
    context = get_web_context(chal_ID)
    nodes = context["nodes"]
    if parent_id not in nodes:
        raise ValueError(f"web node parent does not exist: {parent_id}")

    node_id = f"node-{len(nodes)}"
    while node_id in nodes:
        node_id = f"node-{len(nodes) + 1}"
    previous_evidence = {
        item
        for node in nodes.values()
        for item in node.get("evidence", [])
        if isinstance(item, str)
    }
    node_evidence = list(dict.fromkeys(item for item in evidence if isinstance(item, str)))
    upsert_web_node(
        chal_ID,
        {
            "id": node_id,
            "parent_id": parent_id,
            "inference": inference,
            "field_vars_to_test": field_vars_to_test,
            "responses": responses,
            "phase": phase,
            "input_surface": input_surface,
            "evidence": node_evidence,
            "new_evidence": [item for item in node_evidence if item not in previous_evidence],
            "subsequent_steps": subsequent_steps,
            "status": status,
        },
    )
    return node_id


def pruned_web_context(chal_ID: int, max_ancestors: int = 4) -> dict[str, Any]:
    """Return the active branch and compact evidence for an LLM prompt."""
    context = get_web_context(chal_ID)
    nodes = context["nodes"]
    path: list[dict[str, Any]] = []
    node_id = context["active_node_id"]
    visited: set[str] = set()
    while node_id in nodes and node_id not in visited:
        visited.add(node_id)
        node = nodes[node_id]
        responses = node.get("responses", [])
        compact_responses = [
            {
                "field": result.get("field"),
                "status_code": result.get("status_code"),
                "classification": result.get("classification"),
                "fingerprint": result.get("fingerprint"),
                "graphql_suggestions": result.get("suggestions", []),
                "graphql_required_arguments": result.get("required_arguments", []),
                "graphql_returned_facts": result.get("returned_facts", []),
                "filter_terms": result.get("filter_terms", []),
                "error_markers": result.get("error_markers", []),
                "evidence": str(result.get("text", ""))[:600],
            }
            for result in responses[-8:]
            if isinstance(result, dict)
        ]
        path.append(
            {
                "id": node.get("id"),
                "parent_id": node.get("parent_id"),
                "inference": node.get("inference", ""),
                "field_vars_to_test": node.get("field_vars_to_test", []),
                "responses": compact_responses,
                "phase": node.get("phase", "discovery"),
                "input_surface": node.get("input_surface", "unknown"),
                "new_evidence": node.get("new_evidence", []),
                "subsequent_steps": node.get("subsequent_steps", []),
                "status": node.get("status", "active"),
            }
        )
        parent_id = node.get("parent_id")
        if not isinstance(parent_id, str):
            break
        node_id = parent_id

    path.reverse()
    return {
        "active_node_id": context["active_node_id"],
        "active_branch": path[-max_ancestors:],
        "node_count": len(nodes),
        "known_evidence": sorted(
            {
                item
                for node in nodes.values()
                for item in node.get("evidence", [])
                if isinstance(item, str)
            }
        ),
    }


def attempted_test_keys(chal_ID: int) -> set[str]:
    """Return normalized field/value keys already submitted for this challenge."""
    context = get_web_context(chal_ID)
    keys: set[str] = set()
    for node in context["nodes"].values():
        for test in node.get("field_vars_to_test", []):
            if isinstance(test, dict) and isinstance(test.get("field"), str):
                keys.add(json.dumps([test["field"], test.get("value")], sort_keys=True))
    return keys



def has_recent_evidence_stall(chal_ID: int, limit: int) -> bool:
    """Return whether recent submitted web experiments produced no new evidence."""
    if limit < 1:
        raise ValueError("limit must be positive")
    nodes = list(get_web_context(chal_ID)["nodes"].values())
    experiments = [node for node in nodes if node.get("id") != "root" and node.get("responses")]
    recent = experiments[-limit:]
    return len(recent) == limit and not any(node.get("new_evidence") for node in recent)
