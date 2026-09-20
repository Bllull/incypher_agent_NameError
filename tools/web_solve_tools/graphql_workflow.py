"""Bounded GraphQL helpers for authorized, same-origin CTF challenges.

Endpoint discovery uses a read-only probe, and operation execution is bounded
by explicit candidate, request, and repeated-response limits.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from itertools import islice
from typing import Any, Iterable
from urllib.parse import urlparse, urlunparse

import requests

from tools.http_client import graphql_query, same_origin_url
from tools.web_solve_tools.graphql_evidence import analyze_graphql_response


DEFAULT_GRAPHQL_ENDPOINT_PATHS = ("/graphql", "graphql")
DEFAULT_GRAPHQL_CANDIDATE_LIMIT = 100
DEFAULT_GRAPHQL_REQUEST_LIMIT = 20
DEFAULT_GRAPHQL_REPEAT_LIMIT = 2
DEFAULT_GRAPHQL_TIMEOUT_SECONDS = 15
GRAPHQL_ENDPOINT_PROBE = "query InCypherEndpointProbe { __typename }"


@dataclass(frozen=True)
class GraphQLWorkflowConfig:
    """Limits and endpoint paths shared by the GraphQL workflow."""

    endpoint_paths: tuple[str, ...] = DEFAULT_GRAPHQL_ENDPOINT_PATHS
    candidate_limit: int = DEFAULT_GRAPHQL_CANDIDATE_LIMIT
    request_limit: int = DEFAULT_GRAPHQL_REQUEST_LIMIT
    repeated_response_limit: int = DEFAULT_GRAPHQL_REPEAT_LIMIT
    timeout_seconds: int = DEFAULT_GRAPHQL_TIMEOUT_SECONDS

    def __post_init__(self) -> None:
        if not self.endpoint_paths or not all(
            isinstance(path, str) and path.strip() for path in self.endpoint_paths
        ):
            raise ValueError("endpoint_paths must contain non-empty strings")
        if self.candidate_limit <= 0:
            raise ValueError("candidate_limit must be positive")
        if self.request_limit <= 0:
            raise ValueError("request_limit must be positive")
        if self.repeated_response_limit <= 0:
            raise ValueError("repeated_response_limit must be positive")
        if self.timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive")


@dataclass(frozen=True)
class GraphQLOperation:
    """One GraphQL operation awaiting bounded execution."""

    query: str
    variables: dict[str, Any] = field(default_factory=dict)
    operation_name: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.query, str) or not self.query.strip():
            raise ValueError("query must be a non-empty string")
        if not isinstance(self.variables, dict):
            raise TypeError("variables must be a dictionary")
        if self.operation_name is not None and (
            not isinstance(self.operation_name, str) or not self.operation_name.strip()
        ):
            raise ValueError("operation_name must be a non-empty string or None")


@dataclass(frozen=True)
class GraphQLOperationResult:
    """Structured response and deterministic evidence for one operation."""

    endpoint: str
    operation: GraphQLOperation
    payload: dict[str, Any]
    analysis: dict[str, Any]


@dataclass(frozen=True)
class GraphQLRunResult:
    """Summary of a bounded sequence of GraphQL operation attempts."""

    results: tuple[GraphQLOperationResult, ...]
    stop_reason: str
    requests_made: int
    candidates_considered: int
    duplicate_operations_skipped: int
    flag: str | None = None


@dataclass(frozen=True)
class GraphQLCtfWorkflowResult:
    """Outcome of endpoint discovery and bounded operations for one CTF URL."""

    endpoint: str | None
    probe_result: GraphQLOperationResult | None
    operation_run: GraphQLRunResult | None


def graphql_operation_fingerprint(operation: GraphQLOperation) -> str:
    """Return a stable identity for a query, variables, and operation name."""
    if not isinstance(operation, GraphQLOperation):
        raise TypeError("operation must be a GraphQLOperation")
    normalized = json.dumps(
        {
            "operation_name": operation.operation_name,
            "query": operation.query,
            "variables": operation.variables,
        },
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    )
    return hashlib.sha256(normalized.encode("utf-8", errors="replace")).hexdigest()[:16]


def _normalize_endpoint(url: str) -> str:
    """Remove query/fragment noise and normalize an endpoint's trailing slash."""
    parsed = urlparse(url)
    path = parsed.path or "/"
    if path != "/":
        path = path.rstrip("/")
    return urlunparse((parsed.scheme.lower(), parsed.netloc, path, "", "", ""))


def graphql_endpoint_candidates(
    challenge_url: str,
    endpoint_paths: Iterable[str] = DEFAULT_GRAPHQL_ENDPOINT_PATHS,
) -> list[str]:
    """Derive normalized, same-origin GraphQL endpoint candidates.

    An input URL already ending in ``/graphql`` is retained first. Absolute
    endpoint paths are resolved from the challenge origin, while relative
    paths are resolved beneath the challenge URL. Results preserve order and
    remove duplicates.
    """
    if not isinstance(challenge_url, str) or not challenge_url.strip():
        raise ValueError("challenge_url must be a non-empty string")

    normalized_challenge_url = _normalize_endpoint(challenge_url.strip())
    parsed = urlparse(normalized_challenge_url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError("challenge_url must be an absolute HTTP(S) URL")

    candidates: list[str] = []

    def add(candidate: str) -> None:
        normalized = _normalize_endpoint(candidate)
        if normalized not in candidates:
            candidates.append(normalized)

    already_graphql = parsed.path.rstrip("/").lower().endswith("/graphql")
    if already_graphql:
        add(normalized_challenge_url)

    relative_base = f"{normalized_challenge_url.rstrip('/')}/"
    for endpoint_path in endpoint_paths:
        if not isinstance(endpoint_path, str) or not endpoint_path.strip():
            raise ValueError("endpoint_paths must contain non-empty strings")
        path = endpoint_path.strip()
        if already_graphql and not path.startswith("/"):
            continue
        base_url = normalized_challenge_url if path.startswith("/") else relative_base
        add(same_origin_url(base_url, path))

    return candidates


def _execute_graphql_operation(
    session: requests.Session,
    endpoint: str,
    operation: GraphQLOperation,
    config: GraphQLWorkflowConfig,
) -> GraphQLOperationResult:
    """Execute one GraphQL operation and attach deterministic evidence."""
    if not isinstance(session, requests.Session):
        raise TypeError("session must be a requests.Session")
    if not isinstance(endpoint, str) or not endpoint.strip():
        raise ValueError("endpoint must be a non-empty string")
    parsed_endpoint = urlparse(endpoint)
    if parsed_endpoint.scheme not in {"http", "https"} or not parsed_endpoint.netloc:
        raise ValueError("endpoint must be an absolute HTTP(S) URL")
    if not isinstance(operation, GraphQLOperation):
        raise TypeError("operation must be a GraphQLOperation")
    if not isinstance(config, GraphQLWorkflowConfig):
        raise TypeError("config must be a GraphQLWorkflowConfig")

    normalized_endpoint = _normalize_endpoint(endpoint.strip())
    payload = graphql_query(
        session,
        normalized_endpoint,
        operation.query,
        operation.variables,
        path="",
        operation_name=operation.operation_name,
        timeout=config.timeout_seconds,
    )
    analysis = analyze_graphql_response(payload)
    return GraphQLOperationResult(
        endpoint=normalized_endpoint,
        operation=operation,
        payload=payload,
        analysis=analysis,
    )


def _probe_graphql_endpoint(
    session: requests.Session,
    endpoint: str,
    config: GraphQLWorkflowConfig,
) -> GraphQLOperationResult | None:
    """Identify GraphQL using a read-only meta-field query on the CTF origin."""
    probe = GraphQLOperation(
        query=GRAPHQL_ENDPOINT_PROBE,
        operation_name="InCypherEndpointProbe",
    )
    try:
        result = _execute_graphql_operation(session, endpoint, probe, config)
    except (requests.RequestException, ValueError):
        return None

    data = result.payload.get("data")
    if isinstance(data, dict) and isinstance(data.get("__typename"), str):
        return result

    errors = result.payload.get("errors")
    if isinstance(errors, list) and any(
        isinstance(error, dict)
        and isinstance(error.get("message"), str)
        and bool(error["message"].strip())
        for error in errors
    ):
        return result
    return None


def find_graphql_endpoint(
    session: requests.Session,
    challenge_url: str,
    config: GraphQLWorkflowConfig | None = None,
) -> GraphQLOperationResult | None:
    """Probe candidates in order and return the first GraphQL endpoint."""
    settings = config or GraphQLWorkflowConfig()
    for endpoint in graphql_endpoint_candidates(
        challenge_url,
        settings.endpoint_paths,
    ):
        result = _probe_graphql_endpoint(session, endpoint, settings)
        if result is not None:
            return result
    return None


def run_graphql_ctf_operations(
    session: requests.Session,
    challenge_url: str,
    operations: Iterable[GraphQLOperation],
    config: GraphQLWorkflowConfig | None = None,
) -> GraphQLCtfWorkflowResult:
    """Run approved operations only after a same-origin CTF endpoint is found.

    Endpoint probing is intentionally separate from the operation budget: it
    uses only the finite, configured endpoint candidate list and its read-only
    ``__typename`` request. This helper does not classify challenges, generate
    operations, submit flags, or invoke a solver dispatcher.
    """
    settings = config or GraphQLWorkflowConfig()
    probe_result = find_graphql_endpoint(session, challenge_url, settings)
    if probe_result is None:
        return GraphQLCtfWorkflowResult(
            endpoint=None,
            probe_result=None,
            operation_run=None,
        )

    operation_run = run_graphql_operations_at_endpoint(
        session,
        probe_result.endpoint,
        operations,
        settings,
    )
    return GraphQLCtfWorkflowResult(
        endpoint=probe_result.endpoint,
        probe_result=probe_result,
        operation_run=operation_run,
    )


def _run_graphql_operations(
    session: requests.Session,
    endpoint: str,
    operations: Iterable[GraphQLOperation],
    config: GraphQLWorkflowConfig,
) -> GraphQLRunResult:
    """Run candidate operations within candidate and HTTP-request limits."""
    results: list[GraphQLOperationResult] = []
    requests_made = 0
    candidates_considered = 0
    duplicate_operations_skipped = 0
    discovered_flag: str | None = None
    stop_reason = "operations_exhausted"
    attempted_operations: set[str] = set()
    response_counts: dict[str, int] = {}
    for operation in islice(operations, config.candidate_limit):
        candidates_considered += 1
        operation_fingerprint = graphql_operation_fingerprint(operation)
        if operation_fingerprint in attempted_operations:
            duplicate_operations_skipped += 1
            continue
        attempted_operations.add(operation_fingerprint)
        if requests_made >= config.request_limit:
            stop_reason = "request_limit"
            break
        requests_made += 1
        result = _execute_graphql_operation(session, endpoint, operation, config)
        results.append(result)
        flag = result.analysis.get("flag")
        if isinstance(flag, str) and flag:
            discovered_flag = flag
            stop_reason = "flag_found"
            break
        response_fingerprint = result.analysis.get("fingerprint")
        if isinstance(response_fingerprint, str) and response_fingerprint:
            response_counts[response_fingerprint] = (
                response_counts.get(response_fingerprint, 0) + 1
            )
            if (
                response_counts[response_fingerprint]
                >= config.repeated_response_limit
            ):
                stop_reason = "repeated_response"
                break
    else:
        if candidates_considered >= config.candidate_limit:
            stop_reason = "candidate_limit"
        elif requests_made >= config.request_limit:
            stop_reason = "request_limit"

    return GraphQLRunResult(
        results=tuple(results),
        stop_reason=stop_reason,
        requests_made=requests_made,
        candidates_considered=candidates_considered,
        duplicate_operations_skipped=duplicate_operations_skipped,
        flag=discovered_flag,
    )


def run_graphql_operations_at_endpoint(
    session: requests.Session,
    endpoint: str,
    operations: Iterable[GraphQLOperation],
    config: GraphQLWorkflowConfig | None = None,
) -> GraphQLRunResult:
    """Run supplied, bounded operations at an already-confirmed CTF endpoint."""
    settings = config or GraphQLWorkflowConfig()
    return _run_graphql_operations(session, endpoint, operations, settings)
