"""Offline regression tests for the authorized CTF GraphQL workflow."""

from __future__ import annotations

import unittest
from unittest.mock import patch

import requests

from tools.web_solve_tools.graphql_workflow import (
    GraphQLOperation,
    GraphQLOperationResult,
    GraphQLRunResult,
    GraphQLWorkflowConfig,
    _execute_graphql_operation,
    _run_graphql_operations,
    graphql_endpoint_candidates,
    run_graphql_ctf_operations,
)


CTF_URL = "https://ctf.example.test/challenge"
CTF_ENDPOINT = "https://ctf.example.test/graphql"


def _operation(number: int) -> GraphQLOperation:
    """Return a read-only synthetic CTF query for offline testing."""
    return GraphQLOperation(f"query HarmlessCtfCheck{number} {{ __typename }}")


def _result(
    operation: GraphQLOperation,
    fingerprint: str,
    flag: str | None = None,
) -> GraphQLOperationResult:
    """Build synthetic GraphQL evidence without an HTTP request."""
    return GraphQLOperationResult(
        endpoint=CTF_ENDPOINT,
        operation=operation,
        payload={"data": {"__typename": "Query"}},
        analysis={"fingerprint": fingerprint, "flag": flag},
    )


class GraphQLWorkflowTests(unittest.TestCase):
    """Confirm safe workflow behavior exclusively with mocked transport."""

    def setUp(self) -> None:
        self.session = requests.Session()

    def test_same_origin_endpoint_candidates(self) -> None:
        self.assertEqual(
            graphql_endpoint_candidates(CTF_URL),
            [CTF_ENDPOINT, "https://ctf.example.test/challenge/graphql"],
        )

    @patch("tools.web_solve_tools.graphql_workflow.graphql_query")
    def test_single_read_only_operation_is_forwarded(self, graphql_query_mock) -> None:
        operation = GraphQLOperation("query HarmlessCtfStatus { __typename }")
        graphql_query_mock.return_value = {"data": {"__typename": "Query"}}

        result = _execute_graphql_operation(
            self.session,
            CTF_ENDPOINT,
            operation,
            GraphQLWorkflowConfig(timeout_seconds=7),
        )

        self.assertEqual(result.payload["data"]["__typename"], "Query")
        graphql_query_mock.assert_called_once_with(
            self.session,
            CTF_ENDPOINT,
            operation.query,
            {},
            path="",
            operation_name=None,
            timeout=7,
        )

    @patch("tools.web_solve_tools.graphql_workflow._execute_graphql_operation")
    def test_bounds_duplicates_repeated_responses_and_flags(self, execute_mock) -> None:
        first, second, third = (_operation(index) for index in range(1, 4))

        execute_mock.side_effect = [
            _result(first, "same"),
            _result(second, "same"),
            _result(third, "unused"),
        ]
        repeated = _run_graphql_operations(
            self.session,
            CTF_ENDPOINT,
            [first, second, third],
            GraphQLWorkflowConfig(repeated_response_limit=2),
        )
        self.assertEqual(repeated.stop_reason, "repeated_response")
        self.assertEqual(repeated.requests_made, 2)

        execute_mock.reset_mock()
        duplicate = GraphQLOperation(first.query)
        execute_mock.side_effect = [_result(first, "one"), _result(second, "two")]
        deduplicated = _run_graphql_operations(
            self.session,
            CTF_ENDPOINT,
            [first, duplicate, second],
            GraphQLWorkflowConfig(),
        )
        self.assertEqual(deduplicated.duplicate_operations_skipped, 1)
        self.assertEqual(execute_mock.call_count, 2)

        execute_mock.reset_mock()
        execute_mock.side_effect = [
            _result(first, "before"),
            _result(second, "flag", "INCYPHER{offline_ctf_test}"),
        ]
        flagged = _run_graphql_operations(
            self.session,
            CTF_ENDPOINT,
            [first, second, third],
            GraphQLWorkflowConfig(),
        )
        self.assertEqual(flagged.stop_reason, "flag_found")
        self.assertEqual(flagged.flag, "INCYPHER{offline_ctf_test}")
        self.assertEqual(execute_mock.call_count, 2)

    @patch("tools.web_solve_tools.graphql_workflow.run_graphql_operations_at_endpoint")
    @patch("tools.web_solve_tools.graphql_workflow.find_graphql_endpoint")
    def test_composed_workflow_requires_a_confirmed_endpoint(
        self,
        find_endpoint_mock,
        run_operations_mock,
    ) -> None:
        operation = _operation(1)
        find_endpoint_mock.return_value = None
        absent = run_graphql_ctf_operations(self.session, CTF_URL, [operation])
        self.assertIsNone(absent.endpoint)
        self.assertIsNone(absent.operation_run)
        run_operations_mock.assert_not_called()

        probe = _result(
            GraphQLOperation("query InCypherEndpointProbe { __typename }"),
            "probe",
        )
        summary = GraphQLRunResult((), "operations_exhausted", 0, 0, 0)
        find_endpoint_mock.return_value = probe
        run_operations_mock.return_value = summary
        present = run_graphql_ctf_operations(self.session, CTF_URL, [operation])
        self.assertEqual(present.endpoint, CTF_ENDPOINT)
        self.assertIs(present.operation_run, summary)


if __name__ == "__main__":
    unittest.main()
