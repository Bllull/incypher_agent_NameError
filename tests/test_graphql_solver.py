"""Offline tests for the evidence-gated, authorized CTF GraphQL solver."""

from __future__ import annotations

import unittest
from unittest.mock import patch

import requests

from tools.web_chal import _graphql_response_records, _solve_graphql
from tools.web_solve_tools.graphql_workflow import (
    GraphQLOperation,
    GraphQLOperationResult,
    GraphQLRunResult,
)
from tools.web_solve_tools.web_context import pruned_web_context


CTF_URL = "https://ctf.example.test/challenge"
CTF_ENDPOINT = "https://ctf.example.test/graphql"


def _web_context() -> dict[str, object]:
    return {
        "active_node_id": "root",
        "nodes": {"root": {"id": "root", "status": "active"}},
    }


class GraphQLSolverTests(unittest.TestCase):
    """Keep solver tests fully mocked and limited to harmless CTF queries."""

    @patch("tools.web_chal.append_web_node")
    @patch("tools.web_chal.get_web_context", side_effect=lambda _chal_id: _web_context())
    @patch("tools.web_chal.has_recent_evidence_stall", return_value=False)
    @patch("tools.web_chal.run_graphql_operations_at_endpoint")
    @patch("tools.web_chal._ask_for_graphql_plan")
    @patch("tools.web_chal.find_graphql_endpoint")
    @patch("tools.web_chal.create_session", return_value=requests.Session())
    @patch("tools.web_chal.get_challenge_url", return_value=CTF_URL)
    def test_returns_an_exact_flag_from_a_bounded_ctf_plan(
        self,
        _get_url,
        _create_session,
        find_endpoint,
        ask_plan,
        run_operations,
        _stall,
        _web_context_mock,
        append_node,
    ) -> None:
        probe_operation = GraphQLOperation("query InCypherEndpointProbe { __typename }")
        probe = GraphQLOperationResult(
            endpoint=CTF_ENDPOINT,
            operation=probe_operation,
            payload={"data": {"__typename": "Query"}},
            analysis={"classification": "data_returned", "evidence": ["probe"]},
        )
        planned_operation = GraphQLOperation("query HarmlessCtfNote { note }")
        operation_result = GraphQLOperationResult(
            endpoint=CTF_ENDPOINT,
            operation=planned_operation,
            payload={"data": {"note": "INCYPHER{offline_solver_test}"}},
            analysis={
                "classification": "flag_found",
                "fingerprint": "flag-response",
                "evidence": ["flag_found"],
                "flag": "INCYPHER{offline_solver_test}",
            },
        )
        find_endpoint.return_value = probe
        ask_plan.return_value = {
            "phase": "retrieval",
            "hypothesis": "The recorded CTF field may contain the challenge flag.",
            "operations": [
                {
                    "query": planned_operation.query,
                    "variables": {},
                    "operation_name": None,
                    "purpose": "Read the evidence-supported CTF field.",
                }
            ],
            "advance_when": "An exact challenge flag is returned.",
            "fallback": "Record the response and continue only with new evidence.",
        }
        run_operations.return_value = GraphQLRunResult(
            results=(operation_result,),
            stop_reason="flag_found",
            requests_made=1,
            candidates_considered=1,
            duplicate_operations_skipped=0,
            flag="INCYPHER{offline_solver_test}",
        )

        flag = _solve_graphql(42)

        self.assertEqual(flag, "INCYPHER{offline_solver_test}")
        find_endpoint.assert_called_once()
        ask_plan.assert_called_once_with(42, CTF_ENDPOINT)
        run_operations.assert_called_once()
        self.assertEqual(append_node.call_count, 2)

    @patch("tools.web_chal.append_web_node")
    @patch("tools.web_chal.get_web_context", side_effect=lambda _chal_id: _web_context())
    @patch("tools.web_chal.find_graphql_endpoint", return_value=None)
    @patch("tools.web_chal.create_session", return_value=requests.Session())
    @patch("tools.web_chal.get_challenge_url", return_value=CTF_URL)
    def test_does_not_plan_or_send_operations_without_a_confirmed_endpoint(
        self,
        _get_url,
        _create_session,
        _find_endpoint,
        _web_context_mock,
        append_node,
    ) -> None:
        with patch("tools.web_chal._ask_for_graphql_plan") as ask_plan, patch(
            "tools.web_chal.run_graphql_operations_at_endpoint"
        ) as run_operations:
            self.assertIsNone(_solve_graphql(42))
        ask_plan.assert_not_called()
        run_operations.assert_not_called()
        self.assertEqual(append_node.call_count, 1)

    def test_response_records_follow_executed_operations_after_a_duplicate(self) -> None:
        first = GraphQLOperation("query HarmlessCtfFirst { first }")
        duplicate = GraphQLOperation(first.query)
        second = GraphQLOperation("query HarmlessCtfSecond { second }")
        planned = [
            {
                "query": first.query,
                "variables": {},
                "operation_name": None,
                "purpose": "First read-only CTF check.",
            },
            {
                "query": duplicate.query,
                "variables": {},
                "operation_name": None,
                "purpose": "Duplicate CTF check.",
            },
            {
                "query": second.query,
                "variables": {},
                "operation_name": None,
                "purpose": "Second read-only CTF check.",
            },
        ]
        run = GraphQLRunResult(
            results=(
                GraphQLOperationResult(
                    CTF_ENDPOINT,
                    first,
                    {"data": {"first": "ok"}},
                    {"evidence": ["first"]},
                ),
                GraphQLOperationResult(
                    CTF_ENDPOINT,
                    second,
                    {"data": {"second": "ok"}},
                    {"evidence": ["second"]},
                ),
            ),
            stop_reason="operations_exhausted",
            requests_made=2,
            candidates_considered=3,
            duplicate_operations_skipped=1,
        )

        records, evidence = _graphql_response_records(planned, run)

        self.assertEqual(records[1]["field"]["query"], second.query)
        self.assertEqual(records[1]["purpose"], "Second read-only CTF check.")
        self.assertEqual(evidence, ["first", "second"])

    def test_pruned_context_retains_graphql_evidence(self) -> None:
        context = {
            "active_node_id": "node-1",
            "nodes": {
                "root": {"id": "root", "parent_id": None, "evidence": []},
                "node-1": {
                    "id": "node-1",
                    "parent_id": "root",
                    "inference": "Validator evidence was returned.",
                    "field_vars_to_test": [],
                    "responses": [
                        {
                            "field": {"query": "query { draft }"},
                            "classification": "graphql_error",
                            "fingerprint": "response-1",
                            "suggestions": ["draft"],
                            "required_arguments": [{"field": "draft", "argument": "id"}],
                            "returned_facts": [{"path": "data.draft.id", "value": "d3"}],
                            "text": "synthetic CTF validator response",
                        }
                    ],
                    "phase": "root_field_discovery",
                    "new_evidence": ["graphql_suggestion:draft"],
                    "subsequent_steps": [],
                    "status": "active",
                    "evidence": ["graphql_suggestion:draft"],
                },
            },
        }
        with patch(
            "tools.web_solve_tools.web_context.get_web_context",
            return_value=context,
        ):
            pruned = pruned_web_context(42)

        response = pruned["active_branch"][-1]["responses"][0]
        self.assertEqual(response["graphql_suggestions"], ["draft"])
        self.assertEqual(response["graphql_required_arguments"][0]["argument"], "id")
        self.assertEqual(response["graphql_returned_facts"][0]["value"], "d3")


if __name__ == "__main__":
    unittest.main()
