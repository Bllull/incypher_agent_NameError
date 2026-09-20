"""Orchestration for URL-based CTF challenges."""

from __future__ import annotations

import json

import requests

from tools.context import get_chal_file_path, get_context
from tools.ctfd_api import get_challenge_url
from tools.http_client import create_session
from tools.web_solve_tools.web_llm import call_web_llm
from tools.web_solve_tools.webpage_access_helpers import extract_flag, get_form_json, submit_form
from tools.web_solve_tools.web_context import (
    append_web_node,
    attempted_test_keys,
    get_web_context,
    has_recent_evidence_stall,
    pruned_web_context,
    reset_web_context,
    upsert_web_node,
)
from tools.web_solve_tools.ssti_evidence import analyze_ssti_response


WEB_CHALLENGE_SUBTYPES = ("SSTI",)
SSTI_PHASES = ("discovery", "confirmation", "filter_mapping", "capability_mapping", "retrieval")
MAX_SSTI_ITERATIONS = 20
MAX_SSTI_TESTS_PER_ITERATION = 10
MAX_SSTI_NO_PROGRESS_ITERATIONS = 3


def identify_web_subtype(chal_ID: int) -> str:
    """Classify a web challenge from its stored context using the configured LLM.

    The returned value is always one of ``WEB_CHALLENGE_SUBTYPES`` or
    ``"UNKNOWN"``. Keeping the output constrained makes it safe for the
    dispatcher to grow with additional subtype-specific workflows later.
    """
    challenge_context = get_context(chal_ID) or {}
    web_context = pruned_web_context(chal_ID)
    prompt = f"""You are classifying a web CTF challenge for a workflow dispatcher.

Read the challenge context below and identify its subtype. The only currently
supported subtype is SSTI (server-side template injection). Return exactly one
token: SSTI if the context indicates an SSTI challenge; otherwise return
UNKNOWN. Do not explain your answer.

Challenge ID: {chal_ID}
Challenge context:
{json.dumps(challenge_context, sort_keys=True)}

Previously collected web workflow context:
{json.dumps(web_context, sort_keys=True)}
"""
    try:
        answer = call_web_llm(prompt).strip().upper()
    except Exception as exc:
        print(f"[web] Challenge {chal_ID} subtype classification failed: {exc}")
        return "UNKNOWN"

    # Accept harmless formatting from the model while still enforcing the
    # preset vocabulary used by the dispatcher.
    match = next((subtype for subtype in WEB_CHALLENGE_SUBTYPES if subtype in answer), None)
    return match or "UNKNOWN"


def _parse_ssti_plan(raw_plan: str, form_fields: dict[str, object]) -> dict[str, object]:
    """Parse and validate one machine-readable LLM test plan."""
    cleaned = raw_plan.strip()
    if cleaned.startswith("```"):
        cleaned = cleaned.split("\n", 1)[1].rsplit("```", 1)[0].strip()
    plan = json.loads(cleaned)
    if not isinstance(plan, dict):
        raise ValueError("SSTI LLM plan must be a JSON object")

    phase = plan.get("phase")
    hypothesis = plan.get("hypothesis", "")
    tests = plan.get("tests", [])
    advance_when = plan.get("advance_when", "")
    fallback = plan.get("fallback", "")
    if phase not in SSTI_PHASES:
        raise ValueError(f"SSTI plan phase must be one of {SSTI_PHASES}")
    if not isinstance(hypothesis, str) or not hypothesis.strip():
        raise ValueError("SSTI plan hypothesis must be a non-empty string")
    if not isinstance(tests, list) or not all(isinstance(test, dict) for test in tests):
        raise ValueError("SSTI plan tests must be a list of objects")
    if not isinstance(advance_when, str) or not isinstance(fallback, str):
        raise ValueError("SSTI plan advance_when and fallback must be strings")

    normalized_tests: list[dict[str, object]] = []
    for test in tests:
        field = test.get("field")
        if not isinstance(field, str) or field not in form_fields:
            raise ValueError(f"SSTI plan references unknown form field: {field!r}")
        if "value" not in test:
            raise ValueError(f"SSTI plan has no value for field: {field}")
        purpose = test.get("purpose", "")
        expected_signals = test.get("expected_signals", [])
        expected_output = test.get("expected_output")
        if not isinstance(purpose, str) or not purpose.strip():
            raise ValueError(f"SSTI plan test purpose must be a non-empty string: {field}")
        if not isinstance(expected_signals, list) or not all(isinstance(signal, str) for signal in expected_signals):
            raise ValueError(f"SSTI plan expected_signals must be a list of strings: {field}")
        if expected_output is not None and not isinstance(expected_output, str):
            raise ValueError(f"SSTI plan expected_output must be a string when supplied: {field}")
        normalized_tests.append(
            {
                "field": field,
                "value": test["value"],
                "purpose": purpose,
                "expected_signals": expected_signals,
                "expected_output": expected_output,
            }
        )
    return {
        "phase": phase,
        "hypothesis": hypothesis,
        "tests": normalized_tests,
        "advance_when": advance_when,
        "fallback": fallback,
    }


def _ask_for_ssti_plan(chal_ID: int, form_schema: dict[str, object]) -> dict[str, object]:
    """Ask the LLM for the next field/value tests from a pruned branch."""
    challenge_context = get_context(chal_ID) or {}
    workflow_context = pruned_web_context(chal_ID)
    prompt = f"""You are iteratively solving a web CTF challenge.

Use the challenge context, form schema, and recorded observations to choose
the next smallest set of experiments. Treat observations as facts and every
other claim as a hypothesis. Do not assume a template engine, programming
language semantics, filter mechanism, exposed capability, or flag location.

Choose one evidence-gated phase: discovery (locate possible evaluation),
confirmation (verify an observed effect), filter_mapping (isolate one input
constraint at a time), capability_mapping (learn only capabilities supported
by evidence), or retrieval (only when evidence supports a target). Prefer
tests that distinguish hypotheses. A rejection response can be useful evidence;
do not repeat an already submitted field/value pair.

Return JSON only, with exactly this shape:
{{
  "phase": "one allowed phase",
  "hypothesis": "short evidence-based hypothesis",
  "tests": [{{
    "field": "field_name",
    "value": "value_to_submit",
    "purpose": "what this distinguishes",
    "expected_signals": ["observable result categories"],
    "expected_output": "optional literal output expected from a harmless probe"
  }}],
  "advance_when": "observable condition for changing phase",
  "fallback": "next action if the condition is absent"
}}

The field values must use form field names from the schema. Keep all text
concise. Do not include hidden chain-of-thought or a fixed exploit recipe.

Challenge context:
{json.dumps(challenge_context, sort_keys=True)}

Form schema:
{json.dumps(form_schema, sort_keys=True)}

Pruned workflow context:
{json.dumps(workflow_context, sort_keys=True)}
"""
    return _parse_ssti_plan(
        call_web_llm(prompt, require_deep_reasoning=True),
        form_schema.get("fields", {}),
    )


def _solve_ssti(chal_ID: int) -> str | None:
    """Iteratively choose, submit, and record SSTI field/value tests."""
    web_context = get_web_context(chal_ID)
    challenge_url = get_challenge_url(chal_ID)
    session = create_session()
    form_schema = get_form_json(
        challenge_url,
        context=web_context,
        session=session,
        chal_ID=chal_ID,
    )
    print(f"[web][SSTI] Form schema: {json.dumps(form_schema, sort_keys=True)}")
    fields = form_schema.get("fields", {})
    if not isinstance(fields, dict) or not fields:
        raise ValueError("The validated SSTI form contains no fields")

    for iteration in range(1, MAX_SSTI_ITERATIONS + 1):
        plan = _ask_for_ssti_plan(chal_ID, form_schema)
        tests = plan["tests"]
        assert isinstance(tests, list)
        attempted = attempted_test_keys(chal_ID)
        tests = [
            test for test in tests
            if json.dumps([test.get("field"), test.get("value")], sort_keys=True) not in attempted
        ]
        plan["tests"] = tests
        if len(tests) > MAX_SSTI_TESTS_PER_ITERATION:
            print(
                f"[web][SSTI] Iteration {iteration} suggested {len(tests)} tests; "
                f"capping at {MAX_SSTI_TESTS_PER_ITERATION}."
            )
            tests = tests[:MAX_SSTI_TESTS_PER_ITERATION]
            plan["tests"] = tests
        branch = pruned_web_context(chal_ID)["active_branch"]
        branch_summary = [
            {
                "id": node.get("id"),
                "inference": node.get("inference"),
                "status": node.get("status"),
            }
            for node in branch
        ]
        print(f"[web][SSTI] Iteration {iteration} reasoning branch:")
        print(json.dumps(branch_summary, sort_keys=True))
        print(f"[web][SSTI] Iteration {iteration} phase: {plan['phase']}")
        print(f"[web][SSTI] Iteration {iteration} hypothesis: {plan['hypothesis']}")
        print(
            f"[web][SSTI] Iteration {iteration} advance condition: {plan['advance_when']}"
        )
        print(
            f"[web][SSTI] Iteration {iteration} input test fields: "
            f"{json.dumps(tests, sort_keys=True)}"
        )
        overrides = [{test["field"]: test["value"]} for test in tests]
        if not overrides:
            append_web_node(
                chal_ID,
                parent_id=get_web_context(chal_ID)["active_node_id"],
                inference=str(plan["hypothesis"]),
                field_vars_to_test=tests,
                responses=[],
                subsequent_steps=[str(plan["fallback"])],
                phase=str(plan["phase"]),
                status="stalled",
            )
            return None

        responses = submit_form(form_schema, values=overrides, session=session)
        if not isinstance(responses, list):
            raise TypeError("Repeated SSTI submission did not return response list")

        response_records = []
        for test, payload, response in zip(tests, overrides, responses):
            observation = analyze_ssti_response(
                payload,
                response.status_code,
                response.text,
                expected_output=test.get("expected_output") if isinstance(test.get("expected_output"), str) else None,
            )
            response_records.append(
                {
                    "field": payload,
                    "status_code": response.status_code,
                    "url": response.url,
                    "text": response.text[:4000],
                    **observation,
                }
            )
        flag = next((extract_flag(response.text) for response in responses), None)
        evidence = [item for record in response_records for item in record["evidence"]]
        append_web_node(
            chal_ID,
            parent_id=get_web_context(chal_ID)["active_node_id"],
            inference=str(plan["hypothesis"]),
            field_vars_to_test=tests,
            responses=response_records,
            subsequent_steps=[str(plan["advance_when"]), str(plan["fallback"])],
            phase=str(plan["phase"]),
            evidence=evidence,
            status="flag_found" if flag else "active",
        )
        if flag:
            return flag
        if has_recent_evidence_stall(chal_ID, MAX_SSTI_NO_PROGRESS_ITERATIONS):
            print(f"[web][SSTI] Stopping after {MAX_SSTI_NO_PROGRESS_ITERATIONS} no-progress iterations.")
            stopped_context = get_web_context(chal_ID)
            stopped_node = stopped_context["nodes"][stopped_context["active_node_id"]]
            stopped_node["status"] = "no_progress"
            upsert_web_node(chal_ID, stopped_node)
            return None
    final_context = get_web_context(chal_ID)
    final_node = final_context["nodes"][final_context["active_node_id"]]
    final_node["status"] = "iteration_limit"
    upsert_web_node(chal_ID, final_node)
    return None


def web_chal_solver(chal_ID: int) -> str | None:
    """Classify a web challenge, then dispatch to its subtype workflow."""
    reset_web_context(chal_ID)
    context = get_context(chal_ID)
    print(f"[web] Challenge {chal_ID} context: {context!r}")
    print(f"[web] Challenge {chal_ID} file path: {get_chal_file_path(chal_ID)!r}")
    subtype = identify_web_subtype(chal_ID)
    print(f"[web] Challenge {chal_ID} subtype: {subtype}")
    if subtype != "SSTI":
        print(f"[web] No workflow is implemented for subtype {subtype}.")
        return None

    try:
        return _solve_ssti(chal_ID)
    except (requests.RequestException, ValueError, TypeError) as exc:
        print(f"[web] Challenge {chal_ID} form workflow failed: {exc}")
    return None   

def main():
    web_chal_solver(19)

if __name__ == "__main__":
    main()
