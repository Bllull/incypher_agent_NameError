"""Orchestration for URL-based CTF challenges."""

from __future__ import annotations

import json

import requests

from tools.context import get_chal_file_path, get_context
from tools.ctfd_api import get_challenge_url
from tools.http_client import create_session
from tools.llm_router import call_openai
from tools.web_solve_tools.webpage_access_helpers import extract_flag, get_form_json, submit_form
from tools.web_solve_tools.web_context import (
    append_web_node,
    get_web_context,
    pruned_web_context,
    reset_web_context,
    upsert_web_node,
)


WEB_CHALLENGE_SUBTYPES = ("SSTI",)
MAX_SSTI_ITERATIONS = 20
MAX_SSTI_TESTS_PER_ITERATION = 10


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
        answer = call_openai(prompt).strip().upper()
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

    inference = plan.get("inference", "")
    tests = plan.get("field_vars_to_test", [])
    next_steps = plan.get("subsequent_steps", [])
    if not isinstance(inference, str):
        raise ValueError("SSTI plan inference must be a string")
    if not isinstance(tests, list) or not all(isinstance(test, dict) for test in tests):
        raise ValueError("SSTI plan field_vars_to_test must be a list of objects")
    if not isinstance(next_steps, list) or not all(isinstance(step, str) for step in next_steps):
        raise ValueError("SSTI plan subsequent_steps must be a list of strings")

    normalized_tests: list[dict[str, object]] = []
    for test in tests:
        field = test.get("field")
        if not isinstance(field, str) or field not in form_fields:
            raise ValueError(f"SSTI plan references unknown form field: {field!r}")
        if "value" not in test:
            raise ValueError(f"SSTI plan has no value for field: {field}")
        normalized_tests.append({"field": field, "value": test["value"]})
    return {
        "inference": inference,
        "field_vars_to_test": normalized_tests,
        "subsequent_steps": next_steps,
    }


def _ask_for_ssti_plan(chal_ID: int, form_schema: dict[str, object]) -> dict[str, object]:
    """Ask the LLM for the next field/value tests from a pruned branch."""
    challenge_context = get_context(chal_ID) or {}
    workflow_context = pruned_web_context(chal_ID)
    prompt = f"""You are iteratively solving a web CTF challenge.

Use the challenge context, form schema, and compact active reasoning branch to
choose the next field/value submissions to test. Use observed evidence as the
foundation, but allow clearly labeled hypotheses when evidence is incomplete.
Distinguish confirmed observations from speculative inferences. Prefer tests
that distinguish competing hypotheses or maximize information gained. Do not
repeat tests already present in the branch unless there is a clear reason.

Return JSON only, with exactly this shape:
{{
  "inference": "short evidence-based inference",
  "field_vars_to_test": [{{"field": "field_name", "value": "value_to_submit"}}],
  "subsequent_steps": ["short next-step idea"]
}}

The values must be form field names from the schema. Keep the inference and
steps concise; state whether the inference is confirmed or hypothetical. Do
not include hidden chain-of-thought.

Challenge context:
{json.dumps(challenge_context, sort_keys=True)}

Form schema:
{json.dumps(form_schema, sort_keys=True)}

Pruned workflow context:
{json.dumps(workflow_context, sort_keys=True)}
"""
    return _parse_ssti_plan(
        call_openai(prompt, require_deep_reasoning=True),
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
        tests = plan["field_vars_to_test"]
        assert isinstance(tests, list)
        if len(tests) > MAX_SSTI_TESTS_PER_ITERATION:
            print(
                f"[web][SSTI] Iteration {iteration} suggested {len(tests)} tests; "
                f"capping at {MAX_SSTI_TESTS_PER_ITERATION}."
            )
            tests = tests[:MAX_SSTI_TESTS_PER_ITERATION]
            plan["field_vars_to_test"] = tests
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
        print(f"[web][SSTI] Iteration {iteration} test logic: {plan['inference']}")
        print(
            f"[web][SSTI] Iteration {iteration} subsequent steps: "
            f"{json.dumps(plan['subsequent_steps'], sort_keys=True)}"
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
                inference=str(plan["inference"]),
                field_vars_to_test=tests,
                responses=[],
                subsequent_steps=plan["subsequent_steps"],
                status="stalled",
            )
            return None

        responses = submit_form(form_schema, values=overrides, session=session)
        if not isinstance(responses, list):
            raise TypeError("Repeated SSTI submission did not return response list")

        response_records = [
            {
                "field": payload,
                "status_code": response.status_code,
                "url": response.url,
                "text": response.text[:4000],
            }
            for payload, response in zip(overrides, responses)
        ]
        flag = next((extract_flag(response.text) for response in responses), None)
        append_web_node(
            chal_ID,
            parent_id=get_web_context(chal_ID)["active_node_id"],
            inference=str(plan["inference"]),
            field_vars_to_test=tests,
            responses=response_records,
            subsequent_steps=plan["subsequent_steps"],
            status="flag_found" if flag else "active",
        )
        if flag:
            return flag
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
