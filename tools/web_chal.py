"""Orchestration for URL-based CTF challenges."""

from __future__ import annotations

import json
from collections.abc import Sequence

import requests

from tools.context import append_context, get_chal_file_path, get_context
from tools.ctfd_api import get_challenge_url
from tools.http_client import create_session
from tools.llm_router import call_openai
from tools.web_solve_tools.webpage_access_helpers import extract_flag, get_form_json, submit_form


WEB_CHALLENGE_SUBTYPES = ("SSTI",)
# Temporary compatibility probes. The solver accepts a runtime probe list so
# a later LLM iteration can supply these without changing the submit/store
# workflow.
DEFAULT_SSTI_PROBES = ("{{7*7}}", "${7*7}", "<%= 7*7 %>")
# Reserved context record for data produced by the web-solving workflow.
WEB_CONTEXT_ID = -1000


def identify_web_subtype(chal_ID: int) -> str:
    """Classify a web challenge from its stored context using the configured LLM.

    The returned value is always one of ``WEB_CHALLENGE_SUBTYPES`` or
    ``"UNKNOWN"``. Keeping the output constrained makes it safe for the
    dispatcher to grow with additional subtype-specific workflows later.
    """
    challenge_context = get_context(chal_ID) or ""
    web_context = get_context(WEB_CONTEXT_ID) or ""
    prompt = f"""You are classifying a web CTF challenge for a workflow dispatcher.

Read the challenge context below and identify its subtype. The only currently
supported subtype is SSTI (server-side template injection). Return exactly one
token: SSTI if the context indicates an SSTI challenge; otherwise return
UNKNOWN. Do not explain your answer.

Challenge ID: {chal_ID}
Challenge context:
{challenge_context}

Previously collected web workflow context:
{web_context}
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


def _solve_ssti(
    chal_ID: int,
) -> str | None:
    """Submit supplied SSTI probes and retain the response list.

    Probe selection belongs inside this subtype workflow. The current default
    keeps the existing behavior until the LLM probe-selection step is added.
    """
    # Replace this local selection with the future LLM interaction. Keeping it
    # here ensures the dispatcher remains independent of SSTI details.
    probes = DEFAULT_SSTI_PROBES

    challenge_context = get_context(chal_ID) or ""
    web_context = get_context(WEB_CONTEXT_ID) or ""
    context = "\n\n".join(
        part for part in (challenge_context, web_context) if part
    )
    challenge_url = get_challenge_url(chal_ID)
    session = create_session()
    form_schema = get_form_json(
        challenge_url,
        context=context,
        session=session,
        chal_ID=chal_ID,
    )
    print(f"[web][SSTI] Form schema: {json.dumps(form_schema, sort_keys=True)}")
    fields = form_schema.get("fields", {})
    if not isinstance(fields, dict) or not fields:
        raise ValueError("The validated SSTI form contains no fields")

    overrides = [
        {field_name: probe}
        for field_name in fields
        for probe in probes
    ]
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
    append_context(
        "[SSTI_RESPONSES]\n" + json.dumps(response_records, sort_keys=True),
        WEB_CONTEXT_ID,
    )
    for response in responses:
        flag = extract_flag(response.text)
        if flag:
            return flag
    return None


def web_chal_solver(chal_ID: int) -> str | None:
    """Classify a web challenge, then dispatch to its subtype workflow."""
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

# def main():
#     web_chal_solver(19)

# if __name__ == "__main__":
#     main()
