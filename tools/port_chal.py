"""Solver for TCP challenges hosted by the InCypher hackathon platform."""

from __future__ import annotations

import json
import re

from tools.context import append_context, get_context
from tools.ctfd_api import connect_challenge_tcp
from tools.llm_router import call_openai


_FLAG_PATTERN = re.compile(r"(?:INCYPHER|flag)\{[^\r\n}]+\}", re.IGNORECASE)


def _find_flag(text: str) -> str | None:
    """Return the first flag-shaped value sent by the challenge service."""
    match = _FLAG_PATTERN.search(text)
    return match.group(0) if match else None


def _append_attempt(chal_ID: int, **attempt: str | int) -> None:
    """Store one port-solver attempt as a JSON document in challenge context."""
    append_context(json.dumps(attempt, ensure_ascii=False), chal_ID)


def port_chal_solver(chal_ID: int) -> str | None:
    """Attempt one TCP challenge and return its submitted flag when observed.

    The complete TCP transcript is retained in challenge context when no flag is
    found, so the next invocation can ask the model to improve on this attempt.
    """
    context = get_context(chal_ID) or ""
    challenge_connection = None

    try:
        challenge_connection = connect_challenge_tcp(chal_ID)
        opening_response = challenge_connection.recv(4096).decode(errors="replace")
        opening_flag = _find_flag(opening_response)
        if opening_flag:
            return opening_flag

        commands = call_openai(
            "You are solving an authorized InCypher hackathon TCP challenge. "
            "Based on the challenge description, previous failed-attempt context, "
            "and the service's opening response, produce the command or input to "
            "send next. Return only the exact input, with no Markdown or explanation.\n\n"
            f"Challenge ID: {chal_ID}\n"
            f"Challenge context:\n{context}\n\n"
            f"Service opening response:\n{opening_response}"
        )
        commands = commands.strip()
        if not commands:
            _append_attempt(chal_ID, event="no_command")
            return None

        challenge_connection.sendall((commands + "\n").encode())
        response = challenge_connection.recv(4096).decode(errors="replace")
        flag = _find_flag(response)
        if flag:
            return flag

        _append_attempt(
            chal_ID,
            event="unsolved",
            opening_response=opening_response,
            commands=commands,
            response=response,
        )
        return None
    except Exception as exc:
        _append_attempt(chal_ID, event="error", error=str(exc))
        print(f"[port] Challenge {chal_ID} could not be solved: {exc}")
        return None
    finally:
        if challenge_connection is not None:
            challenge_connection.close()
