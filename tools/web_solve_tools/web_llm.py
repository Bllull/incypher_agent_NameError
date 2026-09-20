"""Resilient LLM calls used only by the web-challenge workflow."""

from __future__ import annotations

import time

from openai import APIConnectionError, APIStatusError

from tools.llm_router import call_openai


WEB_LLM_MAX_ATTEMPTS = 3
_RETRYABLE_STATUS_CODES = {408, 429, 500, 502, 503, 504}


def call_web_llm(prompt: str, *, require_deep_reasoning: bool = False) -> str:
    """Call the shared LLM client with bounded retries for web workflows."""
    for attempt in range(1, WEB_LLM_MAX_ATTEMPTS + 1):
        try:
            return call_openai(prompt, require_deep_reasoning=require_deep_reasoning)
        except APIStatusError as exc:
            if exc.status_code not in _RETRYABLE_STATUS_CODES or attempt == WEB_LLM_MAX_ATTEMPTS:
                raise
        except APIConnectionError:
            if attempt == WEB_LLM_MAX_ATTEMPTS:
                raise

        delay = min(2 ** (attempt - 1), 8)
        print(f"[web][llm] transient gateway failure; retrying in {delay}s ({attempt}/{WEB_LLM_MAX_ATTEMPTS})")
        time.sleep(delay)

    raise RuntimeError("Web LLM retry loop ended unexpectedly")
