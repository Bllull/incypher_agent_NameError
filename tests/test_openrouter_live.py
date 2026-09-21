"""Opt-in direct OpenRouter checks for the configured model rotation.

Set both ``OPENROUTER_API_KEY`` and ``RUN_OPENROUTER_LIVE_TESTS=1`` to run
these tests. They make one minimal paid API request per configured model.
"""

from __future__ import annotations

import os
import unittest

from tools.llm_router import OPENROUTER_MODEL_CYCLE, call_openrouter


_LIVE_ENABLED = bool(os.getenv("OPENROUTER_API_KEY")) and os.getenv(
    "RUN_OPENROUTER_LIVE_TESTS"
) == "1"


@unittest.skipUnless(_LIVE_ENABLED, "OpenRouter live tests are opt-in")
class OpenRouterLiveTests(unittest.TestCase):
    """Probe each configured endpoint directly, without SOCLAAS fallback."""

    def test_each_rotation_model_returns_content(self) -> None:
        for model_name in OPENROUTER_MODEL_CYCLE:
            with self.subTest(model=model_name):
                response = call_openrouter(
                    "Reply with exactly OK.", model_name=model_name, max_attempts=1
                )
                self.assertTrue(response)
