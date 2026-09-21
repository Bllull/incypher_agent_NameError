"""Offline tests for the file solver's internal tool/evidence loop."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from tools import context
from tools.context import get_context, store_context
from tools.file_solve_tools import FileToolResult
from tools.file_chal import file_chal_progress, file_chal_solver


class FileChallengeSolverTests(unittest.TestCase):
    """Ensure tool evidence is durable before the next LLM decision."""

    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary_directory.name)
        self.database_patch = patch.object(context, "CONTEXT_DB_PATH", self.root / "context.sqlite3")
        self.database_patch.start()
        self.artifact = self.root / "challenge.txt"
        self.artifact.write_text("offline fixture", encoding="utf-8")
        store_context({"file_path": str(self.artifact), "file_paths": [str(self.artifact)]}, 77)

    def tearDown(self) -> None:
        self.database_patch.stop()
        self.temporary_directory.cleanup()

    def test_tool_outputs_are_persisted_and_fed_into_the_next_turn(self) -> None:
        action = json.dumps(
            {
                "hypothesis": "Inspect the supplied local artifact first.",
                "action": {"tool": "inspect", "artifact_path": str(self.artifact), "arguments": {}},
            }
        )
        first = FileToolResult("inspect", str(self.artifact), "ok", {"text_preview": "no flag"})
        second = FileToolResult(
            "inspect",
            str(self.artifact),
            "ok",
            {"text_preview": "INCYPHER{offline_file_tool_test}"},
            flag="INCYPHER{offline_file_tool_test}",
        )
        prompts: list[str] = []

        def remember_prompt(prompt: str, **_kwargs: object) -> str:
            prompts.append(prompt)
            return action

        with patch("tools.file_chal.call_openai", side_effect=remember_prompt), patch(
            "tools.file_chal.execute_file_tool", side_effect=[first, second]
        ):
            self.assertEqual(file_chal_solver(77), "INCYPHER{offline_file_tool_test}")

        stored = get_context(77)
        self.assertIsNotNone(stored)
        self.assertEqual(len(stored["file_tool_results"]), 2)  # type: ignore[index]
        self.assertIn("no flag", prompts[1])
        self.assertEqual(file_chal_progress(77)["file_solver_state"]["last_tool"], "inspect")  # type: ignore[index]


if __name__ == "__main__":
    unittest.main()
