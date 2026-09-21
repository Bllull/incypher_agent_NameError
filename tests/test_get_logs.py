"""Tests for the cursor-based log listener without a live portal."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from tools.get_logs import format_log_entry, listen_for_logs


class GetLogsListenerTests(unittest.TestCase):
    def test_one_shot_listener_prints_and_persists_next_cursor(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            cursor_path = Path(directory) / "cursor.json"
            payload = {"entries": [{"id": 9, "message": "hello"}], "next_after": 9}
            with (
                patch("tools.get_logs.get_new_logs", return_value=payload),
                patch("builtins.print") as output,
            ):
                result = listen_for_logs(
                    after=0,
                    cursor_path=cursor_path,
                    once=True,
                )

            self.assertEqual(result, 0)
            self.assertEqual(json.loads(cursor_path.read_text(encoding="utf-8")), {"after": 9})
            self.assertEqual(output.call_count, 3)
            self.assertEqual(
                output.call_args_list[-1].args[0],
                "unknown                          |        9 | unknown                  | null",
            )

    def test_format_log_entry_displays_metadata_and_plain_message(self) -> None:
        self.assertEqual(
            format_log_entry(
                {
                    "id": 9,
                    "received_at": "2026-09-22T10:00:00+00:00",
                    "source": "incypher-agent",
                    "entry": {"message": "solver started"},
                }
            ),
            "2026-09-22T10:00:00+00:00        |        9 | incypher-agent           | solver started",
        )


if __name__ == "__main__":
    unittest.main()
