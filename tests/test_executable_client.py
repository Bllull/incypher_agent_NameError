"""Tests for the local-only, harmless CTF executable wrapper."""

from __future__ import annotations

import base64
import sys
import unittest
from pathlib import Path

from tools.executable_client import (
    ExecutableClient,
    ExecutableOutputLimitError,
    ExecutableTimeoutError,
    ExecutableValidationError,
    ProcessPolicy,
)


WORKSPACE = Path(__file__).resolve().parents[1]
CHILD = WORKSPACE / "tests" / "fixtures" / "harmless_child.py"


class ExecutableClientTests(unittest.TestCase):
    """Run only a local fixture through the repository virtual environment."""

    def make_client(self, **overrides: object) -> ExecutableClient:
        values: dict[str, object] = {
            "workspace_root": WORKSPACE,
            "allowed_executables": (Path(sys.executable),),
            "max_runtime_seconds": 3.0,
            "max_read_bytes": 64,
            "max_total_output_bytes": 128,
        }
        values.update(overrides)
        return ExecutableClient(ProcessPolicy(**values))  # type: ignore[arg-type]

    def test_safe_fixture_echoes_bounded_line_input(self) -> None:
        client = self.make_client()
        session = client.launch(Path(sys.executable), [str(CHILD), "echo"])
        self.assertEqual(client.receive_line(session, 64, 1), b"challenge prompt\r\n")
        client.send_line(session, b"harmless-ctf-answer")
        self.assertEqual(client.receive_line(session, 64, 1), b"answer:harmless-ctf-answer\r\n")
        client.close(session)

    def test_rejects_executable_outside_workspace_or_allowlist(self) -> None:
        client = self.make_client()
        with self.assertRaises(ExecutableValidationError):
            client.launch(Path("C:/Windows/System32/cmd.exe"))
        with self.assertRaises(ExecutableValidationError):
            client.launch(CHILD)

    def test_rejects_oversized_arguments_and_input(self) -> None:
        client = self.make_client(max_argument_bytes=128, max_input_bytes=3)
        with self.assertRaises(ExecutableValidationError):
            client.launch(Path(sys.executable), ["A" * 129])
        session = client.launch(Path(sys.executable), [str(CHILD), "echo"])
        with self.assertRaises(ExecutableValidationError):
            client.send(session, b"four")
        client.close(session)

    def test_reports_timeout_for_harmless_sleep_fixture(self) -> None:
        client = self.make_client()
        session = client.launch(Path(sys.executable), [str(CHILD), "sleep", "1"])
        with self.assertRaises(ExecutableTimeoutError):
            client.receive(session, 8, 0.05)
        client.close(session)

    def test_timeout_retains_partial_fixture_response_in_error_and_transcript(self) -> None:
        client = self.make_client()
        session = client.launch(Path(sys.executable), [str(CHILD), "partial_sleep", "1"])
        with self.assertRaises(ExecutableTimeoutError) as raised:
            client.receive_until(session, b"!", 16, 0.5)
        self.assertEqual(raised.exception.partial_data, b"partial")
        payloads = [
            base64.b64decode(event["payload_b64"])
            for event in client.get_transcript(session)
        ]
        self.assertIn(b"partial", payloads)
        client.close(session)

    def test_stops_fixture_when_total_output_limit_is_exceeded(self) -> None:
        client = self.make_client(max_total_output_bytes=8, max_read_bytes=32)
        session = client.launch(Path(sys.executable), [str(CHILD), "output", "16"])
        with self.assertRaises(ExecutableOutputLimitError) as raised:
            client.receive(session, 16, 1)
        self.assertEqual(raised.exception.partial_data, b"X" * 16)
        payloads = [
            base64.b64decode(event["payload_b64"])
            for event in client.get_transcript(session)
        ]
        self.assertIn(b"X" * 16, payloads)

    def test_transcript_is_read_only_and_redacts_fixture_secret(self) -> None:
        client = self.make_client(redact_patterns=(b"fixture-secret",))
        session = client.launch(Path(sys.executable), [str(CHILD), "secret"])
        self.assertEqual(client.receive_line(session, 64, 1), b"token=fixture-secret\r\n")
        transcript = client.get_transcript(session)
        self.assertIsInstance(transcript, tuple)
        payloads = [base64.b64decode(event["payload_b64"]) for event in transcript]
        self.assertIn(b"token=[REDACTED]\r\n", payloads)
        client.close(session)


if __name__ == "__main__":
    unittest.main()
