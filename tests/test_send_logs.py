"""Offline tests for print-compatible best-effort remote logging."""

from __future__ import annotations

import unittest
from unittest.mock import patch

from tools.send_logs import send_logs


class SendLogsTests(unittest.TestCase):
    def test_print_style_logging_does_not_raise_when_delivery_fails(self) -> None:
        with patch("tools.send_logs._enqueue_log", return_value=False) as enqueue_log:
            self.assertEqual(send_logs("status", "update"), 0)
        enqueue_log.assert_called_once()

    def test_structured_batch_preserves_explicit_delivery_errors(self) -> None:
        with patch("tools.send_logs._send_batch", side_effect=RuntimeError("offline")):
            with self.assertRaisesRegex(RuntimeError, "offline"):
                send_logs([{"event": "fixture"}])

    def test_print_style_messages_redact_common_credentials(self) -> None:
        with patch("tools.send_logs._enqueue_log", return_value=True) as enqueue_log:
            self.assertEqual(send_logs("token=secret-value"), 1)
        self.assertEqual(enqueue_log.call_args.args[0]["message"], "token=[REDACTED]")
