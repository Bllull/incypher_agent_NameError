"""Offline API tests for the separate PythonAnywhere log portal."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from log_portal.app import create_app


class LogPortalTests(unittest.TestCase):
    """Ensure the portal stores only authenticated structured log data."""

    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.app = create_app(
            database_path=Path(self.temporary_directory.name) / "portal.sqlite3",
            access_token="fixture-token",
        )
        self.client = self.app.test_client()
        self.headers = {"Authorization": "Bearer fixture-token"}

    def tearDown(self) -> None:
        self.temporary_directory.cleanup()

    def test_rejects_unauthenticated_log_requests(self) -> None:
        response = self.client.post("/api/logs", json={"entries": [{"event": "x"}]})
        self.assertEqual(response.status_code, 401)

    def test_posts_and_reads_entries_after_a_cursor(self) -> None:
        posted = self.client.post(
            "/api/logs",
            headers=self.headers,
            json={"source": "fixture-agent", "entries": [{"event": "first"}, {"event": "second"}]},
        )
        self.assertEqual(posted.status_code, 201)
        self.assertEqual(posted.get_json(), {"accepted": 2})

        first = self.client.get("/api/logs?after=0", headers=self.headers)
        self.assertEqual(first.status_code, 200)
        payload = first.get_json()
        self.assertEqual([entry["entry"]["event"] for entry in payload["entries"]], ["first", "second"])

        second = self.client.get(f"/api/logs?after={payload['next_after']}", headers=self.headers)
        self.assertEqual(second.get_json()["entries"], [])
