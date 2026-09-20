"""Offline regression tests for shared orchestration helpers."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

import tools.context as context_store
import tools.ctfd_api as ctfd_api
import tools.llm_router as llm_router
from tools.flags import extract_flag


class CoreRefactorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary_directory.name)
        self.context_path_patch = patch.object(
            context_store, "CONTEXT_DB_PATH", self.root / "contexts.sqlite3"
        )
        self.context_path_patch.start()

    def tearDown(self) -> None:
        self.context_path_patch.stop()
        self.temporary_directory.cleanup()

    def test_exact_flag_format(self) -> None:
        self.assertEqual(extract_flag("result: INCYPHER{valid}"), "INCYPHER{valid}")
        self.assertIsNone(extract_flag("flag{wrong}"))
        self.assertIsNone(extract_flag("incypher{wrong_case}"))

    def test_atomic_context_list_and_unique_artifacts(self) -> None:
        context_store.store_context({"name": "Demo"}, 1)
        context_store.append_context_list([{"event": "one"}], "attempts", 1)
        context_store.append_context_list([{"event": "two"}], "attempts", 1)
        context_store.store_artifact_paths(["one.png", "one.png"], 1)

        self.assertEqual(
            context_store.get_context(1),
            {
                "name": "Demo",
                "attempts": [{"event": "one"}, {"event": "two"}],
                "converted_file_paths": ["one.png"],
            },
        )

    def test_prepare_fetches_details_once_and_download_uses_context(self) -> None:
        fake_client = Mock()
        fake_client.challenge_details.return_value = {
            "name": "Demo",
            "description": "Download the asset",
            "files": ["/files/demo.txt"],
        }
        fake_client.download.return_value = b"test data"

        with (
            patch.object(ctfd_api, "_client", fake_client),
            patch.object(ctfd_api, "CHALLENGE_DOWNLOAD_DIR", self.root / "files"),
        ):
            prepared = ctfd_api.prepare_challenge_context(7)
            paths = ctfd_api.download_challenge_files("Demo", 7)

        fake_client.challenge_details.assert_called_once_with(7)
        self.assertEqual(prepared["challenge_type"], "file")
        self.assertEqual(Path(paths[0]).read_bytes(), b"test data")

    def test_submit_rejects_non_incypher_flag(self) -> None:
        fake_client = Mock()
        fake_client.submit.return_value = {"success": True}
        with patch.object(ctfd_api, "_client", fake_client):
            self.assertEqual(
                ctfd_api.submit_flag(4, " INCYPHER{valid} "), {"success": True}
            )
            with self.assertRaises(ValueError):
                ctfd_api.submit_flag(4, "flag{invalid}")
        fake_client.submit.assert_called_once_with(4, "INCYPHER{valid}")

    def test_model_listing_uses_shared_client(self) -> None:
        fake_client = SimpleNamespace(
            models=SimpleNamespace(
                list=lambda: SimpleNamespace(data=[SimpleNamespace(id="default")])
            )
        )
        with patch.object(llm_router, "client", fake_client):
            self.assertEqual(
                llm_router.list_openai_models(max_attempts=1), ["default"]
            )


if __name__ == "__main__":
    unittest.main()
