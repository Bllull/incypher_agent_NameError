"""Offline tests for the file-challenge category delegator."""

from __future__ import annotations

import unittest
from pathlib import Path
import hashlib
from unittest.mock import Mock, patch

from tools import file_chal


class FileChallengeDelegationTests(unittest.TestCase):
    """Ensure every supported category selects only its specialist handler."""

    def test_category_aliases_cover_the_supported_file_solvers(self) -> None:
        self.assertEqual(file_chal.CATEGORY_ALIASES["pwn"], "pwn")
        self.assertEqual(file_chal.CATEGORY_ALIASES["re"], "rev")
        self.assertEqual(file_chal.CATEGORY_ALIASES["reverseengineering"], "rev")
        self.assertEqual(file_chal.CATEGORY_ALIASES["forensic"], "forensics")
        self.assertEqual(file_chal.CATEGORY_ALIASES["crypto"], "cryptography")
        self.assertEqual(file_chal.CATEGORY_ALIASES["practicepwn"], "pwn")
        self.assertEqual(file_chal.CATEGORY_ALIASES["practicerev"], "rev")
        self.assertEqual(file_chal.CATEGORY_ALIASES["practiceforensics"], "forensics")
        self.assertEqual(file_chal.CATEGORY_ALIASES["practicecryptography"], "cryptography")

    @patch("tools.file_chal.get_context")
    def test_delegates_to_the_matching_specialist(self, get_context) -> None:
        context = {"category": "Reverse Engineering", "file_paths": []}
        get_context.return_value = context
        handler = Mock(return_value="INCYPHER{harmless_fixture}")
        with patch.dict(file_chal.FILE_SOLVERS, {"rev": handler}):
            result = file_chal.file_chal_solver(55)
        self.assertEqual(result, "INCYPHER{harmless_fixture}")
        handler.assert_called_once_with(55, context)

    @patch("tools.file_chal.append_context_list")
    @patch("tools.file_chal.get_context", return_value={"category": "misc"})
    def test_unsupported_category_stays_unsolved(self, _get_context, append_attempt) -> None:
        self.assertIsNone(file_chal.file_chal_solver(56))
        append_attempt.assert_called_once()

    @patch("tools.file_chal.append_context_list")
    @patch("tools.file_chal.get_context", return_value={"category": "pwn", "file_paths": []})
    def test_unimplemented_specialist_never_returns_a_synthetic_flag(
        self, _get_context, append_attempt
    ) -> None:
        self.assertIsNone(file_chal.file_chal_solver(57))
        append_attempt.assert_called_once()

    def test_static_reconnaissance_finds_a_flag_location_without_execution(self) -> None:
        fixture = Path(__file__).parent / "fixtures" / "rev_static_fixture.bin"
        finding, flag = file_chal._reconnaissance(fixture)
        self.assertEqual(flag, "INCYPHER{static_fixture}")
        self.assertGreaterEqual(finding["flag_locations"][0]["offset"], 0)

    @patch("tools.file_chal.append_context_list")
    @patch("tools.file_chal._challenge_paths")
    @patch("tools.file_chal.get_context")
    def test_rev_delegator_returns_a_static_flag_before_dynamic_probing(
        self, get_context, paths, append_attempt
    ) -> None:
        fixture = Path(__file__).parent / "fixtures" / "rev_static_fixture.bin"
        get_context.return_value = {"category": "rev", "file_paths": [str(fixture)]}
        paths.return_value = [fixture]
        self.assertEqual(file_chal.file_chal_solver(58), "INCYPHER{static_fixture}")
        self.assertEqual(append_attempt.call_count, 3)

    @patch("tools.file_chal.append_context_list")
    @patch("tools.file_chal._probe_executable", return_value=([{"response": "no flag"}], None))
    @patch("tools.file_chal._is_locally_executable", return_value=True)
    @patch("tools.file_chal._reconnaissance", return_value=({"format": "PE"}, None))
    @patch("tools.file_chal._challenge_paths")
    @patch("tools.file_chal.get_context")
    def test_rev_delegator_records_harmless_dynamic_probe_observations(
        self, get_context, paths, _recon, _executable, probe, append_attempt
    ) -> None:
        fixture = Path(__file__).parent / "fixtures" / "rev_static_fixture.bin"
        get_context.return_value = {"category": "rev", "file_paths": [str(fixture)]}
        paths.return_value = [fixture]
        self.assertIsNone(file_chal.file_chal_solver(59))
        self.assertEqual(probe.call_count, file_chal.REV_SOLVER_MAX_PASSES)
        probe.assert_called_with(fixture)
        self.assertEqual(append_attempt.call_count, 3 * file_chal.REV_SOLVER_MAX_PASSES + 2)

    def test_xor_key_and_byte_hash_rainbow_helpers_are_bounded(self) -> None:
        self.assertEqual(file_chal.derive_xor_key(b"\x11\x22", b"\x10\x20"), b"\x01\x02")
        table = file_chal.build_byte_hash_rainbow_table("sha256")
        self.assertEqual(table[hashlib.sha256(b"A").hexdigest()], ord("A"))
        self.assertEqual(len(table), 256)

    def test_exploit_triage_requires_evidence_before_active_probes(self) -> None:
        triage = file_chal._exploit_triage(
            Path("harmless.bin"),
            {
                "strings": ["gets", "printf", "sha256", "xor"],
                "protections": {
                    "canary": True,
                    "pie": True,
                    "canary_symbols": {"__stack_chk_fail": 1},
                    "pie_relative_offsets": {"main": 2},
                    "decryption_candidates": {"decrypt": 3},
                },
            },
        )
        self.assertTrue(triage["overflow_probe_eligible"])
        self.assertTrue(triage["format_probe_eligible"])
        self.assertEqual(triage["canary_symbols"], {"__stack_chk_fail": 1})
        self.assertIn("requires_opt_in_debugger", triage["decryption_breakpoint_plan"]["status"])


if __name__ == "__main__":
    unittest.main()
