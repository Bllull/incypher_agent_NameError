"""Offline tests for non-interactive URL challenge deployment."""

from __future__ import annotations

import unittest
from unittest.mock import patch

from tools.ctfd_api import ChallengeDeploymentError, get_challenge_url


class ChallengeUrlDeploymentTests(unittest.TestCase):
    """The autonomous agent must never block on manual URL input."""

    @patch("tools.ctfd_api.update_context")
    @patch("tools.ctfd_api.deploy_instance", return_value={"url": "https://instance.ctf.test/"})
    @patch("tools.ctfd_api._docker_platform_available", return_value=True)
    @patch("tools.ctfd_api._stored_challenge_context", return_value={"name": "Harmless"})
    def test_deploys_and_persists_a_platform_url(
        self, _context, _available, deploy, update
    ) -> None:
        self.assertEqual(get_challenge_url(71), "https://instance.ctf.test/")
        deploy.assert_called_once_with(71)
        update.assert_called_once_with({"challenge_url": "https://instance.ctf.test/"}, 71)

    @patch("tools.ctfd_api._docker_platform_available", return_value=False)
    @patch("tools.ctfd_api._stored_challenge_context", return_value={"name": "Harmless"})
    def test_never_prompts_for_manual_deployment_when_unavailable(
        self, _context, _available
    ) -> None:
        with patch("builtins.input") as prompt, self.assertRaises(ChallengeDeploymentError):
            get_challenge_url(72)
        prompt.assert_not_called()

    @patch("tools.ctfd_api.deploy_instance", return_value={"connection_url": "tcp://wrong"})
    @patch("tools.ctfd_api._docker_platform_available", return_value=True)
    @patch("tools.ctfd_api._stored_challenge_context", return_value={"name": "Harmless"})
    def test_rejects_non_http_deployment_targets(self, _context, _available, _deploy) -> None:
        with self.assertRaises(ChallengeDeploymentError):
            get_challenge_url(73)


if __name__ == "__main__":
    unittest.main()
