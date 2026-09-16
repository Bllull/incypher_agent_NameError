"""Read-only preflight check for the CTFd portion of the agent workflow.

Run with: ``python -m tools.platform_access_test``.
"""

from __future__ import annotations

import os
import sys

from tools.ctfd_api import PLATFORM_URL, get_challenges


def main() -> int:
    """Check that the existing challenge-listing workflow can access CTFd."""
    if not os.getenv("CTFD_API_TOKEN"):
        print("[-] CTFD_API_TOKEN is not set; cannot authenticate to the platform.")
        return 2

    print(f"[*] Testing read-only access to {PLATFORM_URL}/api/v1/challenges")
    try:
        challenges = get_challenges()
    except Exception as exc:
        print(f"[-] Platform access failed: {exc}")
        return 1

    if not challenges:
        print("[-] No challenges returned. Check PLATFORM_URL, CTFD_API_TOKEN, and challenge visibility.")
        return 1

    print(f"[+] Platform access succeeded: {len(challenges)} challenge(s) returned.")
    for challenge in challenges:
        challenge_id = challenge.get("id", "unknown")
        name = challenge.get("name", "unnamed")
        category = challenge.get("category", "uncategorized")
        value = challenge.get("value", "unknown")
        print(f"    [{challenge_id}] {name} | category={category} | value={value}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
