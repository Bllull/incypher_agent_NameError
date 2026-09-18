"""Connectivity, description, and challenge-file preflight for the agent workflow.

Run with: ``python -m tools.preflight``.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

from openai import OpenAI

import tools.config  # Load repository-local credentials before reading them.
from tools.ctfd_api import (
    PLATFORM_URL,
    download_challenge_files,
    extract_challenge_description,
    get_challenges,
)


def check_soclaas_connection() -> bool:
    """Verify the OpenAI-compatible gateway credentials without invoking a model."""
    api_key = os.getenv("SOCLAAS_API_KEY")
    base_url = os.getenv("SOCLAAS_BASE_URL")
    if not api_key or not base_url:
        print("[-] SOCLAAS_API_KEY or SOCLAAS_BASE_URL is not set.")
        return False

    print(f"[*] Testing SoClass API access at {base_url}")
    try:
        OpenAI(api_key=api_key, base_url=base_url).models.list()
    except Exception as exc:
        print(f"[-] SoClass API access failed: {exc}")
        return False

    print("[+] SoClass API access succeeded.")
    return True


def check_challenge_description_retrieval(challenges: list[dict]) -> bool:
    """Verify that at least one CTFd ``data.description`` value is retrieved."""
    print("[*] Looking for a challenge description to verify retrieval...")
    for challenge in challenges:
        challenge_name = str(challenge.get("name", "unnamed"))
        try:
            challenge_id = int(challenge.get("id"))
        except (TypeError, ValueError) as exc:
            print(f"[-] Skipping challenge with invalid details: {challenge_name}: {exc}")
            continue
        except Exception as exc:
            print(f"[-] Could not retrieve details for {challenge_name}: {exc}")
            continue

        try:
            description = extract_challenge_description(challenge_id)
        except Exception as exc:
            print(f"[-] Could not retrieve description for {challenge_name}: {exc}")
            continue
        if description:
            print(
                f"[+] Challenge description retrieval succeeded for "
                f"[{challenge_id}] {challenge_name}: {len(description)} character(s)."
            )
            return True

    print("[-] No non-empty CTFd data.description value was available to verify.")
    return False


def check_challenge_file_download(challenges: list[dict]) -> bool:
    """Verify challenge-file downloading against the first available file asset.

    Challenges without API ``files`` links are skipped. A platform with no file
    challenges is still a successful preflight, because there is no file asset
    available to test.
    """
    print("[*] Looking for a challenge file to verify downloading...")
    for challenge in challenges:
        challenge_name = str(challenge.get("name", "unnamed"))
        try:
            challenge_id = int(challenge.get("id"))
        except (TypeError, ValueError) as exc:
            print(f"[-] Skipping challenge with invalid details: {challenge_name}: {exc}")
            continue
        except Exception as exc:
            print(f"[-] Could not retrieve details for {challenge_name}: {exc}")
            continue

        try:
            downloaded_paths = download_challenge_files(challenge_name, challenge_id)
        except Exception as exc:
            print(f"[-] Challenge file download failed for [{challenge_id}] {challenge_name}: {exc}")
            return False

        if not downloaded_paths:
            continue
        missing_paths = [path for path in downloaded_paths if not Path(path).is_file()]
        if missing_paths:
            print(f"[-] Download reported missing file(s): {', '.join(missing_paths)}")
            return False
        print(
            f"[+] Challenge file download succeeded for [{challenge_id}] "
            f"{challenge_name}: {len(downloaded_paths)} file(s)."
        )
        return True

    print("[+] No challenge files were available to test; skipping download verification.")
    return True


def main() -> int:
    """Validate API connectivity, challenge listing, descriptions, and files."""
    if not check_soclaas_connection():
        return 2

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

    if not check_challenge_description_retrieval(challenges):
        return 1
    if not check_challenge_file_download(challenges):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
