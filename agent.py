"""CTFd challenge discovery entry point.

The delegator will later classify and dispatch challenges. For now it only
retrieves the challenge list, each challenge's detail record, and its URL.
"""

from __future__ import annotations

from tools.ctfd_api import (
    connect_challenge_url,
    extract_challenge_description,
    get_challenges,
)


def main() -> None:
    """List CTFd challenges and retrieve their details and challenge URLs."""
    print("[*] Fetching challenge list from CTFd API...")
    challenges = get_challenges()
    if not challenges:
        print("[-] No challenges returned or API token invalid.")
        return

    print(f"[*] Retrieving details for {len(challenges)} CTFd challenge(s)...")
    for challenge in challenges:
        raw_challenge_id = challenge.get("id")
        challenge_name = str(challenge.get("name", "unnamed"))
        try:
            challenge_id = int(raw_challenge_id)
        except (TypeError, ValueError):
            print(f"[-] Skipping challenge with invalid ID: {challenge_name}")
            continue

        try:
            description = extract_challenge_description(challenge_id)
        except Exception as exc:
            print(f"[-] Could not retrieve details for [{challenge_id}] {challenge_name}: {exc}")
            continue
        page_url = connect_challenge_url(challenge_name, challenge_id)
        print(f"[+] [{challenge_id}] {challenge_name} | page={page_url}")
        print(f"    Description: {description or '(none)'}")


if __name__ == "__main__":
    main()
