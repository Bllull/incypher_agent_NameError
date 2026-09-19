"""CTFd challenge execution loop and solver delegation."""

from __future__ import annotations

import time

from tools.context import append_context, store_chal_file_path, store_context
from tools.ctfd_api import (
    download_challenge_files,
    extract_challenge_description,
    get_challenges,
    identify_challenge_type,
)
from tools.file_chal import file_chal_solver
from tools.port_chal import port_chal_solver
from tools.web_chal import web_chal_solver


def _delegate(challenge_type: str, chal_ID: int) -> str | None:
    """Pass a prepared challenge to its matching solver and return its flag."""
    if challenge_type == "web":
        return web_chal_solver(chal_ID)
    elif challenge_type == "port":
        return port_chal_solver(chal_ID)
    elif challenge_type == "file":
        return file_chal_solver(chal_ID)
    else:
        raise ValueError(f"Unsupported challenge type: {challenge_type}")


def main() -> None:
    """Process every CTFd challenge until all are delegated or a fatal error occurs."""
    print("[*] Fetching challenge list from CTFd API...")
    try:
        challenges = get_challenges()
    except Exception as exc:
        print(f"[FATAL] Could not retrieve challenges: {exc}")
        return

    if not challenges:
        print("[-] No challenges returned or API token invalid.")
        return

    print(f"[*] Processing {len(challenges)} CTFd challenge(s)...")
    unsolved: list[tuple[str, int, str]] = []
    for challenge in challenges:
        challenge_name = str(challenge.get("name", "unnamed"))
        try:
            chal_ID = int(challenge.get("id"))
        except (TypeError, ValueError):
            print(f"[-] Skipping challenge with invalid ID: {challenge_name}")
            continue

        try:
            description = extract_challenge_description(chal_ID)
            store_context(description, chal_ID)
            challenge_kind = identify_challenge_type(chal_ID)
            challenge_type = {"url": "web", "tcp": "port", "file": "file"}.get(
                challenge_kind
            )
            if challenge_type is None:
                raise ValueError(f"Unsupported challenge type: {challenge_kind}")

            if challenge_kind == "file":
                file_paths = download_challenge_files(challenge_name, chal_ID)
                if file_paths:
                    store_chal_file_path(file_paths[0], chal_ID)
                    if len(file_paths) > 1:
                        append_context(
                            "Additional downloaded files:\n" + "\n".join(file_paths[1:]),
                            chal_ID,
                        )

            print(f"[*] Delegating [{chal_ID}] {challenge_name} as {challenge_type}.")
            if not _delegate(challenge_type, chal_ID):
                unsolved.append((challenge_name, chal_ID, challenge_type))
        except Exception as exc:
            print(f"[FATAL] Challenge [{chal_ID}] {challenge_name} failed: {exc}")
            return

    retry_round = 1
    while unsolved:
        print(f"[*] Unsolved retry round {retry_round}: {len(unsolved)} challenge(s).")
        try:
            remaining: list[tuple[str, int, str]] = []
            for challenge_name, chal_ID, challenge_type in unsolved:
                print(f"[*] Retrying [{chal_ID}] {challenge_name} as {challenge_type}.")
                if not _delegate(challenge_type, chal_ID):
                    remaining.append((challenge_name, chal_ID, challenge_type))
            unsolved = remaining
        except Exception as exc:
            print(f"[FATAL] Unsolved challenge retry failed: {exc}")
            return
        retry_round += 1
        if unsolved:
            time.sleep(1)

    print("[+] All challenges were solved.")


if __name__ == "__main__":
    main()
