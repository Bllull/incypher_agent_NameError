"""CTFd challenge execution loop and solver delegation."""

from __future__ import annotations

from collections.abc import Callable
import time

from tools.context import update_context
from tools.ctfd_api import (
    download_challenge_files,
    get_challenges,
    prepare_challenge_context,
)
from tools.file_chal import file_chal_solver
from tools.flags import extract_flag
from tools.port_chal import port_chal_solver
from tools.web_chal import web_chal_solver


Solver = Callable[[int], str | None]
SOLVERS: dict[str, Solver] = {
    "url": web_chal_solver,
    "tcp": port_chal_solver,
    "file": file_chal_solver,
}


def _delegate(challenge_type: str, chal_ID: int) -> str | None:
    """Pass a prepared challenge to its matching solver and return its flag."""
    solver = SOLVERS.get(challenge_type)
    if solver is None:
        raise ValueError(f"Unsupported challenge type: {challenge_type}")
    result = solver(chal_ID)
    return extract_flag(result) if result else None


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
            chal_ID = int(challenge.get("id")) #type: ignore
        except (TypeError, ValueError):
            print(f"[-] Skipping challenge with invalid ID: {challenge_name}")
            continue

        try:
            context = prepare_challenge_context(chal_ID, challenge_name)
            challenge_name = str(context["name"])
            challenge_kind = str(context["challenge_type"])

            if challenge_kind == "file":
                file_paths = download_challenge_files(challenge_name, chal_ID)
                if file_paths:
                    update_context(
                        {"file_path": file_paths[0], "file_paths": file_paths}, chal_ID
                    )

            print(f"[*] Delegating [{chal_ID}] {challenge_name} as {challenge_kind}.")
            if not _delegate(challenge_kind, chal_ID):
                unsolved.append((challenge_name, chal_ID, challenge_kind))
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
