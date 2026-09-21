"""CTFd challenge execution loop and solver delegation."""

from __future__ import annotations

from dataclasses import dataclass
import random
import time
from pathlib import Path

from tools.context import append_context_list, get_context, solver_progress, update_context
from tools.ctfd_api import (
    ChallengeFileDownloadError,
    download_challenge_files,
    get_challenges,
    prepare_challenge_context,
)
from tools.file_chal import file_chal_progress, file_chal_solver
from tools.flags import extract_flag
from tools.port_chal import port_chal_progress, port_chal_solver
from tools.send_logs import send_logs as print
from tools.solver_contract import SolverBinding
from tools.web_chal import web_chal_progress, web_chal_solver


SOLVERS: dict[str, SolverBinding] = {
    "url": SolverBinding(web_chal_solver, web_chal_progress),
    "tcp": SolverBinding(port_chal_solver, port_chal_progress),
    "file": SolverBinding(file_chal_solver, file_chal_progress),
}
PROGRESS_SOURCES = tuple((name, binding.progress) for name, binding in SOLVERS.items())
MAX_BACKOFF_SECONDS = 3_600


@dataclass
class PendingChallenge:
    """A challenge retained until it returns an exact flag."""

    name: str
    chal_id: int
    challenge_type: str | None = None


def _delegate(challenge_type: str, chal_ID: int) -> str | None:
    """Pass a prepared challenge to its matching solver and return its flag."""
    binding = SOLVERS.get(challenge_type)
    if binding is None:
        raise ValueError(f"Unsupported challenge type: {challenge_type}")
    result = binding.solve(chal_ID)
    return extract_flag(result) if result else None


def _solver_progress(chal_id: int) -> str:
    """Query every solver's read-only evidence view for a challenge fingerprint."""
    return solver_progress(chal_id, PROGRESS_SOURCES)


def _next_attempt_at(chal_id: int) -> float:
    context = get_context(chal_id) or {}
    scheduler = context.get("solver_scheduler", {})
    if not isinstance(scheduler, dict):
        return 0.0
    value = scheduler.get("next_attempt_at", 0.0)
    return float(value) if isinstance(value, (int, float)) else 0.0


def _schedule_retry(chal_id: int, *, made_progress: bool) -> None:
    """Persist an unbounded, evidence-gated retry schedule for one challenge."""
    context = get_context(chal_id) or {}
    previous = context.get("solver_scheduler", {})
    previous = previous if isinstance(previous, dict) else {}
    prior_stagnation = previous.get("stagnation_count", 0)
    prior_stagnation = prior_stagnation if isinstance(prior_stagnation, int) else 0
    stagnation_count = 0 if made_progress else prior_stagnation + 1
    base_delay = 1 if made_progress else min(
        MAX_BACKOFF_SECONDS, 2 ** min(stagnation_count, 12)
    )
    jitter = random.uniform(0, min(30, base_delay * 0.1))
    progress_fingerprint = _solver_progress(chal_id)
    update_context(
        {
            "solver_scheduler": {
                "stagnation_count": stagnation_count,
                "next_attempt_at": time.time() + base_delay + jitter,
                "last_progress_fingerprint": progress_fingerprint,
            }
        },
        chal_id,
    )


def _record_challenge_error(chal_id: int, phase: str, error: Exception) -> None:
    """Best-effort error persistence that never stops the scheduler."""
    try:
        append_context_list(
            [{"phase": phase, "error": str(error)}], "solver_errors", chal_id
        )
    except Exception as record_error:
        print(f"[-] Could not persist error for [{chal_id}]: {record_error}")


def _prepare_pending_challenge(challenge: PendingChallenge) -> None:
    """Prepare context and required file assets, retaining partial downloads."""
    context = prepare_challenge_context(challenge.chal_id, challenge.name)
    challenge.name = str(context["name"])
    challenge.challenge_type = str(context["challenge_type"])
    if challenge.challenge_type != "file":
        return

    stored_context = get_context(challenge.chal_id) or context
    file_links = stored_context.get("file_links", [])
    existing_paths = stored_context.get("file_paths", [])
    paths_are_complete = (
        isinstance(file_links, list)
        and isinstance(existing_paths, list)
        and len(existing_paths) == len(file_links)
        and all(isinstance(path, str) and Path(path).is_file() for path in existing_paths)
    )
    if paths_are_complete:
        return
    file_paths = download_challenge_files(challenge.name, challenge.chal_id)
    if not file_paths:
        raise RuntimeError("No challenge files were downloaded")
    update_context({"file_path": file_paths[0], "file_paths": file_paths}, challenge.chal_id)


def _attempt(challenge: PendingChallenge) -> str | None:
    """Run one isolated preparation/delegation attempt and schedule its retry."""
    before = _solver_progress(challenge.chal_id)
    flag: str | None = None
    try:
        if challenge.challenge_type is None or challenge.challenge_type == "file":
            _prepare_pending_challenge(challenge)
        if challenge.challenge_type is None:
            raise RuntimeError("Challenge preparation did not determine a challenge type")
        print(
            f"[*] Delegating [{challenge.chal_id}] {challenge.name} "
            f"as {challenge.challenge_type}."
        )
        flag = _delegate(challenge.challenge_type, challenge.chal_id)
    except ChallengeFileDownloadError as exc:
        _record_challenge_error(challenge.chal_id, "file_download", exc)
        print(f"[-] Challenge [{challenge.chal_id}] file download incomplete: {exc}")
    except Exception as exc:
        _record_challenge_error(challenge.chal_id, "attempt", exc)
        print(f"[-] Challenge [{challenge.chal_id}] {challenge.name} failed: {exc}")

    after = _solver_progress(challenge.chal_id)
    if not flag:
        _schedule_retry(challenge.chal_id, made_progress=before != after)
    return flag


def main() -> None:
    """Process challenges until solved, using unbounded evidence-gated retries."""
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
    unsolved: list[PendingChallenge] = []
    for challenge in challenges:
        challenge_name = str(challenge.get("name", "unnamed"))
        try:
            chal_ID = int(challenge.get("id")) #type: ignore
        except (TypeError, ValueError):
            print(f"[-] Skipping challenge with invalid ID: {challenge_name}")
            continue

        pending = PendingChallenge(challenge_name, chal_ID)
        if not _attempt(pending):
            unsolved.append(pending)

    while unsolved:
        now = time.time()
        remaining: list[PendingChallenge] = []
        for challenge in unsolved:
            if _next_attempt_at(challenge.chal_id) > now:
                remaining.append(challenge)
                continue
            if not _attempt(challenge):
                remaining.append(challenge)
        unsolved = remaining
        if unsolved:
            next_due = min(_next_attempt_at(item.chal_id) for item in unsolved)
            time.sleep(max(0.1, min(60.0, next_due - time.time())))

    print("[+] All challenges were solved.")


if __name__ == "__main__":
    main()
