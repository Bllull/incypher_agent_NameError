"""Persistent JSON context storage for CTF challenges."""

from __future__ import annotations

import json
import os
import sqlite3
from hashlib import sha256
from collections.abc import Callable, Iterable, Mapping
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator


_WORK_ROOT = Path(os.getenv("IN_CYPHER_WORK_DIR", "/work"))
if not _WORK_ROOT.is_dir() or not os.access(_WORK_ROOT, os.W_OK):
    _WORK_ROOT = Path(__file__).resolve().parent.parent / ".agent_data"
CONTEXT_DB_PATH = _WORK_ROOT / "challenge_contexts.sqlite3"
Context = dict[str, Any]
_NON_PROGRESS_FIELDS = {
    "solver_scheduler",
    "solver_errors",
    "port_attempts",
    "file_download_errors",
    "file_solver_attempts",
    # These narrate or count attempts; they are not new solver evidence.
    "rev_solver_passes",
    "rev_attempt_summaries",
    "rev_probe_ledger",
}


def _validate_challenge_id(chal_ID: int) -> int:
    """Return an integer challenge ID, including negative shared-context IDs."""
    if isinstance(chal_ID, bool) or not isinstance(chal_ID, int):
        raise ValueError("chal_ID must be an integer")
    return chal_ID


def _validate_context(context: Context) -> Context:
    """Ensure context is a JSON-serializable dictionary."""
    if not isinstance(context, dict):
        raise TypeError("context must be a dictionary")
    try:
        json.dumps(context)
    except (TypeError, ValueError) as exc:
        raise TypeError("context must contain JSON-serializable values") from exc
    return context


@contextmanager
def _connect() -> Iterator[sqlite3.Connection]:
    """Open the local context database and ensure its JSON schema exists."""
    CONTEXT_DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(CONTEXT_DB_PATH)
    try:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS challenge_contexts (
                challenge_id INTEGER PRIMARY KEY,
                context_json TEXT NOT NULL DEFAULT '{}',
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
        yield connection
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def store_context(context: Context, chal_ID: int) -> None:
    """Create or replace a challenge's complete JSON context."""
    challenge_id = _validate_challenge_id(chal_ID)
    value = _validate_context(context)
    with _connect() as connection:
        connection.execute(
            """
            INSERT INTO challenge_contexts (challenge_id, context_json)
            VALUES (?, ?)
            ON CONFLICT(challenge_id) DO UPDATE SET
                context_json = excluded.context_json,
                updated_at = CURRENT_TIMESTAMP
            """,
            (challenge_id, json.dumps(value, sort_keys=True)),
        )


def get_context(chal_ID: int) -> Context | None:
    """Return a challenge's JSON context, or ``None`` when it is absent."""
    challenge_id = _validate_challenge_id(chal_ID)
    with _connect() as connection:
        row = connection.execute(
            "SELECT context_json FROM challenge_contexts WHERE challenge_id = ?",
            (challenge_id,),
        ).fetchone()
    if row is None:
        return None

    value = json.loads(row[0])
    if not isinstance(value, dict):
        raise ValueError(f"Stored context for challenge {challenge_id} is not a dictionary")
    return value


def update_context(context: Context, chal_ID: int) -> None:
    """Merge JSON fields into a challenge context, replacing matching keys."""
    challenge_id = _validate_challenge_id(chal_ID)
    updates = _validate_context(context)
    with _connect() as connection:
        connection.execute("BEGIN IMMEDIATE")
        row = connection.execute(
            "SELECT context_json FROM challenge_contexts WHERE challenge_id = ?",
            (challenge_id,),
        ).fetchone()
        current = {} if row is None else json.loads(row[0])
        if not isinstance(current, dict):
            raise ValueError(f"Stored context for challenge {challenge_id} is not a dictionary")
        current.update(updates)
        connection.execute(
            """
            INSERT INTO challenge_contexts (challenge_id, context_json)
            VALUES (?, ?)
            ON CONFLICT(challenge_id) DO UPDATE SET
                context_json = excluded.context_json,
                updated_at = CURRENT_TIMESTAMP
            """,
            (challenge_id, json.dumps(current, sort_keys=True)),
        )


def deterministic_progress_evidence(context: Mapping[str, Any]) -> dict[str, Any]:
    """Return only durable evidence suitable for retry-progress comparison.

    Attempt counters, scheduler state, errors, and prose summaries can change
    while a solver repeats identical work.  Excluding them makes progress a
    reproducible function of artifacts and concrete solver observations.
    """
    return {
        key: value
        for key, value in context.items()
        if key not in _NON_PROGRESS_FIELDS
    }


def solver_progress(
    chal_ID: int,
    progress_sources: Iterable[tuple[str, Callable[[int], Mapping[str, Any]]]] = (),
) -> str:
    """Return a stable fingerprint of durable solver evidence for one challenge.

    Each registered solver is queried through its read-only progress source.
    This intentionally ignores scheduler bookkeeping, errors, and repeated TCP
    attempt logs. A failing progress source is excluded so observability cannot
    stop the challenge loop.
    """
    challenge_id = _validate_challenge_id(chal_ID)
    context = get_context(challenge_id) or {}
    evidence = deterministic_progress_evidence(context)
    solver_evidence: dict[str, Mapping[str, Any]] = {}
    for source_name, source in progress_sources:
        try:
            snapshot = source(challenge_id)
        except Exception:
            continue
        if isinstance(snapshot, Mapping):
            solver_evidence[source_name] = deterministic_progress_evidence(snapshot)
    evidence["solver_evidence"] = solver_evidence
    canonical = json.dumps(evidence, sort_keys=True, separators=(",", ":"), default=str)
    return f"sha256:{sha256(canonical.encode('utf-8')).hexdigest()}"


def append_context_list(
    values: list[Any],
    field: str,
    chal_ID: int,
    *,
    unique: bool = False,
) -> None:
    """Atomically append JSON values to a list field in challenge context."""
    challenge_id = _validate_challenge_id(chal_ID)
    if not isinstance(field, str) or not field.strip():
        raise ValueError("field must be a non-empty string")
    try:
        json.dumps(values)
    except (TypeError, ValueError) as exc:
        raise TypeError("values must contain JSON-serializable items") from exc

    with _connect() as connection:
        connection.execute("BEGIN IMMEDIATE")
        row = connection.execute(
            "SELECT context_json FROM challenge_contexts WHERE challenge_id = ?",
            (challenge_id,),
        ).fetchone()
        current = {} if row is None else json.loads(row[0])
        if not isinstance(current, dict):
            raise ValueError(f"Stored context for challenge {challenge_id} is not a dictionary")

        existing = current.get(field, [])
        if not isinstance(existing, list):
            raise ValueError(f"Context field {field!r} is not a list")
        for value in values:
            if not unique or value not in existing:
                existing.append(value)
        current[field] = existing

        connection.execute(
            """
            INSERT INTO challenge_contexts (challenge_id, context_json)
            VALUES (?, ?)
            ON CONFLICT(challenge_id) DO UPDATE SET
                context_json = excluded.context_json,
                updated_at = CURRENT_TIMESTAMP
            """,
            (challenge_id, json.dumps(current, sort_keys=True)),
        )


def store_artifact_paths(filepaths: list[str], chal_ID: int) -> None:
    """Record unique generated artifact paths in challenge context."""
    if not isinstance(filepaths, list) or not all(
        isinstance(filepath, str) and filepath.strip() for filepath in filepaths
    ):
        raise ValueError("filepaths must be a list of non-empty strings")
    append_context_list(filepaths, "converted_file_paths", chal_ID, unique=True)


def delete_context(chal_ID: int) -> None:
    """Delete the complete JSON context for one challenge ID, if it exists."""
    challenge_id = _validate_challenge_id(chal_ID)
    with _connect() as connection:
        connection.execute(
            "DELETE FROM challenge_contexts WHERE challenge_id = ?",
            (challenge_id,),
        )


def store_name(name: str, chal_ID: int) -> None:
    """Store the challenge name under the JSON ``name`` field."""
    if not isinstance(name, str) or not name.strip():
        raise ValueError("name must be a non-empty string")
    update_context({"name": name}, chal_ID)


def get_name(chal_ID: int) -> str | None:
    """Return the stored challenge name, when present."""
    context = get_context(chal_ID)
    name = context.get("name") if context else None
    return name if isinstance(name, str) else None


def store_chal_file_path(filepath: str, chal_ID: int) -> None:
    """Store the primary local challenge-file path in JSON context."""
    if not isinstance(filepath, str) or not filepath.strip():
        raise ValueError("filepath must be a non-empty string")
    update_context({"file_path": filepath}, chal_ID)


def get_chal_file_path(chal_ID: int) -> str | None:
    """Return the primary local challenge-file path, when present."""
    context = get_context(chal_ID)
    filepath = context.get("file_path") if context else None
    return filepath if isinstance(filepath, str) else None
