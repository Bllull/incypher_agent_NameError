"""Persistent JSON context storage for CTF challenges."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any


CONTEXT_DB_PATH = (
    Path(__file__).resolve().parent.parent / ".agent_data" / "challenge_contexts.sqlite3"
)
Context = dict[str, Any]


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


def _connect() -> sqlite3.Connection:
    """Open the local context database and ensure its JSON schema exists."""
    CONTEXT_DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(CONTEXT_DB_PATH)
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
    return connection


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
