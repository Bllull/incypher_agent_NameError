"""Persistent retrieval-augmented context storage for CTF challenges."""

from __future__ import annotations

import sqlite3
from pathlib import Path


CONTEXT_DB_PATH = (
    Path(__file__).resolve().parent.parent / ".agent_data" / "challenge_contexts.sqlite3"
)


def _validate_challenge_id(chal_ID: int) -> int:
    """Return a valid challenge ID or raise a useful error."""
    if isinstance(chal_ID, bool) or not isinstance(chal_ID, int) or chal_ID < 0:
        raise ValueError("chal_ID must be a non-negative integer")
    return chal_ID


def _connect() -> sqlite3.Connection:
    """Open the local context database and ensure its schema exists."""
    CONTEXT_DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(CONTEXT_DB_PATH)
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS challenge_contexts (
            challenge_id INTEGER PRIMARY KEY,
            context TEXT NOT NULL,
            filepath TEXT,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        )
        """
    )
    return connection


def _validate_context(context: str) -> str:
    """Ensure stored context is text."""
    if not isinstance(context, str):
        raise TypeError("context must be a string")
    return context


def store_context(context: str, chal_ID: int) -> None:
    """Create or replace the stored context for a challenge."""
    challenge_id = _validate_challenge_id(chal_ID)
    text = _validate_context(context)
    with _connect() as connection:
        connection.execute(
            """
            INSERT INTO challenge_contexts (challenge_id, context)
            VALUES (?, ?)
            ON CONFLICT(challenge_id) DO UPDATE SET
                context = excluded.context,
                updated_at = CURRENT_TIMESTAMP
            """,
            (challenge_id, text),
        )


def get_context(chal_ID: int) -> str | None:
    """Return the stored context for a challenge."""
    challenge_id = _validate_challenge_id(chal_ID)
    with _connect() as connection:
        row = connection.execute(
            "SELECT context FROM challenge_contexts WHERE challenge_id = ?",
            (challenge_id,),
        ).fetchone()
    return row[0] if row else None


def append_context(context: str, chal_ID: int) -> None:
    """Append additional context for a challenge."""
    challenge_id = _validate_challenge_id(chal_ID)
    text = _validate_context(context)
    with _connect() as connection:
        connection.execute(
            """
            INSERT INTO challenge_contexts (challenge_id, context)
            VALUES (?, ?)
            ON CONFLICT(challenge_id) DO UPDATE SET
                context = CASE
                    WHEN challenge_contexts.context = '' THEN excluded.context
                    WHEN excluded.context = '' THEN challenge_contexts.context
                    ELSE challenge_contexts.context || char(10) || excluded.context
                END,
                updated_at = CURRENT_TIMESTAMP
            """,
            (challenge_id, text),
        )


def store_chal_file_path(filepath: str, chal_ID: int) -> None:
    """Store or replace the local challenge-file path for a challenge."""
    challenge_id = _validate_challenge_id(chal_ID)
    if not isinstance(filepath, str) or not filepath.strip():
        raise ValueError("filepath must be a non-empty string")
    with _connect() as connection:
        connection.execute(
            """
            INSERT INTO challenge_contexts (challenge_id, context, filepath)
            VALUES (?, '', ?)
            ON CONFLICT(challenge_id) DO UPDATE SET
                filepath = excluded.filepath,
                updated_at = CURRENT_TIMESTAMP
            """,
            (challenge_id, filepath),
        )


def get_chal_file_path(chal_ID: int) -> str | None:
    """Return the local path of a challenge download, when available."""
    challenge_id = _validate_challenge_id(chal_ID)
    with _connect() as connection:
        row = connection.execute(
            "SELECT filepath FROM challenge_contexts WHERE challenge_id = ?",
            (challenge_id,),
        ).fetchone()
    return row[0] if row and row[0] is not None else None
