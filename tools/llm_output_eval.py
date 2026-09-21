"""Optional local accounting and SOCLAAS evaluation for model outputs.

This module is intentionally independent from solver control flow: logging and
evaluation failures must never prevent a challenge attempt from completing.
"""

from __future__ import annotations

import json
import os
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator


_WORK_ROOT = Path(os.getenv("IN_CYPHER_WORK_DIR", "/work"))
if not _WORK_ROOT.is_dir() or not os.access(_WORK_ROOT, os.W_OK):
    _WORK_ROOT = Path(__file__).resolve().parent.parent / ".agent_data"
OUTPUT_EVAL_DB_PATH = _WORK_ROOT / "llm_output_usage.sqlite3"
EVAL_RESULTS_PATH = Path(os.getenv("EVAL_RESULTS_PATH", str(_WORK_ROOT / "eval_results.txt")))


@contextmanager
def _connect() -> Iterator[sqlite3.Connection]:
    OUTPUT_EVAL_DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(OUTPUT_EVAL_DB_PATH)
    try:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS model_outputs (
                id INTEGER PRIMARY KEY,
                created_at TEXT NOT NULL,
                challenge_id INTEGER,
                provider TEXT NOT NULL,
                model TEXT NOT NULL,
                prompt_tokens INTEGER,
                completion_tokens INTEGER,
                total_tokens INTEGER,
                output_text TEXT NOT NULL
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


def log_model_output(
    *,
    provider: str,
    model: str,
    challenge_id: int | None,
    prompt_tokens: int | None,
    completion_tokens: int | None,
    total_tokens: int | None,
    output_text: str,
) -> None:
    """Persist token accounting and output text for optional local evaluation."""
    if not provider or not model or not isinstance(output_text, str):
        raise ValueError("provider, model, and output_text are required")
    token_values = (prompt_tokens, completion_tokens, total_tokens)
    if any(value is not None and (not isinstance(value, int) or value < 0) for value in token_values):
        raise ValueError("token values must be non-negative integers or None")
    with _connect() as connection:
        connection.execute(
            """
            INSERT INTO model_outputs (
                created_at, challenge_id, provider, model, prompt_tokens,
                completion_tokens, total_tokens, output_text
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                datetime.now(timezone.utc).isoformat(),
                challenge_id,
                provider,
                model,
                prompt_tokens,
                completion_tokens,
                total_tokens,
                output_text,
            ),
        )


def recent_model_outputs(
    *, challenge_id: int | None = None, limit: int = 30
) -> list[dict[str, object]]:
    """Return bounded output records for a local evaluation prompt."""
    if limit < 1 or limit > 100:
        raise ValueError("limit must be between 1 and 100")
    query = """
        SELECT challenge_id, provider, model, prompt_tokens, completion_tokens,
               total_tokens, output_text
        FROM model_outputs
    """
    parameters: tuple[object, ...] = ()
    if challenge_id is not None:
        query += " WHERE challenge_id = ?"
        parameters = (challenge_id,)
    query += " ORDER BY id DESC LIMIT ?"
    parameters += (limit,)
    with _connect() as connection:
        rows = connection.execute(query, parameters).fetchall()
    return [
        {
            "challenge_id": row[0],
            "provider": row[1],
            "model": row[2],
            "prompt_tokens": row[3],
            "completion_tokens": row[4],
            "total_tokens": row[5],
            "output": row[6][:8_000],
        }
        for row in rows
    ]


def log_evaluation_result(result: str, *, challenge_id: int | None = None) -> None:
    """Append one evaluator response to the local, human-readable result log.

    This optional reporting path is deliberately best-effort, so a full or
    unwritable volume cannot affect a solver attempt or its model evaluation.
    """
    if not isinstance(result, str):
        raise ValueError("result must be a string")
    label = "all challenges" if challenge_id is None else f"challenge {challenge_id}"
    record = (
        f"[{datetime.now(timezone.utc).isoformat()}] {label}\n"
        f"{result.rstrip()}\n\n"
    )
    try:
        EVAL_RESULTS_PATH.parent.mkdir(parents=True, exist_ok=True)
        with EVAL_RESULTS_PATH.open("a", encoding="utf-8") as output_file:
            output_file.write(record)
    except OSError:
        # Evaluation output is auxiliary and must not interrupt a solver.
        pass


def digest_model_outputs(*, challenge_id: int | None = None, limit: int = 30) -> str:
    """Ask SOCLAAS to identify the best-performing and most efficient model.

    The evaluator uses SOCLAAS directly so it does not consume another rotated
    OpenRouter model call or recursively evaluate its own output.
    """
    records = recent_model_outputs(challenge_id=challenge_id, limit=limit)
    if not records:
        result = "No logged model outputs are available for evaluation."
        log_evaluation_result(result, challenge_id=challenge_id)
        return result
    from tools.llm_router import call_soclaas

    prompt = f"""Evaluate outputs from authorized CTF-solving model attempts.
Rank models only from the recorded outputs and token counts below. Identify:
1. the best-performing model, based on actionable, evidence-grounded output;
2. the most efficient model, based on useful output per total token.
If evidence is insufficient, say so. Return concise JSON with keys
best_performing_model, most_efficient_model, and rationale. Do not reveal or
repeat any exact CTF flag found in the records.

Records:
{json.dumps(records, ensure_ascii=False)}
"""
    result = call_soclaas(prompt, model_name="default", max_attempts=DEFAULT_EVAL_ATTEMPTS)
    log_evaluation_result(result, challenge_id=challenge_id)
    return result


DEFAULT_EVAL_ATTEMPTS = 2
