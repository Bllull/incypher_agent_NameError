"""Authenticated, append-only log portal for a remote CTF-agent container.

Deploy this module as a PythonAnywhere Flask application.  It accepts only
JSON log records and returns records after a caller-provided cursor; it never
interprets received content as commands or instructions.
"""

from __future__ import annotations

import json
import os
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from flask import Flask, jsonify, request


MAX_ENTRIES_PER_REQUEST = 100
MAX_ENTRY_BYTES = 16 * 1024
DEFAULT_LIMIT = 100
MAX_LIMIT = 500


def create_app(
    *, database_path: str | Path | None = None, access_token: str | None = None
) -> Flask:
    """Create a log portal with a private SQLite store and bearer authentication."""
    app = Flask(__name__)
    database = Path(database_path or os.getenv("LOG_PORTAL_DB", "log_portal.sqlite3"))
    token = access_token if access_token is not None else os.getenv("LOG_PORTAL_TOKEN", "")
    app.config.update(LOG_PORTAL_DB=database, LOG_PORTAL_TOKEN=token)

    def connect() -> sqlite3.Connection:
        database.parent.mkdir(parents=True, exist_ok=True)
        connection = sqlite3.connect(database)
        connection.row_factory = sqlite3.Row
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS log_entries (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                received_at TEXT NOT NULL,
                source TEXT NOT NULL,
                payload_json TEXT NOT NULL
            )
            """
        )
        return connection

    def authorized() -> bool:
        configured_token = app.config["LOG_PORTAL_TOKEN"]
        authorization = request.headers.get("Authorization", "")
        return bool(configured_token) and authorization == f"Bearer {configured_token}"

    @app.get("/healthz")
    def healthz() -> tuple[dict[str, str], int]:
        return {"status": "ok"}, 200

    @app.post("/api/logs")
    def post_logs():
        if not authorized():
            return jsonify({"error": "unauthorized"}), 401
        body = request.get_json(silent=True)
        if not isinstance(body, dict):
            return jsonify({"error": "JSON object required"}), 400
        source = body.get("source", "remote-agent")
        entries = body.get("entries")
        if not isinstance(source, str) or not source.strip() or len(source) > 128:
            return jsonify({"error": "valid source required"}), 400
        if not isinstance(entries, list) or not entries or len(entries) > MAX_ENTRIES_PER_REQUEST:
            return jsonify({"error": "1-100 entries required"}), 400
        try:
            serialized = [json.dumps(entry, sort_keys=True, separators=(",", ":")) for entry in entries]
        except (TypeError, ValueError):
            return jsonify({"error": "entries must be JSON serializable"}), 400
        if any(len(entry.encode("utf-8")) > MAX_ENTRY_BYTES for entry in serialized):
            return jsonify({"error": "entry exceeds size limit"}), 413

        received_at = datetime.now(timezone.utc).isoformat()
        connection = connect()
        try:
            connection.executemany(
                "INSERT INTO log_entries (received_at, source, payload_json) VALUES (?, ?, ?)",
                [(received_at, source, entry) for entry in serialized],
            )
            connection.commit()
        finally:
            connection.close()
        return jsonify({"accepted": len(serialized)}), 201

    @app.get("/api/logs")
    def get_logs():
        if not authorized():
            return jsonify({"error": "unauthorized"}), 401
        try:
            after = max(0, int(request.args.get("after", "0")))
            limit = min(MAX_LIMIT, max(1, int(request.args.get("limit", str(DEFAULT_LIMIT)))))
        except ValueError:
            return jsonify({"error": "after and limit must be integers"}), 400
        connection = connect()
        try:
            rows = connection.execute(
                "SELECT id, received_at, source, payload_json FROM log_entries "
                "WHERE id > ? ORDER BY id ASC LIMIT ?",
                (after, limit),
            ).fetchall()
        finally:
            connection.close()
        entries = [
            {
                "id": row["id"],
                "received_at": row["received_at"],
                "source": row["source"],
                "entry": json.loads(row["payload_json"]),
            }
            for row in rows
        ]
        next_after = entries[-1]["id"] if entries else after
        return jsonify({"entries": entries, "next_after": next_after}), 200

    return app


app = create_app()
