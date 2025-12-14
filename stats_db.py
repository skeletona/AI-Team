from __future__ import annotations

import os
import logging
import sqlite3
from time import time
from pathlib import Path
from typing import Mapping
from dotenv import load_dotenv

load_dotenv()

_INITIALIZED: set[str] = set()
EXPECTED_COLUMNS = ["challenge_id", "timestamp", "task", "status", "flag", "tokens_used", "error"]
DB_PATH = Path(os.environ.get("DB_PATH", "codex_stats.db"))

def _connect(db_path: Path) -> sqlite3.Connection:
    return sqlite3.connect(
        str(db_path),
        timeout=15.0,
        isolation_level=None,
        check_same_thread=False,
    )


def _table_exists(conn: sqlite3.Connection) -> bool:
    row = conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name='stats'"
    ).fetchone()
    return bool(row)


def _create_table(conn: sqlite3.Connection) -> None:
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS stats (
            challenge_id INTEGER PRIMARY KEY,
            timestamp INTEGER NOT NULL,
            task TEXT,
            flag TEXT,
            tokens_used INTEGER,
            status TEXT,
            error TEXT
        )
        """
    )


def _ensure_index(conn: sqlite3.Connection) -> None:
    conn.execute("CREATE INDEX IF NOT EXISTS stats_by_challenge ON stats(challenge_id)")


def _column_names(conn: sqlite3.Connection, table: str) -> list[str]:
    rows = conn.execute(f"PRAGMA table_info({table})").fetchall()
    return [row[1] for row in rows]


def _migrate_table(conn: sqlite3.Connection, existing: list[str]) -> None:
    conn.execute("ALTER TABLE stats RENAME TO stats_old")
    _create_table(conn)
    cols = ", ".join([col for col in EXPECTED_COLUMNS if col in existing and col != "id"])
    if cols:
        conn.execute(f"INSERT INTO stats ({cols}) SELECT {cols} FROM stats_old")
    conn.execute("DROP TABLE stats_old")


def _ensure_schema(conn: sqlite3.Connection) -> None:
    if not _table_exists(conn):
        _create_table(conn)
    else:
        existing = _column_names(conn, "stats")
        if existing != EXPECTED_COLUMNS:
            _migrate_table(conn, existing)
    _ensure_index(conn)


def _to_int(value: object | None) -> int | None:
    if value is None:
        return None
    if isinstance(value, int):
        return value
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def ensure_stats_db(path: Path) -> None:
    resolved = str(path.resolve())
    if resolved in _INITIALIZED:
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    with _connect(path) as conn:
        _ensure_schema(conn)
    _INITIALIZED.add(resolved)


def insert_entry(
    challenge_id: int,
    status: str,
    task: Optional[str] = None,
    flag: Optional[str] = None,
    tokens_used: int = 0,
    error: Optional[str] = None,
) -> None:
    ensure_stats_db(DB_PATH)

    stmt = """
        INSERT INTO stats
            (challenge_id, timestamp, task, status, flag, tokens_used, error)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(challenge_id) DO UPDATE SET
            timestamp   = excluded.timestamp,
            task        = COALESCE(excluded.task, task),
            status      = excluded.status,
            flag        = excluded.flag,
            tokens_used = excluded.tokens_used,
            error       = excluded.error
    """
    params = (
        challenge_id,   int(time()),    task,
        status,         flag,           tokens_used,
        error,
    )
    with _connect(DB_PATH) as conn:
        conn.execute(stmt, params)


def read_entries(path: Path) -> list[Mapping[str, object]]:
    ensure_stats_db(path)
    with _connect(path) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute("SELECT * FROM stats ORDER BY timestamp ASC").fetchall()
    return [
        {
            "timestamp": row["timestamp"],
            "task": row["task"],
            "challenge_id": row["challenge_id"],
            "flag": row["flag"],
            "tokens_used": row["tokens_used"],
            "status": row["status"],
            "error": row["error"],
            "thinking": None,
        }
        for row in rows
    ]


def delete_status(path: Path, status: str) -> None:
    ensure_stats_db(path)
    with _connect(path) as conn:
        conn.execute("DELETE FROM stats WHERE status = ?", (status,))


def get_entry(path: Path, challenge_id: int) -> dict:
    ensure_stats_db(path)
    with _connect(path) as conn:
        conn.row_factory = sqlite3.Row
        row = conn.execute(
            "SELECT * FROM stats WHERE challenge_id = ?", (challenge_id,),
        ).fetchone()
    return dict(row)

