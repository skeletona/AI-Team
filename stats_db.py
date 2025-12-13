from __future__ import annotations

import logging
import sqlite3
from pathlib import Path
from typing import Mapping

_INITIALIZED: set[str] = set()


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
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp REAL NOT NULL,
            task TEXT,
            challenge_id INTEGER UNIQUE,
            flag TEXT,
            tokens_used INTEGER,
            status TEXT,
            error TEXT
        )
        """
    )


def _ensure_index(conn: sqlite3.Connection) -> None:
    conn.execute("CREATE INDEX IF NOT EXISTS stats_by_challenge ON stats(challenge_id)")


EXPECTED_COLUMNS = ["id", "timestamp", "task", "challenge_id", "flag", "tokens_used", "status", "error"]


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


def insert_entry(path: Path, entry: Mapping[str, object]) -> None:
    ensure_stats_db(path)
    challenge_id = entry.get("challenge_id")
    stmt = """
        INSERT INTO stats
            (timestamp, task, challenge_id, flag, tokens_used, status, error)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(challenge_id) DO UPDATE SET
            timestamp = excluded.timestamp,
            task = excluded.task,
            flag = excluded.flag,
            tokens_used = excluded.tokens_used,
            status = excluded.status,
            error = excluded.error
    """
    params = (
        float(entry.get("timestamp") or 0.0),
        entry.get("task"),
        int(challenge_id) if isinstance(challenge_id, int) else None,
        entry.get("flag"),
        _to_int(entry.get("tokens_used")),
        entry.get("status"),
        entry.get("error"),
    )
    with _connect(path) as conn:
        if isinstance(challenge_id, int) and entry.get("status") != "running":
            conn.execute(
                "DELETE FROM stats WHERE challenge_id = ? AND status = ?",
                (int(challenge_id), "running"),
            )
        conn.execute(stmt, params)


def read_entries(path: Path) -> list[Mapping[str, object]]:
    if not path.exists():
        return []
    ensure_stats_db(path)
    with _connect(path) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute("SELECT * FROM stats ORDER BY timestamp ASC").fetchall()
    return [
        {
            "id": row["id"],
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


def dedupe_stats(path: Path) -> None:
    ensure_stats_db(path)
    with _connect(path) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            "SELECT id, challenge_id, task, timestamp FROM stats ORDER BY timestamp DESC, id DESC"
        ).fetchall()
        seen: set[str] = set()
        delete_ids: list[int] = []
        for row in rows:
            key: str | None = None
            cid = row["challenge_id"]
            if cid is not None:
                key = f"cid:{cid}"
            elif row["task"]:
                key = f"task:{row['task']}"
            if key is None:
                continue
            if key in seen:
                delete_ids.append(row["id"])
            else:
                seen.add(key)
        if delete_ids:
            conn.executemany("DELETE FROM stats WHERE id = ?", [(did,) for did in delete_ids])


def delete_status(path: Path, status: str) -> None:
    ensure_stats_db(path)
    with _connect(path) as conn:
        conn.execute("DELETE FROM stats WHERE status = ?", (status,))
