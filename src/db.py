#!/usr/bin/env python3

import sqlite3

from src.models import *

_INITIALIZED: set[str] = set()
EXPECTED_COLUMNS = [
    "id",
    "timestamp",
    "name",
    "status",
    "points",
    "solves",
    "category",
    "flag",
    "attempt",
    "tokens",
    "error",
]


def _connect(db_path: Path) -> sqlite3.Connection:
    return sqlite3.connect(
        str(db_path),
        timeout=15.0,
        isolation_level=None,
        check_same_thread=False,
    )


def _table_exists(conn: sqlite3.Connection) -> bool:
    row = conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name='tasks'"
    ).fetchone()
    return bool(row)


def _create_table(conn: sqlite3.Connection) -> None:
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS tasks (
            id        TEXT PRIMARY KEY,
            timestamp INTEGER,
            name      TEXT,
            status    TEXT,
            points    INTEGER,
            solves    INTEGER,
            category  TEXT,
            flag      TEXT,
            attempt   INTEGER,
            tokens    INTEGER,
            error     TEXT
        )
        """
    )


def _ensure_index(conn: sqlite3.Connection) -> None:
    conn.execute("CREATE INDEX IF NOT EXISTS tasks_by_challenge ON tasks(id)")


def _column_names(conn: sqlite3.Connection, table: str) -> list[str]:
    rows = conn.execute(f"PRAGMA table_info({table})").fetchall()
    return [row[1] for row in rows]


def _ensure_schema(conn: sqlite3.Connection) -> None:
    if not _table_exists(conn):
        _create_table(conn)
    else:
        existing = _column_names(conn, "tasks")
        if existing != EXPECTED_COLUMNS:
            error(
                "SQL schema is wrong:\nExpected: %s\nActual:   %s\n",
                EXPECTED_COLUMNS,
                existing,
            )
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


def ensure_tasks_db(path: Path) -> None:
    resolved = str(path.resolve())
    if resolved in _INITIALIZED:
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    with _connect(path) as conn:
        _ensure_schema(conn)
    _INITIALIZED.add(resolved)


def insert_entry(
    id: str,
    tokens:     int | None = None,
    points:     int | None = None,
    solves:     int | None = None,
    attempt:    int | None = None,
    timestamp:  int | None = None,
    status:     str | None = None,
    name:       str | None = None,
    flag:       str | None = None,
    error:      str | None = None,
    category:   str | None = None,
    log:        Path| None = None,
) -> None:
    ensure_tasks_db(DB_PATH)
    if status and status not in ("queued", "running", "solved", "failed"):
        error("Invalid task status insertion: %s", status)
        return

    stmt = """
        INSERT INTO tasks (
            id, timestamp, name, status, points,
            solves, category, flag, attempt, tokens, error
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT (id) DO UPDATE SET
            timestamp = EXCLUDED.timestamp,
            name      = COALESCE(EXCLUDED.name, name),
            status    = COALESCE(EXCLUDED.status, status),
            points    = COALESCE(EXCLUDED.points, points),
            solves    = COALESCE(EXCLUDED.solves, solves),
            category  = COALESCE(EXCLUDED.category, category),
            flag      = COALESCE(EXCLUDED.flag, flag),
            attempt   = COALESCE(EXCLUDED.attempt, attempt),
            tokens    = tokens + COALESCE(EXCLUDED.tokens, 0),
            error     = COALESCE(EXCLUDED.error, error)

    """
    params = (
        id,
        now(),
        name,
        status,
        points,
        solves,
        category,
        flag,
        attempt,
        tokens,
        error,
    )
    with _connect(DB_PATH) as conn:
        conn.execute(stmt, params)


def read_entries(path: Path) -> list[Task]:
    ensure_tasks_db(path)
    with _connect(path) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute("SELECT * FROM tasks").fetchall()
    
    return [Task(
            id=row["id"],
            name=row["name"],
            status=row["status"],
            points=row["points"],
            solves=row["solves"],
            timestamp=row["timestamp"],
            category=row["category"],
            flag=row["flag"],
            tokens=row["tokens"],
            error=row["error"],
            log=(CODEX_DIR / row["name"] / f"{CODEX_FILE}.{row["attempt"] or 0}")
        ) for row in rows]


def move_status(path: Path, old_status: str, new_status: str) -> None:
    ensure_tasks_db(path)
    with _connect(path) as conn:
        conn.execute(
            "UPDATE tasks SET status = ? WHERE status = ?",
            (new_status, old_status),
        )
        conn.commit()


def get_entry(path: Path, id: str) -> Task | None:
    ensure_tasks_db(path)
    with _connect(path) as conn:
        conn.row_factory = sqlite3.Row
        row = conn.execute("SELECT * FROM tasks WHERE id = ?", (id,)).fetchone()
    if row is None:
        return None
    return Task(
            id=row["id"],
            timestamp=row["timestamp"],
            name=row["name"],
            status=row["status"],
            points=row["points"],
            solves=row["solves"],
            category=row["category"],
            flag=row["flag"],
            tokens=row["tokens"],
            error=row["error"],
            log=(CODEX_DIR / row["name"] / f"{CODEX_FILE}.{row["attempt"]}")
        )


def change_task(
    task:       Task,
    status:     str | None = None,
    error:      str | None = None,
    name:       str | None = None,
    timestamp:  int | None = None,
    flag:       str | None = None,
    category:   str | None = None,
    log:        Path| None = None,
    attempt:    int | None = None,
    tokens:     int | None = None,
    points:     int | None = None,
    solves:     int | None = None,
) -> Task:
    updates: dict[str, object] = {}
    if (category and category != task.category) or (name and name != task.name):
        raise ValueError("Cannot change category or name of a task")
    
    if attempt:
        info([CODEX_DIR, task.name, CODEX_FILE, attempt])
        log = CODEX_DIR / task.name / f"{CODEX_FILE}.{attempt}"
    elif log:
        attempt = int(str(log).split(".")[-1])

    if category   is not None: updates["category"]  = category
    if points     is not None: updates["points"]    = points
    if status     is not None: updates["status"]    = status
    if solves     is not None: updates["solves"]    = solves
    if error      is not None: updates["error"]     = error
    if flag       is not None: updates["flag"]      = flag
    if name       is not None: updates["name"]      = name
    if log        is not None: updates["log"]       = log

    if tokens:
        updates["tokens"]  = task.tokens  + tokens
    updates["timestamp"] = now()

    debug(f"{task.name}: Updating: {updates}")
    new_task = replace(task, **updates)

    if attempt:
        updates["attempt"] = attempt

    insert_entry(task.id, **updates)
    return new_task

