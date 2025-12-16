import sqlite3
from pathlib import Path

from src.models import DB_PATH, Task, now

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
            id        INTEGER PRIMARY KEY,
            timestamp INTEGER NOT NULL,
            name      TEXT,
            status    TEXT NOT NULL,
            points    INTEGER NOT NULL,
            solves    INTEGER NOT NULL,
            category  TEXT,
            flag      TEXT,
            tokens    INTEGER NOT NULL,
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
    id: int,
    status: str,
    timestamp: str | None = None,
    name: str | None = None,
    flag: str | None = None,
    tokens: int | None = 0,
    error: str | None = None,
    points: int | None = 0,
    solves: int | None = 0,
    category: str | None = None,
) -> None:
    if status not in ("queued", "running", "solved", "failed"):
        error("Invalid task status insertion: %s", status)
        return

    ensure_tasks_db(DB_PATH)
    tokens = tokens or 0
    points = points or 0
    solves = solves or 0

    stmt = """
        INSERT INTO tasks
            (id, timestamp, name, status, points, solves, category, flag, tokens, error)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(id) DO UPDATE SET
            timestamp = excluded.timestamp,
            name      = COALESCE(excluded.name, name),
            status    = excluded.status,
            points    = excluded.points,
            solves    = excluded.solves,
            category  = excluded.category,
            flag      = excluded.flag,
            tokens    = excluded.tokens + tokens,
            error     = excluded.error
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
        tokens,
        error,
    )
    with _connect(DB_PATH) as conn:
        conn.execute(stmt, params)


def create_entry(
    id: int,
    status: str,
    timestamp: str | None = None,
    name: str | None = None,
    flag: str | None = None,
    tokens: int | None = 0,
    error: str | None = None,
    points: int | None = 0,
    solves: int | None = 0,
    category: str | None = None,
) -> None:
    if status not in ("queued", "running", "solved", "failed"):
        error("Invalid task status insertion: %s", status)
        return

    ensure_tasks_db(DB_PATH)
    tokens = tokens or 0
    points = points or 0
    solves = solves or 0

    stmt = """
        INSERT INTO tasks
            (id, timestamp, name, status, points, solves, category, flag, tokens, error)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(id) DO NOTHING
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
    return [
        Task(
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
        )
        for row in rows
    ]


def move_status(path: Path, old_status: str, new_status: str) -> None:
    ensure_tasks_db(path)
    with _connect(path) as conn:
        conn.execute(
            "UPDATE tasks SET status = ? WHERE status = ?",
            (new_status, old_status),
        )
        conn.commit()


def get_entry(path: Path, id: int) -> Task | None:
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
    )

