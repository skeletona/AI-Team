import sqlite3

from src.models import *

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
        "SELECT name FROM sqlite_master WHERE type='table' AND name='tasks'"
    ).fetchone()
    return bool(row)


def _create_table(conn: sqlite3.Connection) -> None:
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS tasks (
            id INTEGER PRIMARY KEY,
            timestamp INTEGER NOT NULL,
            name TEXT,
            status TEXT,
            flag TEXT,
            tokens INTEGER NOT NULL,
            error TEXT
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
            logging.error("SQL schema is wrong:\nExpected: %s\nActual:   %s\n", EXPECTED_COLUMNS, existing)
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
    id:     int,
    status: str,
    name:   str | None  = None,
    flag:   str | None  = None,
    tokens: int | None  = 0,
    error:  str | None  = None,
) -> None:
    if status not in ("queued", "running", "solved", "failed"):
        logging.error("Invalid task status insertion:", status)
        return

    ensure_tasks_db(DB_PATH)
    if tokens is None:
        tokens = 0

    stmt = """
        INSERT INTO tasks
            (id, timestamp, name, status, flag, tokens, error)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(id) DO UPDATE SET
            timestamp   = excluded.timestamp,
            name        = COALESCE(excluded.name, name),
            status      = excluded.status,
            flag        = excluded.flag,
            tokens      = excluded.tokens + tokens,
            error       = excluded.error
    """
    params = (
        id,   int(time()),    name,
        status,         flag,           tokens,
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
            timestamp=  row["timestamp"],
            tokens=     row["tokens"],
            status=     row["status"],
            error=      row["error"],
            name=       row["name"],
            flag=       row["flag"],
            id=         row["id"],
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
        task = Task(**conn.execute("SELECT * FROM tasks WHERE id = ?", (id,)).fetchone())
    if task:
        return task
    else:
        return None

