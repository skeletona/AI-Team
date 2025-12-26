use rusqlite::types::{FromSql, FromSqlError, FromSqlResult, ValueRef};
use rusqlite::{Connection, Result, OptionalExtension};
use std::fmt;


#[derive(Eq, Hash, PartialEq)]
pub enum TaskStatus {
    Queued,
    Running,
    Solved,
    Failed,
    Blocked,
}

impl TaskStatus {
    pub fn as_str(&self) -> &str {
        match self {
            Self::Queued  => "queued",
            Self::Running => "running",
            Self::Solved  => "solved",
            Self::Failed  => "failed",
            Self::Blocked => "blocked",
        }
    }
}

impl FromSql for TaskStatus {
    fn column_result(value: ValueRef<'_>) -> FromSqlResult<Self> {
        match value.as_str()? {
            "queued"  => Ok(Self::Queued),
            "running" => Ok(Self::Running),
            "solved"  => Ok(Self::Solved),
            "failed"  => Ok(Self::Failed),
            "blocked"   => Ok(Self::Blocked),
            other => Err(FromSqlError::Other(Box::new(
                std::io::Error::new(std::io::ErrorKind::InvalidData, format!("Invalid status: {other}"))
            ))),
        }
    }
}

impl fmt::Display for TaskStatus {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(self.as_str())
    }
}


#[allow(dead_code)]
pub struct Task {
    pub timestamp:  i32,
    pub id:         String,
    pub name:       String,
    pub status:     TaskStatus,
    pub attempt:    u8,
    pub tokens:     u32,
    pub points:     i16,
    pub solves:     u16,
    pub category:   String,
    pub flag:       String,
    pub error:      String,
}

pub fn init_db(conn: &Connection) -> Result<()> {
    conn.execute("
            CREATE TABLE IF NOT EXISTS tasks (
            timestamp INTEGER,
            id        TEXT PRIMARY KEY,
            name      TEXT,
            status    TEXT NOT NULL CHECK (
                status IN ('queued', 'running', 'solved', 'failed', 'blocked')
            ),
            attempt   INTEGER       NOT NULL,
            tokens    INTEGER       NOT NULL,
            points    INTEGER,
            solves    INTEGER,
            category  TEXT,
            flag      TEXT,
            error     TEXT
            )",
            ()
    )?;

    Ok(())
}


pub fn list_tasks() -> Result<Vec<Task>> {
    let conn = Connection::open("tasks.db")?;
    init_db(&conn)?;

    let mut stmt = conn.prepare("
            SELECT timestamp, id, name, status, attempt, tokens, points, solves, category, flag, error
            FROM tasks
            ORDER BY timestamp DESC
    ")?;

    let rows = stmt.query_map([], |row| {
        Ok(Task {
            timestamp:  row.get(0)?,
            id:         row.get(1)?,
            name:       row.get(2)?,
            status:     row.get(3)?,
            attempt:    row.get(4)?,
            tokens:     row.get(5)?,
            points:     row.get(6)?,
            solves:     row.get(7)?,
            category:   row.get(8)?,
            flag:       row.get(9)?,
            error:      row.get(10)?,
        })
    })?;

    rows.collect()
}


pub fn get_task(id: &str) -> Result<Option<Task>> {
    let conn = Connection::open("tasks.db")?;
    init_db(&conn)?;

    let task = conn.query_row("
        SELECT timestamp, id, name, status, attempt, tokens, points, solves, category, flag, error
        FROM tasks
        WHERE id = ?1",
        [id],
        |row| {
            Ok(Task {
                timestamp:  row.get(0)?,
                id:         row.get(1)?,
                name:       row.get(2)?,
                status:     row.get(3)?,
                attempt:    row.get(4)?,
                tokens:     row.get(5)?,
                points:     row.get(6)?,
                solves:     row.get(7)?,
                category:   row.get(8)?,
                flag:       row.get(9)?,
                error:      row.get(10)?,
            })
        }
    ).optional()?;

    Ok(task)
}

