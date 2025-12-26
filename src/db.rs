use rusqlite::{Connection, Result, OptionalExtension};
use std::convert::TryFrom;
use std::fmt;


#[derive(Debug, Clone)]
pub enum TaskStatus {
    Queued,
    Running,
    Solved,
    Failed,
    Blocked,
}

impl TaskStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            TaskStatus::Queued  => "queued",
            TaskStatus::Running => "running",
            TaskStatus::Solved  => "solved",
            TaskStatus::Failed  => "failed",
            TaskStatus::Blocked   => "blocked",
        }
    }
}

impl TryFrom<&str> for TaskStatus {
    type Error = String;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        match s {
            "queued"  => Ok(TaskStatus::Queued),
            "running" => Ok(TaskStatus::Running),
            "solved"  => Ok(TaskStatus::Solved),
            "failed"  => Ok(TaskStatus::Failed),
            "blocked" => Ok(TaskStatus::Blocked),
            _ => Err(format!("Invalid status: {}", s)),
        }
    }
}

impl fmt::Display for TaskStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}


#[derive(Debug)]
pub struct Task {
    pub timestamp:  i32,
    pub id:         String,
    pub name:       String,
    pub status:     TaskStatus,
    pub attempt:    i32,
    pub tokens:     i32,
    pub points:     i32,
    pub solves:     i32,
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

    let mut stmt = conn.prepare("
            SELECT timestamp, id, name, status, attempt, tokens, points, solves, category, flag, error
            FROM tasks
            ORDER BY timestamp DESC
    ")?;

    let rows = stmt.query_map([], |row| {
        let status_str: String = row.get(3)?;
        let status = TaskStatus::try_from(status_str.as_str())
            .map_err(|msg| rusqlite::Error::FromSqlConversionFailure(
                3,
                rusqlite::types::Type::Text,
                Box::new(std::io::Error::new(std::io::ErrorKind::InvalidData, msg)),
            ))?;

        Ok(Task {
            timestamp:  row.get(0)?,
            id:         row.get(1)?,
            name:       row.get(2)?,
            status,
            attempt:    row.get(4)?,
            tokens:     row.get(5)?,
            points:     row.get(6)?,
            solves:     row.get(7)?,
            category:   row.get(8)?,
            flag:       row.get(9)?,
            error:      row.get(10)?,
        })
    })?;

    let mut out = Vec::new();
    for r in rows {
        out.push(r?);
    }

    Ok(out)
}


pub fn get_task(id: &str) -> Result<Option<Task>> {
    let conn = Connection::open("tasks.db")?;

    let task = conn.query_row("
        SELECT timestamp, id, name, status, attempt, tokens, points, solves, category, flag, error
        FROM tasks
        WHERE id = ?1",
        [id],
        |row| {
            let status_str: String = row.get(3)?;
            let status = TaskStatus::try_from(status_str.as_str())
                .map_err(|msg| rusqlite::Error::FromSqlConversionFailure(
                3,
                rusqlite::types::Type::Text,
                Box::new(std::io::Error::new(std::io::ErrorKind::InvalidData, msg)),
            ))?;

            Ok(Task {
                timestamp:  row.get(0)?,
                id:         row.get(1)?,
                name:       row.get(2)?,
                status,
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

