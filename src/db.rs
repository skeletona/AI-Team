use rusqlite::{Connection, Result, OptionalExtension};


#[derive(Debug)]
pub struct Task {
    pub timestamp:  i32,
    pub id:         String,
    pub name:       String,
    pub status:     String,
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
            id        VARCHAR(100) PRIMARY KEY,
            name      VARCHAR(100),
            status    VARCHAR(10)    NOT NULL,
            attempt   INTEGER NOT NULL,
            tokens    INTEGER NOT NULL,
            points    INTEGER,
            solves    INTEGER,
            category  VARCHAR(100),
            flag      VARCHAR(100),
            error     VARCHAR(100)
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

