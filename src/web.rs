#![warn(clippy::all)]

use tower_http::services::ServeDir;
use futures_util::stream::Stream;
use async_stream;
use askama::Template;
use axum::{
    response::sse::{Event, KeepAlive, Sse},
    extract::Path,
    http::StatusCode,
    response::Html,
    routing::get,
    Router,
};
use tokio::{
    time::{self, Duration},
    io::{AsyncReadExt, AsyncSeekExt},
    fs,
};
use std::{
    collections::HashMap,
    convert::Infallible,
    io::SeekFrom,
};

mod db;
use db::{Task, TaskStatus};


#[derive(Template)]
#[template(path = "index.html")]
struct IndexTemplate {
    tokens_used: u32,
    fill_5h:     f32,
    fill_week:   f32,
    runs:        u16,
    flags:       u8,
    cards: HashMap<TaskStatus, Vec<Task>>,
}

#[derive(Template)]
#[template(path = "task.html")]
struct TaskTemplate {
    task:   Task,
}


const NO_LOG: &str = "
           No log :(


⠟⢻⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡟⠛⢻⣿
⡆⠊⠈⣿⢿⡟⠛⢿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⣎⠈⠻
⣷⣠⠁⢀⠰⠀⣰⣿⣿⣿⣿⣿⣿⠟⠋⠛⠛⠿⠿⢿⣿⣿⣿⣧⠀⢹⣿⡑⠐⢰
⣿⣿⠀⠁⠀⠀⣿⣿⣿⣿⠟⡩⠐⠀⠀⠀⠀⢐⠠⠈⠊⣿⣿⣿⡇⠘⠁⢀⠆⢀
⣿⣿⣆⠀⠀⢤⣿⣿⡿⠃⠈⠀⣠⣶⣿⣿⣷⣦⡀⠀⠀⠈⢿⣿⣇⡆⠀⠀⣠⣾
⣿⣿⣿⣧⣦⣿⣿⣿⡏⠀⠀⣰⣿⣿⣿⣿⣿⣿⣿⡆⠀⠀⠐⣿⣿⣷⣦⣷⣿⣿
⣿⣿⣿⣿⣿⣿⣿⣿⡆⠀⢰⣿⣿⣿⣿⣿⣿⣿⣿⣿⡄⠀⠀⣿⣿⣿⣿⣿⣿⣿
⣿⣿⣿⣿⣿⣿⣿⣿⡆⠀⣾⣿⣿⠋⠁⠀⠉⠻⣿⣿⣧⠀⠠⣿⣿⣿⣿⣿⣿⣿
⣿⣿⣿⣿⣿⣿⣿⣿⣿⡀⣿⡿⠁⠀⠀⠀⠀⠀⠘⢿⣿⠀⣺⣿⣿⣿⣿⣿⣿⣿
⣿⣿⣿⣿⣿⣿⣿⣿⣿⣧⣠⣂⠀⠀⠀⠀⠀⠀⠀⢀⣁⢠⣿⣿⣿⣿⣿⣿⣿⣿
⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⣶⣄⣤⣤⣔⣶⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿
";


fn internal_error<E: std::fmt::Display>(e: E) -> (StatusCode, String) {
    (StatusCode::INTERNAL_SERVER_ERROR, e.to_string())
}


/// localhost:8000/
async fn index() -> Result<Html<String>, (StatusCode, String)> {
    let mut cards: HashMap<TaskStatus, Vec<Task>> = HashMap::from([
        (TaskStatus::Queued,  Vec::new()),
        (TaskStatus::Running, Vec::new()),
        (TaskStatus::Solved,  Vec::new()),
        (TaskStatus::Failed,  Vec::new()),
        (TaskStatus::Blocked, Vec::new()),
    ]);
    let mut runs = 0;
    let mut flags = 0;

    let tasks = db::list_tasks().map_err(internal_error)?;
    for task in tasks {
        runs += task.attempt as u16;
        if task.flag != "" {
            flags += 1;
        }
        if let Some(v) = cards.get_mut(&task.status) {
            v.push(task);
        } else {
            eprintln!("Unknown status in cards: {}", task.status);
        }
    }

    let (tokens_5h, limit_5h, tokens_week, limit_week) = (75.0, 100.0, 33.0, 100.0);
    let fill_5h   = ( tokens_5h * 100.0)   / limit_5h;
    let fill_week = (tokens_week * 100.0) / limit_week;

    let html = IndexTemplate {
        tokens_used: 0,
        fill_5h,
        fill_week,
        flags,
        runs,
        cards,
    }
    .render().unwrap();
    Ok(Html(html))
}


/// localhost:8000/task/{id}
async fn task(Path(id): Path<String>) -> Result<Html<String>, (StatusCode, String)> {
    match db::get_task(&id).map_err(internal_error)? {
        Some(task) => {
            let html = TaskTemplate { task }.render().unwrap();
            Ok(Html(html))
        }
        None => Err((StatusCode::NOT_FOUND, "Task not found".to_string())),  // TODO
    }
}


/// localhost:8000/task/{id}/stream
async fn task_stream(Path(id): Path<String>) -> Sse<impl Stream<Item = Result<Event, Infallible>>> {
    let stream = async_stream::stream! {
        let task = match db::get_task(&id) {
            Ok(Some(t)) => t,
            Ok(None) => {
                yield Ok(Event::default().data("Task not found\n"));
                return;
            }
            Err(e) => {
                yield Ok(Event::default().data(format!("DB error: {e}\n")));
                return;
            }
        };

        let log_path = task.log_path();

        let mut offset: u64 = 0;

        match fs::read(&log_path).await {
            Ok(bytes) => {
                offset = bytes.len() as u64;
                if !bytes.is_empty() {
                    // Важно: SSE "data" не любит сырой \0; тут ожидаем текстовый лог.
                    let text = String::from_utf8_lossy(&bytes);
                    yield Ok(Event::default().data(text.to_string()));
                }
            }
            Err(_) => {
                yield Ok(Event::default().data(NO_LOG.to_string()));
            }
        }

        let mut tick = time::interval(Duration::from_millis(1000));
        loop {
            tick.tick().await;

            let meta = match fs::metadata(&log_path).await {
                Ok(m) => m,
                Err(_) => {
                    continue;
                }
            };

            let len = meta.len();

            if len == offset {
                continue;
            }

            if len < offset {
                offset = 0;
            }

            let mut file = match fs::File::open(&log_path).await {
                Ok(f) => f,
                Err(_) => continue,
            };

            if file.seek(SeekFrom::Start(offset)).await.is_err() {
                continue;
            }

            let mut buf = Vec::with_capacity((len - offset) as usize);
            if file.read_to_end(&mut buf).await.is_err() {
                continue;
            }

            offset = len;

            if !buf.is_empty() {
                let text = String::from_utf8_lossy(&buf);
                yield Ok(Event::default().data(text.to_string()));
            }
        }
    };

    Sse::new(stream).keep_alive(
        KeepAlive::new()
            .interval(Duration::from_secs(15))
            .text("keep-alive")
    )
}


#[tokio::main]
async fn main() {
    let app = Router::new()
        .route("/", get(index))
        .route("/task/{id}", get(task))
        .route("/task/{id}/stream", get(task_stream))
        .nest_service(
            "/static",
            ServeDir::new("src/static"),
    );

    let listener = tokio::net::TcpListener::bind("0.0.0.0:8000").await.unwrap();
    println!("Website is at http://localhost:8000");
    axum::serve(listener, app).await.unwrap();
}

