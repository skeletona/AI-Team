#![warn(clippy::all)]

use tower_http::services::ServeDir;
use std::collections::HashMap;
use askama::Template;
use axum::{
    extract::Path,
    http::StatusCode,
    response::Html,
    routing::get,
    Router,
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
    log:    String,
}


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


async fn task(Path(id): Path<String>) -> Result<Html<String>, (StatusCode, String)> {
    match db::get_task(&id).map_err(internal_error)? {
        Some(task) => {
            let html = TaskTemplate { task, log: String::new() }.render().unwrap();
            Ok(Html(html))
        }
        None => Err((StatusCode::NOT_FOUND, "Task not found".to_string())),
    }
}


fn internal_error<E: std::fmt::Display>(e: E) -> (StatusCode, String) {
    (StatusCode::INTERNAL_SERVER_ERROR, e.to_string())
}


#[tokio::main]
async fn main() {
    let app = Router::new()
        .route("/", get(index))
        .route("/task/{id}", get(task))
        .nest_service(
            "/static",
            ServeDir::new("src/static"),
    );

    let listener = tokio::net::TcpListener::bind("0.0.0.0:8000").await.unwrap();
    println!("Website is at http://localhost:8000");
    axum::serve(listener, app).await.unwrap();
}

