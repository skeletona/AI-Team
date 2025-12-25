mod db;

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


#[derive(Template)]
#[template(path = "index.html")]
struct IndexTemplate {
    tokens_used: i32,
    fill_5h:     i32,
    fill_week:   i32,
    runs:        i32,
    flags:       i32,
    cards: HashMap<String, Vec<db::Task>>,
}

#[derive(Template)]
#[template(path = "task.html")]
struct TaskTemplate {
    task:   db::Task,
    log:    String,
}


async fn index() -> Result<Html<String>, (StatusCode, String)> {
    let mut cards = HashMap::from([
        ("queued".into(),   Vec::new()),
        ("running".into(),  Vec::new()),
        ("solved".into(),   Vec::new()),
        ("failed".into(),   Vec::new()),
        ("block".into(),    Vec::new()),
    ]);
    let mut runs = 0;
    let mut flags = 0;

    let tasks = db::list_tasks().map_err(internal_error)?;
    for task in tasks {
        runs += task.attempt;
        if task.flag != "" {
            flags += 1;
        }
        cards.get_mut(&task.status).unwrap().push(task);
    }

    let (tokens_5h, limit_5h, tokens_week, limit_week) = (75, 100, 33, 100);
    let fill_5h   = ( tokens_5h * 100)   / limit_5h;
    let fill_week = (tokens_week * 100) / limit_week;

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

