#!/usr/bin/env python3

import re
from sys import exit
from html import escape
from typing import List, Mapping, Optional

from flask import Flask, Response, jsonify, redirect, render_template, render_template_string, url_for, request, abort
from flask_sock import Sock

from src.models import *
from . import db

ANSI_RE = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")
PERCENT_5H = 0
PERCENT_WEEK = 0

app = Flask(__name__, template_folder="web/templates", static_folder="web/static")
sock = Sock(app)


def strip_ansi(text: str) -> str:
    return ANSI_RE.sub("", text or "")


def load_log(task: Task) -> str | None:
    if task.log.exists():
        content = task.log.read_text(encoding="utf-8", errors="replace")
    else:
        warning(f"{task.name}: no log file: {task.log}")
        return 
    return content


def task_view_model(task: Task) -> dict:
    if not task:
        error("task_view_model but task does not exist")
        return {}

    text = load_log(task)

    return {
        "title": task.name,
        "task_id": task.id,
        "task_name": task.name,
        "runs": 0,
        "tokens": task.tokens,
        "text": text,
        "latest_status": task.status,
    }


def stats_view_model() -> Mapping[str, object]:
    entries = db.read_entries(DB_PATH)
    time_now = now()
    tokens = sum(task.tokens for task in entries if time_now - task.timestamp < 5 * 360)

    # --- Budgets ---
    limit_5h    = 25000000
    limit_week  = 100000000

    tokens_5h   = int(PERCENT_5H * limit_5h / 100 + tokens)
    tokens_week = int(PERCENT_WEEK * limit_week / 100 + tokens)

    budgets = {
        "tokens_5h": tokens_5h,
        "limit_5h": limit_5h,
        "tokens_week": tokens_week,
        "limit_week": limit_week,
    }

    # --- Cards (task detail page only) ---
    cards: dict[str, list[Task]] = {
        "queued": [],
        "running": [],
        "solved": [],
        "failed": [],
    }
    for task in entries:
        cards[task.status].append(task)

    return {
        "title":    "AI-Team Stats",
        "tokens":   tokens,
        "budgets":  budgets,
        "cards":    cards,
        "runs":     0,
        "flags":    0,
    }


@app.route("/", methods=["GET"])
@app.route("/index.html", methods=["GET"])
def index() -> Response:
    context = stats_view_model()
    html = render_template("stats.html", **context)
    return Response(html, mimetype="text/html")


@app.route("/task/<string:task_id>", methods=["GET"])
def task_detail(task_id: str) -> Response:
    task = db.get_entry(DB_PATH, task_id)
    if not task:
        abort(404)

    context = task_view_model(task)
    html = render_template("detail.html", **context)
    return Response(html, mimetype="text/html")


@sock.route("/task/<string:task_id>/update")
def load_codex_ws(ws, task_id: str):
    message = ws.receive()
    if not message or not message.startswith("start_log_stream:"):
        print(f"WS received unexpected message or no message: {message}", flush=True)
        ws.close()
        return

    task = db.get_entry(DB_PATH, task_id)
    if not task.log.exists() or task is None or task.status != "running":
        ws.close()
        return

    with open(task.log, "r", encoding="utf-8") as f:
        f.seek(0, 2)
        while True:
            task = db.get_entry(DB_PATH, task_id)
            line = f.readline()
            if task.status != "running":
                break
            if not line:
                sleep(1)
            else:
                ws.send(line)


@app.route("/api/task/<int:task_id>/message", methods=["POST"])
def task_message(task_id: str) -> Response:
    data = request.get_json(silent=True) or {}
    message = str(data.get("message") or "").strip()
    if not message:
        return jsonify({"error": "missing message"}), 400

    task = db.get_entry(DB_PATH, task_id)
    if not task:
        return jsonify({"error": "task not found"}), 404
    task_dir = TASKS_DIR / task

    ts = now().strftime("%Y-%m-%d %H:%M:%S")
    context_path = task_dir / "codex_context.txt"
    note = f"[Operator note {ts}]\n{message}\n\n"
    try:
        existing = context_path.read_text(encoding="utf-8")
    except Exception:
        existing = ""
    try:
        context_path.write_text((existing + "\n" + note).strip() + "\n", encoding="utf-8")
    except Exception as exc:
        return jsonify({"error": f"failed to write context: {exc}"}), 500

    stop_flag = CODEX_DIR / task_dir.name / "stop.flag"
    stop_flag.parent.mkdir(parents=True, exist_ok=True)
    stop_flag.write_text(message, encoding="utf-8")

    return jsonify({"status": "ok"})


def get_percent() -> tuple[float]:
    proc = subprocess.Popen(
        ["codex", "exec", "--skip-git-repo-check", "say hi"],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        env={"RUST_LOG": "debug"},
        text=True,
        bufsize=1,
    )

    assert proc.stdout is not None
    for line in proc.stdout:
        if "RateLimitWindow" in line:
            primary = float(line.split('used_percent:')[1].split(',')[0].strip())
            secondary = float(line.split('used_percent:')[2].split(',')[0].strip())
            info(f"Tokens used in 5h:{100 - primary}%, week: {100 - secondary}%")
            return (100 - primary, 100 - secondary)


def main():
    global PERCENT_5H, PERCENT_WEEK
    info(f"Running website on http://{HOST}:{PORT} (database: {DB_PATH})")
    PERCENT_5H, PERCENT_WEEK = get_percent()
    app.run(host=HOST, port=PORT, debug=DEBUG_FLASK)
    info("ended")

if __name__ == "__main__":
    main()
