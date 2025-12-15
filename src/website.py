#!/usr/bin/env python3
"""
Simple stats dashboard for Codex task runs.

Reads entries from DB_PATH (default: codex_stats.db) and serves a
small HTML page showing recent runs, Codex thinking snippets, attempted flags,
and token usage totals, using Flask.
"""

from __future__ import annotations

import json
import hashlib
import re
from html import escape
from typing import List, Mapping, Optional

from flask import Flask, Response, jsonify, redirect, render_template, render_template_string, url_for, request
from flask_sock import Sock

from src.models import *
from . import db

ANSI_RE = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")

app = Flask(__name__, template_folder="web/templates", static_folder="web/static")
sock = Sock(app)

def strip_ansi(text: str) -> str:
    return ANSI_RE.sub("", text or "")


def _format_tokens(value: int) -> str:
    if value >= 1_000_000:
        return f"{value / 1_000_000:.1f}M"
    if value >= 10_000:
        return f"{value / 1_000:.1f}K"
    if value >= 1_000:
        return f"{value / 1_000:.0f}K"
    return str(value)


def _percent_left(used: int, limit: int) -> int:
    if limit <= 0:
        return 100
    ratio = min(max(used / limit, 0.0), 1.0)
    return int(round((1.0 - ratio) * 100))


def load_log(task: Task) -> str | None:
    path = CODEX_DIR / task.name / "thinking.log"
    try:
        content = path.read_text(encoding="utf-8", errors="replace")
    except Exception:
        logging.error(f"Error reading thinking.log: {path}")
        return None
    if len(content) > 200_000:
        return "\n\n[truncated]" + content[-200_000:]
    return content


def task_view_model(task_id: int) -> Mapping[str, object]:
    task = db.get_entry(DB_PATH, task_id)
    text = load_log(task)

    return {
        "title": task.name,
        "task_id": task.id,
        "task_name": task.name,
        "runs": 0,
        "tokens": task.tokens,
        "text": text,
    }


def stats_view_model() -> Mapping[str, object]:
    entries = db.read_entries(DB_PATH)
    tokens = sum(task.tokens for task in entries)

    # --- Budgets ---
    budgets = {  # TODO
        "tokens_5h": 0,
        "limit_5h": TOKEN_LIMIT_5H,
        "tokens_week": 0,
        "limit_week": TOKEN_LIMIT_WEEK,
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


@app.route("/task/<int:task_id>", methods=["GET"])
def task_detail(task_id: int) -> Response:
    context = task_view_model(task_id)
    html = render_template("detail.html", **context)
    return Response(html, mimetype="text/html")


@sock.route("/task/<int:task_id>/update")
def load_codex_ws(ws, task_id: int):
    # Wait for the client to send a message to start the log stream
    message = ws.receive()
    if not message or not message.startswith("start_log_stream:"):
        print(f"WS received unexpected message or no message: {message}", flush=True)
        ws.close()
        return

    task = db.get_entry(DB_PATH, task_id)
    path = CODEX_DIR / task.name / "thinking.log"
    
    if not path.exists() or task is None or task.status != "running":
        ws.close()
        return
    print("WS start", flush=True)

    with open(path, "r", encoding="utf-8") as f:
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

    print("WS end", flush=True)


@app.route("/api/task/<int:task_id>/message", methods=["POST"])
def task_message(task_id: int) -> Response:
    data = request.get_json(silent=True) or {}
    message = str(data.get("message") or "").strip()
    if not message:
        return jsonify({"error": "missing message"}), 400

    task = db.get_entry(DB_PATH, task_id)
    if not task:
        return jsonify({"error": "task not found"}), 404
    task_dir = TASKS_DIR / task

    ts = time().strftime("%Y-%m-%d %H:%M:%S")
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


def main():
    logging.info(f"Running website on http://{HOST}:{PORT} (database: {DB_PATH})")
    app.run(host=HOST, port=PORT, debug=DEBUG_FLASK, use_reloader=False)


if __name__ == "__main__":
    main()
